//! Pure-Rust read-only reader for the Windows **UserAssist** artifact.
//!
//! UserAssist is per-user **GUI execution evidence**. Windows Explorer records every program a
//! user launches from the shell (double-click, Start menu, taskbar) under
//! `Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{GUID}\Count` in that user's
//! `NTUSER.DAT` hive. There are two `{GUID}` subkeys — one for executables, one for Start-Menu
//! shortcuts. Each value keys one launched program: the value **name** is the program path
//! **ROT13**-encoded, and the value **data** is a fixed binary struct carrying the launch **run
//! count**, focus count/time, and the **last-execution `FILETIME`**.
//!
//! [`parse_bytes`] opens the hive with [`winreg_core`], walks both GUID subkeys, ROT13-decodes
//! each name, and decodes the struct into a [`UserAssistEntry`]. It never writes, is
//! `#![forbid(unsafe_code)]`, and is panic-free: every hive read is fallible and propagated, and
//! every struct field is read through a bounds-checked helper (a too-short value is skipped, never
//! panicked on).
//!
//! The struct layout follows `regipy`'s `user_assist` plugin (the reference implementation,
//! derived from libyal `winreg-kb`) and Didier Stevens' UserAssist research. The modern
//! (Windows 7+) struct is 72 bytes: session id `@0`, run count `@4`, focus count `@8`, focus time
//! ms `@12`, last-execution `FILETIME` `@60`. Windows XP uses a 16-byte struct (run count `@4`,
//! last-execution `FILETIME` `@8`). The `UEME_CTLSESSION` / `UEME_CTLCUACount` bookkeeping
//! counters are skipped.

#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

use winreg_core::error::HiveError;
use winreg_core::hive::Hive;

/// The registry path (from the hive root) to the UserAssist key.
const USERASSIST_PATH: &str = r"Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist";

/// One UserAssist `Count` value — a program a user launched from the GUI.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct UserAssistEntry {
    /// The launched program's path, **ROT13-decoded** from the value name. Most are file paths
    /// (`C:\Users\…\foo.exe`, a `.lnk` shortcut); some are shell `KNOWNFOLDER`-GUID or `AppUserModelId`
    /// tokens, kept verbatim after decoding.
    pub name: String,
    /// The `{GUID}` subkey this entry came from (executables vs shortcuts).
    pub guid: String,
    /// Number of times the user launched the program (struct offset 4).
    pub run_count: u32,
    /// Focus count — how many times the program's window gained focus (struct offset 8; 0 on the
    /// legacy Windows XP struct).
    pub focus_count: u32,
    /// Total time the program held focus, in milliseconds (struct offset 12; 0 on Windows XP).
    pub focus_time_ms: u32,
    /// Last-execution time as a raw Windows `FILETIME` (struct offset 60 on Windows 7+, offset 8
    /// on Windows XP). `0` means UserAssist recorded no execution (a focus-only entry).
    pub last_executed_filetime: u64,
    /// The parent `Count` key's last-written time as a raw Windows `FILETIME`.
    pub key_last_written_filetime: u64,
}

/// A failure reading UserAssist from a hive.
#[derive(Debug)]
pub enum UserAssistError {
    /// The hive could not be parsed.
    Hive(HiveError),
    /// The hive has no `…\Explorer\UserAssist` key — not an `NTUSER.DAT`, or one without UserAssist.
    NotUserAssist,
}

impl std::fmt::Display for UserAssistError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Hive(e) => write!(f, "hive error: {e}"),
            Self::NotUserAssist => {
                write!(
                    f,
                    "hive has no UserAssist key — not an NTUSER.DAT with UserAssist"
                )
            }
        }
    }
}

impl std::error::Error for UserAssistError {}

impl From<HiveError> for UserAssistError {
    fn from(e: HiveError) -> Self {
        Self::Hive(e)
    }
}

/// Parse the UserAssist entries from a raw `NTUSER.DAT` hive.
///
/// Walks both `{GUID}\Count` subkeys, ROT13-decodes each value name, decodes the run-count /
/// `FILETIME` struct, and skips the `UEME_CTLSESSION` / `UEME_CTLCUACount` counters. Values too
/// short to hold either the Windows 7+ (72-byte) or Windows XP (16-byte) struct are skipped.
///
/// # Errors
/// [`UserAssistError`] if the bytes are not a readable hive, or the hive has no UserAssist key.
pub fn parse_bytes(bytes: &[u8]) -> Result<Vec<UserAssistEntry>, UserAssistError> {
    let hive = Hive::from_bytes(bytes.to_vec())?;
    let Some(userassist) = hive.open_key(USERASSIST_PATH)? else {
        return Err(UserAssistError::NotUserAssist);
    };

    let mut out = Vec::new();
    for guid_key in userassist.subkeys()? {
        let guid = guid_key.name();
        // A well-formed UserAssist GUID subkey holds a `Count` child; a malformed hive that omits
        // it yields an empty `Option`, so the loop body is simply skipped (never aborting the read).
        // The explicit `.into_iter()` iterates the `Option` as 0-or-1 without an `if let` whose
        // never-taken else-branch would leave an uncoverable region on well-formed hives.
        #[allow(clippy::explicit_into_iter_loop)]
        for count in guid_key.subkey("Count")?.into_iter() {
            let key_lw = count.last_written_raw();
            for value in count.values()? {
                let name = resolve_known_folder(&rot13(&value.name()));
                if name.starts_with("UEME_CTLSESSION") || name.starts_with("UEME_CTLCUACount") {
                    continue;
                }
                // A value whose data cell is unreadable is skipped, not fatal (`.ok()`), and a
                // value too short to hold either struct yields `None` from `parse_struct`.
                if let Some(entry) = value
                    .raw_data()
                    .ok()
                    .and_then(|data| parse_struct(name, guid.clone(), key_lw, &data))
                {
                    out.push(entry);
                }
            }
        }
    }
    Ok(out)
}

/// Decode one `Count` value's binary struct into a [`UserAssistEntry`]. Supports the Windows 7+
/// 72-byte layout and the Windows XP 16-byte layout; returns `None` for a value too short to hold
/// either (every field is read through a bounds-checked helper, so a malformed value is skipped,
/// never panicked on).
fn parse_struct(
    name: String,
    guid: String,
    key_last_written_filetime: u64,
    data: &[u8],
) -> Option<UserAssistEntry> {
    if data.len() >= 72 {
        Some(UserAssistEntry {
            name,
            guid,
            run_count: read_u32_le(data, 4)?,
            focus_count: read_u32_le(data, 8)?,
            focus_time_ms: read_u32_le(data, 12)?,
            last_executed_filetime: read_u64_le(data, 60)?,
            key_last_written_filetime,
        })
    } else if data.len() >= 16 {
        Some(UserAssistEntry {
            name,
            guid,
            run_count: read_u32_le(data, 4)?,
            focus_count: 0,
            focus_time_ms: 0,
            last_executed_filetime: read_u64_le(data, 8)?,
            key_last_written_filetime,
        })
    } else {
        None
    }
}

/// ROT13-decode a UserAssist value name. Rotates ASCII letters by 13 (its own inverse) and passes
/// every other byte — digits, `\`, `:`, `{}`, punctuation — through unchanged.
fn rot13(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            'A'..='Z' => (((c as u8 - b'A' + 13) % 26) + b'A') as char,
            'a'..='z' => (((c as u8 - b'a' + 13) % 26) + b'a') as char,
            other => other,
        })
        .collect()
}

/// Resolve a leading Windows `KNOWNFOLDERID` GUID prefix (`{GUID}\rest`) to its folder path, so
/// UserAssist entries read as real paths. UserAssist stores executable entries as
/// `{FOLDERID}\program.exe` — without resolution a `System32` binary looks path-less and would be
/// mis-flagged as relocated. The GUID→folder mapping is Microsoft's fixed `KNOWNFOLDERID` set.
/// An unrecognized GUID (or a non-GUID name) is returned unchanged.
fn resolve_known_folder(name: &str) -> String {
    let Some(rest) = name.strip_prefix('{') else {
        return name.to_string();
    };
    let Some((guid, tail)) = rest.split_once("}\\") else {
        return name.to_string();
    };
    let folder = match guid.to_ascii_uppercase().as_str() {
        "1AC14E77-02E7-4E5D-B744-2EB1AE5198B7" => r"C:\Windows\System32",
        "D65231B0-B2F1-4857-A4CE-A8E7C6EA7D27" => r"C:\Windows\SysWOW64",
        "F38BF404-1D43-42F2-9305-67DE0B28FC23" => r"C:\Windows",
        "6D809377-6AF0-444B-8957-A3773F02200E" | "905E63B6-C1BF-494E-B29C-65B732D3D21A" => {
            r"C:\Program Files"
        }
        "7C5A40EF-A0FB-4BFC-874A-C0F2E0B9FA8E" => r"C:\Program Files (x86)",
        "B4BFCC3A-DB2C-424C-B029-7FE99A87C641" => r"%USERPROFILE%\Desktop",
        "374DE290-123F-4565-9164-39C4925E467B" => r"%USERPROFILE%\Downloads",
        "FDD39AD0-238F-46AF-ADB4-6C85480369C7" => r"%USERPROFILE%\Documents",
        "F1B32785-6FBA-4FCF-9D55-7B8E7F157091" => r"%LOCALAPPDATA%",
        "3EB685DB-65F9-4CF6-A03A-E3EF65729F3D" => r"%APPDATA%",
        "A77F5D77-2E2B-44C3-A6A2-ABA601054A51" => {
            r"%APPDATA%\Microsoft\Windows\Start Menu\Programs"
        }
        _ => return name.to_string(), // unrecognized GUID — keep verbatim
    };
    format!("{folder}\\{tail}")
}

/// Read a little-endian `u32` at `offset`, or `None` if the slice is too short.
fn read_u32_le(data: &[u8], offset: usize) -> Option<u32> {
    let bytes = data.get(offset..offset.checked_add(4)?)?;
    Some(u32::from_le_bytes(bytes.try_into().ok()?))
}

/// Read a little-endian `u64` at `offset`, or `None` if the slice is too short.
fn read_u64_le(data: &[u8], offset: usize) -> Option<u64> {
    let bytes = data.get(offset..offset.checked_add(8)?)?;
    Some(u64::from_le_bytes(bytes.try_into().ok()?))
}

#[cfg(test)]
mod tests;
