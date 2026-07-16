//! Tier-1 validation against a real NIST CFReDS Data-Leakage `NTUSER.DAT`, cross-checked with the
//! `regipy` `user_assist` oracle (61 entries, counters excluded). See `tests/data/README.md`.

use super::*;

/// The real CFReDS `informant` `NTUSER.DAT` — a populated UserAssist key.
const NTUSER: &[u8] = include_bytes!("../tests/data/ntuser.hve");
/// A valid REGF hive with no UserAssist key (an `Amcache.hve`) — exercises `NotUserAssist`.
const NOT_USERASSIST: &[u8] = include_bytes!("../tests/data/not_userassist.hve");

const EXEC_GUID: &str = "{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}";
const LNK_GUID: &str = "{F4E57C4B-2036-45F0-A9AB-443BCFE33D9F}";

fn find<'a>(entries: &'a [UserAssistEntry], name: &str) -> &'a UserAssistEntry {
    entries
        .iter()
        .find(|e| e.name == name)
        .unwrap_or_else(|| panic!("entry not found: {name}"))
}

#[test]
fn cfreds_ntuser_entry_count_matches_the_oracle() {
    let entries = parse_bytes(NTUSER).unwrap();
    // regipy: 65 raw Count values across two GUIDs − 4 UEME counters = 61.
    assert_eq!(entries.len(), 61);
}

#[test]
fn ueme_counter_entries_are_skipped() {
    let entries = parse_bytes(NTUSER).unwrap();
    assert!(!entries
        .iter()
        .any(|e| e.name.starts_with("UEME_CTLSESSION") || e.name.starts_with("UEME_CTLCUACount")));
}

#[test]
fn both_guid_subkeys_are_walked() {
    let entries = parse_bytes(NTUSER).unwrap();
    assert!(entries.iter().any(|e| e.guid == EXEC_GUID));
    assert!(entries.iter().any(|e| e.guid == LNK_GUID));
}

#[test]
fn google_chrome_shortcut_matches_the_oracle() {
    let entries = parse_bytes(NTUSER).unwrap();
    let e = find(&entries, r"C:\Users\Public\Desktop\Google Chrome.lnk");
    assert_eq!(e.guid, LNK_GUID);
    assert_eq!(e.run_count, 2);
    assert_eq!(e.focus_time_ms, 2);
    assert_eq!(e.last_executed_filetime, 130_716_052_100_840_000);
    assert!(e.key_last_written_filetime > 0);
}

#[test]
fn ccsetup_executable_matches_the_oracle() {
    let entries = parse_bytes(NTUSER).unwrap();
    let e = find(
        &entries,
        r"C:\Users\informant\Desktop\Download\ccsetup504.exe",
    );
    assert_eq!(e.guid, EXEC_GUID);
    assert_eq!(e.run_count, 1);
    assert_eq!(e.focus_time_ms, 4274);
    assert_eq!(e.last_executed_filetime, 130_717_690_768_820_000);
}

#[test]
fn focus_only_entry_has_zero_run_count_and_filetime() {
    let entries = parse_bytes(NTUSER).unwrap();
    let e = find(
        &entries,
        r"C:\Users\informant\AppData\Local\Temp\~nsu.tmp\Au_.exe",
    );
    assert_eq!(e.run_count, 0);
    assert_eq!(e.last_executed_filetime, 0);
    assert_eq!(e.focus_time_ms, 12667);
}

#[test]
fn every_entry_carries_a_non_empty_decoded_name() {
    let entries = parse_bytes(NTUSER).unwrap();
    assert!(entries.iter().all(|e| !e.name.is_empty()));
}

#[test]
fn non_hive_bytes_error_cleanly() {
    let err = parse_bytes(b"not a hive").unwrap_err();
    assert!(matches!(err, UserAssistError::Hive(_)));
    assert!(err.to_string().contains("hive error"));
}

#[test]
fn a_hive_without_userassist_is_named_not_userassist() {
    let err = parse_bytes(NOT_USERASSIST).unwrap_err();
    assert!(matches!(err, UserAssistError::NotUserAssist));
    assert!(err.to_string().contains("no UserAssist key"));
}

#[test]
fn rot13_round_trips_and_ignores_non_letters() {
    // ROT13 is its own inverse; digits, punctuation, and the backslash pass through unchanged.
    assert_eq!(rot13(r"P:\Hfref\Choyvp"), r"C:\Users\Public");
    assert_eq!(rot13(r"C:\Users\Public"), r"P:\Hfref\Choyvp");
    assert_eq!(rot13("123-.exe"), "123-.rkr");
}

#[test]
fn read_u32_le_is_bounds_checked() {
    assert_eq!(read_u32_le(&[0xB2, 0x10, 0, 0], 0), Some(4274));
    assert_eq!(read_u32_le(&[1, 2, 3, 4], 1), None); // would run off the end
    assert_eq!(read_u32_le(&[1, 2], 0), None); // too short
}

#[test]
fn read_u64_le_is_bounds_checked() {
    assert_eq!(read_u64_le(&[0, 0, 0, 0, 0, 0, 0, 0], 0), Some(0));
    assert_eq!(read_u64_le(&[1, 2, 3, 4, 5, 6, 7], 0), None); // too short
}

#[test]
fn parse_struct_handles_win7_winxp_and_undersized() {
    // 72-byte Win7: run@4=7, focus_count@8=3, focus_ms@12=99, last_exec@60=42.
    let mut win7 = vec![0u8; 72];
    win7[4] = 7;
    win7[8] = 3;
    win7[12] = 99;
    win7[60] = 42;
    let e = parse_struct("x".into(), "g".into(), 0, &win7).unwrap();
    assert_eq!(
        (
            e.run_count,
            e.focus_count,
            e.focus_time_ms,
            e.last_executed_filetime
        ),
        (7, 3, 99, 42)
    );

    // 16-byte WinXP: run@4=9, last_exec@8=5; focus fields absent → 0.
    let mut winxp = vec![0u8; 16];
    winxp[4] = 9;
    winxp[8] = 5;
    let x = parse_struct("y".into(), "g".into(), 0, &winxp).unwrap();
    assert_eq!(
        (
            x.run_count,
            x.focus_count,
            x.focus_time_ms,
            x.last_executed_filetime
        ),
        (9, 0, 0, 5)
    );

    // Too short for either struct → skipped.
    assert!(parse_struct("z".into(), "g".into(), 0, &[0u8; 8]).is_none());
}

#[test]
fn known_folder_guids_resolve_to_paths() {
    // FOLDERID_System → System32 (so a system binary here is NOT flagged relocated).
    assert_eq!(
        resolve_known_folder(r"{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\calc.exe"),
        r"C:\Windows\System32\calc.exe"
    );
    // FOLDERID_Windows.
    assert_eq!(
        resolve_known_folder(r"{F38BF404-1D43-42F2-9305-67DE0B28FC23}\explorer.exe"),
        r"C:\Windows\explorer.exe"
    );
    // Unrecognized GUID → kept verbatim.
    let unknown = r"{00000000-0000-0000-0000-000000000000}\x.exe";
    assert_eq!(resolve_known_folder(unknown), unknown);
    // A plain path (no GUID prefix) passes through unchanged.
    assert_eq!(
        resolve_known_folder(r"C:\Users\a\x.exe"),
        r"C:\Users\a\x.exe"
    );
    // A malformed `{`-prefixed token without a closing `}\` is left alone.
    assert_eq!(resolve_known_folder("{not-a-guid"), "{not-a-guid");
}
