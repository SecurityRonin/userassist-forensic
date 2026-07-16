//! Windows **UserAssist** forensic analyzer.
//!
//! UserAssist is per-user evidence of **interactive GUI launch** — Explorer records the programs a
//! user started from the shell (double-click, Start menu, taskbar), each with a **run count** and a
//! **last-execution time**. [`analyze_bytes`] decodes the entries with [`userassist_core`] and
//! [`audit`] adds a small set of *high-precision* graded findings: a Windows system-binary name
//! launched from a non-`System32` path (masquerading) and a program launched from a
//! known-suspicious directory.
//!
//! Findings are observations, never verdicts: UserAssist establishes that a user launched a program
//! with a given path some number of times; whether it is malicious is a correlation/tribunal
//! question. A non-zero run count with a last-execution time is strong evidence of interactive
//! launch — but the entry alone does not prove intent.
//!
//! Built on [`userassist_core`]; findings use [`forensicnomicon::report`].

#![forbid(unsafe_code)]

use forensicnomicon::report::{Category, Finding, Observation, Severity, Source, SubjectRef};

// Re-export the core types that appear in this crate's public API.
pub use userassist_core::{UserAssistEntry, UserAssistError};

/// The result of analyzing a hive's UserAssist entries.
#[derive(Debug, Clone)]
pub struct UserAssistReport {
    /// The decoded UserAssist entries.
    pub entries: Vec<UserAssistEntry>,
    /// Graded anomalies (may be empty).
    pub anomalies: Vec<UserAssistAnomaly>,
}

/// A graded UserAssist finding — a *high-precision* triage signal that stays quiet on benign
/// launches and fires only on a genuinely anomalous pattern.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UserAssistAnomaly {
    /// A Windows system-binary *name* launched from a path that is not under `System32`/`SysWOW64`
    /// — consistent with masquerading (`T1036.005`).
    SystemBinaryRelocated {
        /// The system-binary base name (e.g. `SVCHOST.EXE`).
        name: String,
        /// The full path UserAssist recorded.
        path: String,
        /// The launch run count.
        run_count: u32,
        /// The last-execution `FILETIME` (0 if UserAssist recorded no execution).
        last_executed_filetime: u64,
    },
    /// A program launched from a directory commonly used to stage malware (Temp, Downloads,
    /// `$Recycle.Bin`, …) — `T1204`.
    SuspiciousPath {
        /// The program base name.
        name: String,
        /// The suspicious path.
        path: String,
        /// The launch run count.
        run_count: u32,
        /// The last-execution `FILETIME` (0 if UserAssist recorded no execution).
        last_executed_filetime: u64,
    },
}

/// Decode a hive's UserAssist entries and audit them.
///
/// # Errors
/// [`UserAssistError`] if the bytes are not a readable hive, or the hive has no UserAssist key.
pub fn analyze_bytes(bytes: &[u8]) -> Result<UserAssistReport, UserAssistError> {
    let entries = userassist_core::parse_bytes(bytes)?;
    let anomalies = audit(&entries);
    Ok(UserAssistReport { entries, anomalies })
}

/// Audit decoded UserAssist entries for graded anomalies (may be empty).
#[must_use]
pub fn audit(entries: &[UserAssistEntry]) -> Vec<UserAssistAnomaly> {
    let mut out = Vec::new();
    for e in entries {
        let path = e.name.as_str();
        let name = base_name(path);
        let upper = path.to_uppercase();
        let in_system = upper.contains(r"\SYSTEM32\") || upper.contains(r"\SYSWOW64\");
        if forensicnomicon::processes::is_system32_binary(&name) && !in_system {
            out.push(UserAssistAnomaly::SystemBinaryRelocated {
                name: name.to_uppercase(),
                path: path.to_string(),
                run_count: e.run_count,
                last_executed_filetime: e.last_executed_filetime,
            });
        }
        if is_executable_image(path)
            && forensicnomicon::heuristics::paths::is_suspicious_exec_path(path)
        {
            out.push(UserAssistAnomaly::SuspiciousPath {
                name,
                path: path.to_string(),
                run_count: e.run_count,
                last_executed_filetime: e.last_executed_filetime,
            });
        }
    }
    out
}

/// The base name (last `\`/`/`-component) of a path.
fn base_name(path: &str) -> String {
    path.rsplit(['\\', '/']).next().unwrap_or(path).to_string()
}

/// Executable-image / script extensions. The staging-directory heuristic applies only to a
/// program image — a UserAssist `.lnk` shortcut, `AppUserModelId`, or Control-Panel token is
/// not "a binary staged in a malware directory". (Duplicates the intent of the private
/// `EXEC_EXTENSIONS` in `forensicnomicon::heuristics::srum`; a shared `is_executable_image`
/// belongs in `forensicnomicon::heuristics::paths` — tracked for centralization.)
const EXECUTABLE_IMAGE_EXTENSIONS: &[&str] = &[
    ".exe", ".scr", ".com", ".pif", ".bat", ".cmd", ".ps1", ".vbs", ".vbe", ".js", ".jse", ".wsf",
    ".hta", ".cpl", ".dll", ".msi",
];

/// Returns `true` if `path` names an executable image (by extension), so the staging-directory
/// heuristic should apply. Shortcuts (`.lnk`) and non-file shell tokens return `false`.
fn is_executable_image(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    EXECUTABLE_IMAGE_EXTENSIONS
        .iter()
        .any(|ext| lower.ends_with(ext))
}

impl UserAssistAnomaly {
    fn fields(&self) -> (&str, &str, u32) {
        match self {
            UserAssistAnomaly::SystemBinaryRelocated {
                name,
                path,
                run_count,
                ..
            }
            | UserAssistAnomaly::SuspiciousPath {
                name,
                path,
                run_count,
                ..
            } => (name, path, *run_count),
        }
    }
}

impl Observation for UserAssistAnomaly {
    fn severity(&self) -> Option<Severity> {
        Some(match self {
            UserAssistAnomaly::SystemBinaryRelocated { .. } => Severity::High,
            UserAssistAnomaly::SuspiciousPath { .. } => Severity::Medium,
        })
    }

    fn category(&self) -> Category {
        match self {
            UserAssistAnomaly::SystemBinaryRelocated { .. } => Category::Concealment,
            UserAssistAnomaly::SuspiciousPath { .. } => Category::Threat,
        }
    }

    fn code(&self) -> &'static str {
        match self {
            UserAssistAnomaly::SystemBinaryRelocated { .. } => "USERASSIST-SYSTEM-BINARY-RELOCATED",
            UserAssistAnomaly::SuspiciousPath { .. } => "USERASSIST-SUSPICIOUS-PATH",
        }
    }

    fn note(&self) -> String {
        let (name, path, run_count) = self.fields();
        match self {
            UserAssistAnomaly::SystemBinaryRelocated { .. } => format!(
                "{name} is a Windows system binary, but UserAssist recorded a launch at {path} \
                 (run count {run_count}) — consistent with masquerading."
            ),
            UserAssistAnomaly::SuspiciousPath { .. } => format!(
                "{name} at {path} (run count {run_count}) sits in a directory commonly used to \
                 stage malware — consistent with suspicious execution."
            ),
        }
    }

    fn mitre(&self) -> &'static [&'static str] {
        match self {
            UserAssistAnomaly::SystemBinaryRelocated { .. } => &["T1036.005"],
            UserAssistAnomaly::SuspiciousPath { .. } => &["T1204"],
        }
    }

    fn subjects(&self) -> Vec<SubjectRef> {
        let (name, path, _) = self.fields();
        vec![SubjectRef {
            scheme: "filesystem".to_string(),
            kind: "executable".to_string(),
            id: path.to_string(),
            label: Some(name.to_string()),
        }]
    }
}

/// Convenience: produce a [`Finding`] for an anomaly under the given scope.
#[must_use]
pub fn to_finding(anomaly: &UserAssistAnomaly, scope: impl Into<String>) -> Finding {
    anomaly.to_finding(Source {
        analyzer: "userassist-forensic".to_string(),
        scope: scope.into(),
        version: Some(env!("CARGO_PKG_VERSION").to_string()),
    })
}

#[cfg(test)]
mod tests;
