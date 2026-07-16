//! Unit tests: audit heuristics, the `Observation` mapping, and `analyze_bytes` on the real
//! committed CFReDS `NTUSER.DAT`.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use super::*;

/// The real CFReDS `informant` `NTUSER.DAT` (the same fixture userassist-core validates against).
const NTUSER: &[u8] = include_bytes!("../../core/tests/data/ntuser.hve");

fn entry(name: &str, run_count: u32) -> UserAssistEntry {
    UserAssistEntry {
        name: name.to_string(),
        guid: "{GUID}".to_string(),
        run_count,
        ..Default::default()
    }
}

#[test]
fn system_binary_at_non_system_path_flags_masquerading() {
    let a = audit(&[entry(r"C:\Temp\svchost.exe", 3)]);
    assert!(a.iter().any(|x| matches!(
        x,
        UserAssistAnomaly::SystemBinaryRelocated { name, run_count, .. }
            if name == "SVCHOST.EXE" && *run_count == 3
    )));
}

#[test]
fn system_binary_in_system32_is_not_flagged() {
    let a = audit(&[entry(r"C:\Windows\System32\svchost.exe", 1)]);
    assert!(!a
        .iter()
        .any(|x| matches!(x, UserAssistAnomaly::SystemBinaryRelocated { .. })));
}

#[test]
fn suspicious_path_is_flagged() {
    let a = audit(&[entry(r"C:\Users\a\AppData\Local\Temp\dropper.exe", 2)]);
    match a
        .into_iter()
        .find(|x| matches!(x, UserAssistAnomaly::SuspiciousPath { .. }))
    {
        Some(UserAssistAnomaly::SuspiciousPath {
            name, run_count, ..
        }) => {
            assert_eq!(name, "dropper.exe");
            assert_eq!(run_count, 2);
        }
        other => panic!("expected SuspiciousPath, got {other:?}"),
    }
}

#[test]
fn benign_and_non_path_entries_are_quiet() {
    let a = audit(&[
        entry(r"C:\Program Files\app\app.exe", 5),
        entry("Microsoft.Windows.GettingStarted", 14),
    ]);
    assert!(a.is_empty());
}

#[test]
fn observation_maps_all_fields() {
    for a in [
        UserAssistAnomaly::SystemBinaryRelocated {
            name: "SVCHOST.EXE".to_string(),
            path: r"C:\Temp\svchost.exe".to_string(),
            run_count: 3,
            last_executed_filetime: 130_716_052_100_840_000,
        },
        UserAssistAnomaly::SuspiciousPath {
            name: "x.exe".to_string(),
            path: r"C:\Temp\x.exe".to_string(),
            run_count: 0,
            last_executed_filetime: 0,
        },
    ] {
        assert!(a.severity().is_some());
        assert!(!a.code().is_empty());
        assert!(!a.mitre().is_empty());
        assert!(!a.note().is_empty());
        assert!(!a.subjects().is_empty());
        let _ = to_finding(&a, "NTUSER.DAT");
    }
    let reloc = UserAssistAnomaly::SystemBinaryRelocated {
        name: "SVCHOST.EXE".to_string(),
        path: r"C:\Temp\svchost.exe".to_string(),
        run_count: 3,
        last_executed_filetime: 0,
    };
    assert_eq!(reloc.severity(), Some(Severity::High));
    assert_eq!(reloc.category(), Category::Concealment);
    assert_eq!(reloc.mitre(), &["T1036.005"]);
    assert!(reloc.note().contains("run count 3"));

    let susp = UserAssistAnomaly::SuspiciousPath {
        name: "x.exe".to_string(),
        path: r"C:\Temp\x.exe".to_string(),
        run_count: 0,
        last_executed_filetime: 0,
    };
    assert_eq!(susp.severity(), Some(Severity::Medium));
    assert_eq!(susp.category(), Category::Threat);
    assert_eq!(susp.mitre(), &["T1204"]);
}

#[test]
fn analyze_bytes_on_the_real_cfreds_hive() {
    let report = analyze_bytes(NTUSER).unwrap();
    assert_eq!(report.entries.len(), 61);
    // The informant staged installers in Downloads and Temp — both fire SuspiciousPath.
    assert!(report.anomalies.iter().any(|a| matches!(
        a,
        UserAssistAnomaly::SuspiciousPath { path, .. } if path.contains("icloudsetup.exe")
    )));
    assert!(report.anomalies.iter().any(|a| matches!(
        a,
        UserAssistAnomaly::SuspiciousPath { path, .. } if path.ends_with(r"~nsu.tmp\Au_.exe")
    )));
    // No system binary masquerades in this hive, so no false High finding.
    assert!(!report
        .anomalies
        .iter()
        .any(|a| matches!(a, UserAssistAnomaly::SystemBinaryRelocated { .. })));
}

#[test]
fn analyze_bytes_rejects_non_hive() {
    assert!(matches!(
        analyze_bytes(b"nope"),
        Err(UserAssistError::Hive(_))
    ));
}
