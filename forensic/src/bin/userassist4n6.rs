//! `userassist4n6` — read a Windows `NTUSER.DAT` and print the per-user UserAssist launches (path,
//! run count, last-execution time), plus graded findings.
//!
//! Decoding + analysis live in the `userassist_forensic` / `userassist_core` libraries; this binary
//! reads the file and renders the result.
#![forbid(unsafe_code)]

use std::process::ExitCode;

use forensicnomicon::report::Observation;
use userassist_forensic::{analyze_bytes, UserAssistAnomaly, UserAssistReport};
use winreg_core::key::filetime_to_datetime;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let all = args.iter().any(|a| a == "--all");
    let Some(path) = args.iter().find(|a| !a.starts_with("--")) else {
        eprintln!("usage: userassist4n6 <NTUSER.DAT> [--all]");
        return ExitCode::from(2);
    };

    let bytes = match std::fs::read(path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("userassist4n6: {path}: {e}");
            return ExitCode::FAILURE;
        }
    };
    match analyze_bytes(&bytes) {
        Ok(report) => {
            print_report(&report, all);
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("userassist4n6: {path}: {e}");
            ExitCode::FAILURE
        }
    }
}

fn print_report(report: &UserAssistReport, all: bool) {
    println!("UserAssist: {} entries", report.entries.len());

    if report.anomalies.is_empty() {
        println!("Findings: none");
    } else {
        println!("Findings ({}):", report.anomalies.len());
        for a in &report.anomalies {
            let sev = a
                .severity()
                .map_or_else(|| "INFO".to_string(), |s| format!("{s:?}").to_uppercase());
            println!("  [{sev}] {}  {}", a.code(), subject_path(a));
            println!("    {}", a.note());
        }
    }

    if all {
        // Most-recently-executed first; never-executed (FILETIME 0) entries sort last.
        let mut entries: Vec<_> = report.entries.iter().collect();
        entries.sort_by_key(|e| std::cmp::Reverse(e.last_executed_filetime));
        println!("\nLaunches (run count, last execution, path):");
        for e in entries {
            let when = filetime_to_datetime(e.last_executed_filetime)
                .map_or_else(|| "-".to_string(), |t| t.to_string());
            println!("  {:>5}  {when:<32}  {}", e.run_count, e.name);
        }
    }
}

fn subject_path(a: &UserAssistAnomaly) -> &str {
    match a {
        UserAssistAnomaly::SystemBinaryRelocated { path, .. }
        | UserAssistAnomaly::SuspiciousPath { path, .. } => path,
    }
}
