//! RED stub — types and signatures only, wrong bodies. Replaced by the GREEN implementation.
#![forbid(unsafe_code)]

use forensicnomicon::report::{Category, Finding, Observation, Severity, Source, SubjectRef};

pub use userassist_core::{UserAssistEntry, UserAssistError};

#[derive(Debug, Clone)]
pub struct UserAssistReport {
    pub entries: Vec<UserAssistEntry>,
    pub anomalies: Vec<UserAssistAnomaly>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UserAssistAnomaly {
    SystemBinaryRelocated {
        name: String,
        path: String,
        run_count: u32,
        last_executed_filetime: u64,
    },
    SuspiciousPath {
        name: String,
        path: String,
        run_count: u32,
        last_executed_filetime: u64,
    },
}

pub fn analyze_bytes(bytes: &[u8]) -> Result<UserAssistReport, UserAssistError> {
    let entries = userassist_core::parse_bytes(bytes)?;
    Ok(UserAssistReport {
        entries,
        anomalies: Vec::new(),
    })
}

#[must_use]
pub fn audit(_entries: &[UserAssistEntry]) -> Vec<UserAssistAnomaly> {
    Vec::new()
}

impl Observation for UserAssistAnomaly {
    fn severity(&self) -> Option<Severity> {
        None
    }
    fn category(&self) -> Category {
        Category::Threat
    }
    fn code(&self) -> &'static str {
        ""
    }
    fn note(&self) -> String {
        String::new()
    }
    fn mitre(&self) -> &'static [&'static str] {
        &[]
    }
    fn subjects(&self) -> Vec<SubjectRef> {
        Vec::new()
    }
}

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
