//! RED stub — types and signatures only, wrong bodies. Replaced by the GREEN implementation.
#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

use winreg_core::error::HiveError;

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct UserAssistEntry {
    pub name: String,
    pub guid: String,
    pub run_count: u32,
    pub focus_count: u32,
    pub focus_time_ms: u32,
    pub last_executed_filetime: u64,
    pub key_last_written_filetime: u64,
}

#[derive(Debug)]
pub enum UserAssistError {
    Hive(HiveError),
    NotUserAssist,
}

impl std::fmt::Display for UserAssistError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Hive(e) => write!(f, "hive error: {e}"),
            Self::NotUserAssist => write!(f, "hive has no UserAssist key"),
        }
    }
}

impl std::error::Error for UserAssistError {}

impl From<HiveError> for UserAssistError {
    fn from(e: HiveError) -> Self {
        Self::Hive(e)
    }
}

pub fn parse_bytes(_bytes: &[u8]) -> Result<Vec<UserAssistEntry>, UserAssistError> {
    Ok(Vec::new())
}

fn rot13(s: &str) -> String {
    s.to_string()
}

fn read_u32_le(_data: &[u8], _off: usize) -> Option<u32> {
    None
}

fn read_u64_le(_data: &[u8], _off: usize) -> Option<u64> {
    None
}

fn parse_struct(
    _name: String,
    _guid: String,
    _key_lw: u64,
    _data: &[u8],
) -> Option<UserAssistEntry> {
    None
}

#[cfg(test)]
mod tests;
