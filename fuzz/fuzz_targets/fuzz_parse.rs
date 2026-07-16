//! Fuzz target: feed arbitrary bytes as an NTUSER hive to the UserAssist reader.
//! Invariant: `parse_bytes` never panics — malformed / non-hive input yields a typed error,
//! and the ROT13 decode and struct reads are bounds-checked (no unwrap, no out-of-bounds index).
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = userassist_core::parse_bytes(data);
});
