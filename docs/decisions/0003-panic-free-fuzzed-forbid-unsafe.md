# 3. `forbid(unsafe)` + panic-free-by-lint + fuzzed parsing of untrusted hives

Date: 2026-07-24
Status: Accepted

## Context

A `NTUSER.DAT` handed to this tool is attacker-controllable evidence: a truncated
`Count` value, a lying length, a hive that omits the `Count` child key, or a
malformed struct must never crash the reader or — worse — produce silently wrong
output. A forensic tool that panics on a crafted artifact is a denial-of-service
on the investigation, and one that reads out of bounds is a memory-safety hole in
a security-critical parser.

This crate parses no format that needs `mmap` or any raw-pointer trick — it reads
a byte slice through `winreg-core` and decodes small fixed structs — so it has no
reason to weaken the strongest safety posture. The fleet's Paranoid Gatekeeper
standard (`ronin-issen/CLAUDE.md`) and the global Rust lint-posture recipe define
exactly this bar.

## Decision

Enforce a panic-free posture statically and dynamically.

- **Static, memory safety:** `unsafe_code = "forbid"` in `[workspace.lints.rust]`
  (`Cargo.toml`), reasserted as `#![forbid(unsafe_code)]` at the top of
  `core/src/lib.rs`, `forensic/src/lib.rs`, and the `userassist4n6` binary. There
  is no `mmap` exception; every `unsafe` is a hard compile error. This earns the
  README `unsafe forbidden` badge honestly.
- **Static, panics:** `[workspace.lints.clippy]` denies `unwrap_used` and
  `expect_used` in production (`clippy.toml` re-permits them only in tests). Every
  struct field is read through a bounds-checked helper — `read_u32_le` /
  `read_u64_le` return `Option` via `data.get(offset..offset.checked_add(N)?)`
  (`core/src/lib.rs`) — so a too-short value yields `None` and the entry is
  skipped, never panicked on. Hive reads are fallible and propagated; an
  unreadable value cell is skipped with `.ok()`, and a `Count`-less GUID subkey is
  iterated as a 0-or-1 `Option` so the loop body is simply skipped.
- **Dynamic:** two `cargo-fuzz` targets — `fuzz_parse` (the reader) and
  `fuzz_forensic` (the full analyze/audit pipeline) — under `fuzz/fuzz_targets/`,
  built and smoke-run in CI (`.github/workflows/fuzz.yml`), with the invariant
  that no input may panic.

## Consequences

Malformed evidence degrades to an error or a partial result, never a crash or an
out-of-bounds read. The lints occasionally require more verbose bounds-checked
code than a quick `unwrap` would, and one deliberately defensive control-flow
choice (iterating `subkey("Count")` as an `Option` rather than an `if let`) is
annotated in-source to explain why. The fuzz targets are maintained surface and
run on every CI cycle. Because the panic-free guarantee is stated as *by lint*
(construction) and *fuzzed* (measured), the README avoids a bare, unprovable
"panic-free" absolute — consistent with the fleet's evidence-based robustness
wording.

## Status

Accepted.
