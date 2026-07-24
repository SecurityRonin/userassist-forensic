# 1. Reader/analyzer split — `userassist-core` + `userassist-forensic`

Date: 2026-07-24
Status: Accepted

## Context

UserAssist has two separable concerns: *decoding* the artifact (walk the
`NTUSER.DAT` hive, ROT13-decode value names, parse the run-count/`FILETIME`
struct) and *judging* it (grade a launch as masquerading or staging-directory
execution). A single crate would force a downstream tool that only wants decoded
entries — an examiner CLI, a correlation engine, another fleet analyzer — to
compile the finding-generation surface and pull `forensicnomicon`, and would
couple the raw reader to the audit's severity policy.

The fleet crate-structure standard (`ronin-issen/CLAUDE.md`, "Crate-structure
standard — reader/analyzer split") mandates the split for every format: one
workspace repo named `<x>-forensic` with a `core/` reader and a `forensic/`
analyzer.

## Decision

Ship two crates from one workspace (`Cargo.toml` `members = ["core",
"forensic"]`), following the fleet's Pattern A (single-format repo):

- **`userassist-core`** — the reader. `parse_bytes(&[u8]) -> Vec<UserAssistEntry>`
  (`core/src/lib.rs`); no findings, no severity, no MITRE. Depends only on
  `winreg-core` (see ADR 0002).
- **`userassist-forensic`** — the analyzer. `analyze_bytes` + `audit`
  (`forensic/src/lib.rs`) emit graded `forensicnomicon::report` findings, and the
  crate bundles the `userassist4n6` examiner binary
  (`forensic/src/bin/userassist4n6.rs`). Depends on `userassist-core`,
  `winreg-core`, and `forensicnomicon`.

The bare `userassist` name was free on crates.io, so no collision-driven rename
was needed (contrast the `bluetooth-forensic-core` case); the crates take the
plain `userassist-core` / `userassist-forensic` grammar. The examiner front-end
follows the fleet `<x>4n6` binary convention: `userassist4n6`.

The dependency direction is `forensic → core → winreg-core`, and `forensic →
forensicnomicon`. `userassist-core`'s API exposes decoded entries with full path,
run count, focus fields, and both `FILETIME`s — everything the audit needs — so
the analyzer builds *on* `core` rather than re-parsing the hive at a lower level
(the standard's default: build `-forensic` on `-core` when `-core`'s API exposes
what the audit needs).

## Consequences

A tool that only needs decoded launches links `userassist-core` alone, with a
minimal dependency tree. The audit's severity/MITRE policy lives entirely in
`userassist-forensic` and can evolve without touching the reader. The reader
stays medium-agnostic — it takes raw hive bytes, so it works over a live file, a
mounted image, or bytes carved from memory without knowing the source. The split
adds a second published crate to version and release (handled by release-plz;
`release-plz.toml`).

## Status

Accepted.
