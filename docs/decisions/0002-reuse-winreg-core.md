# 2. Parse the hive with `winreg-core`, not a hand-rolled REGF reader

Date: 2026-07-24
Status: Accepted

## Context

UserAssist lives inside a Windows registry hive: the value at
`Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{GUID}\Count` in a
user's `NTUSER.DAT`. Reaching those values requires a full REGF parser — base
block, hive bins, `nk`/`vk`/`lf`/`lh`/`ri` cells, key/value navigation — none of
which is specific to UserAssist. Re-implementing REGF here would duplicate a
solved problem, add a large untrusted-input parser to audit and fuzz, and drift
from the fleet's other registry consumers.

The fleet already publishes `winreg-core`, a generic REGF hive parser, and the
dependency-preference rule (`ronin-issen/CLAUDE.md`, "Dependency Preference —
prefer our own crates") makes reusing our own crate a hard rule, not a tiebreaker.

## Decision

Depend on `winreg-core` (`Cargo.toml`: `winreg-core = "0.2"`, with the inline note
"Generic REGF hive parser — UserAssist lives in NTUSER.DAT, so core walks its
schema with winreg-core"). `userassist-core` opens the hive with
`winreg_core::hive::Hive::from_bytes`, navigates to the UserAssist key with
`open_key`, and walks the two `{GUID}\Count` subkeys' values
(`core/src/lib.rs::parse_bytes`). The reader owns only the *UserAssist-specific*
knowledge: which key path, ROT13 name decoding, the `Count`-value binary struct,
and the `UEME_*` counter skip. All REGF mechanics belong to `winreg-core`.
Timestamp rendering in the CLI reuses `winreg_core::key::filetime_to_datetime`
(`forensic/src/bin/userassist4n6.rs`) rather than a private `FILETIME` converter.

## Consequences

`userassist-core` stays small and focused on the artifact, and inherits
`winreg-core`'s robustness and fuzzing for the hive layer. REGF bug fixes and
format-coverage improvements arrive via a dependency bump, benefiting every fleet
registry consumer at once. The reader is coupled to `winreg-core`'s API surface
(`Hive`, `HiveError`, key/value navigation); a breaking change there requires a
coordinated bump. `HiveError` is folded into the crate's `UserAssistError` so
callers see one error type (`core/src/lib.rs`).

## Status

Accepted.
