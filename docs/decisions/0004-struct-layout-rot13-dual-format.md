# 4. UserAssist decoding: ROT13 names, little-endian struct, dual Win7/XP layouts

Date: 2026-07-24
Status: Accepted

## Context

The `Count` values under `…\Explorer\UserAssist\{GUID}` do not store paths or
counts in the clear. The value **name** is the launched program's path with every
ASCII letter ROT13-rotated; the value **data** is a fixed binary struct whose
field offsets differ between Windows XP and Windows 7+. Getting any offset,
width, or endianness wrong yields plausible-but-wrong evidence (a wrong run count
or a garbage timestamp) that would pass a self-authored round-trip test — the
exact trap the fleet's research-first discipline exists to prevent. The layout
therefore had to be taken from an authoritative reference, not from memory.

## Decision

Decode against the community reference implementations (`core/src/lib.rs`,
`docs/validation.md`):

- **Names are ROT13.** `rot13` rotates `A–Z`/`a–z` by 13 (its own inverse) and
  passes every other byte — digits, `\`, `:`, `{}`, punctuation — through
  unchanged, so paths and GUID tokens decode correctly.
- **The struct is little-endian**, read via `read_u32_le`/`read_u64_le`.
- **Two layouts, length-dispatched.** Modern (Windows 7+) is 72 bytes: run count
  `@4`, focus count `@8`, focus-time-ms `@12`, last-execution `FILETIME` `@60`.
  Legacy (Windows XP) is 16 bytes: run count `@4`, last-execution `FILETIME` `@8`
  (focus fields zeroed). `parse_struct` selects by `data.len() >= 72` then `>= 16`,
  and returns `None` for anything shorter.
- **Bookkeeping counters are skipped.** Values whose decoded name starts with
  `UEME_CTLSESSION` or `UEME_CTLCUACount` are session/UI counters, not launches,
  and are excluded from the entry list.

Offsets and the ROT13 scheme are confirmed against `regipy`'s `user_assist`
plugin (itself derived from libyal `winreg-kb`) and Didier Stevens' UserAssist
research, and cross-checked field-for-field on a real hive (see ADR 0004's
validation companion, `docs/validation.md`).

## Consequences

Decoded entries match an independent oracle byte-for-byte on real data, so the
run counts and timestamps carried into findings are trustworthy. Length-dispatch
covers both major Windows eras without a version flag. Skipping the `UEME_*`
counters yields a clean launch list (61 entries on the CFReDS hive, matching
regipy). The struct offsets are a hard contract with the format; a future
Windows layout change would require a new length branch, added additively without
disturbing the existing two.

## Status

Accepted.
