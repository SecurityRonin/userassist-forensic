# 5. Resolve `KNOWNFOLDERID` GUID prefixes to real paths before auditing

Date: 2026-07-24
Status: Accepted

## Context

UserAssist stores executable entries not as bare `C:\...` paths but as
`{FOLDERID-GUID}\program.exe`, where the leading GUID is a Microsoft
`KNOWNFOLDERID` standing in for a well-known directory (System32, Program Files,
the user's Downloads, etc.). Left unresolved, a genuine `System32` binary decodes
to a path-less bare filename. The forensic audit's system-binary-relocation check
(ADR 0006) then sees `calc.exe` / `cmd.exe` / `explorer.exe` with no `\System32\`
in the path and mis-flags each as a **High**-severity masquerade — a flood of
false positives on the most ordinary launches. This was found during bring-up and
fixed in commit `37cf6a5` ("resolve KNOWNFOLDERID GUID prefixes to real paths").

## Decision

`resolve_known_folder` (`core/src/lib.rs`), applied inside `parse_bytes`
immediately after ROT13-decoding each name, maps Microsoft's fixed
`KNOWNFOLDERID` set (`{1AC14E77-…}` → `C:\Windows\System32`, `{7C5A40EF-…}` →
`C:\Program Files (x86)`, `{374DE290-…}` → `%USERPROFILE%\Downloads`, and the
rest) to a real folder path, then reattaches the trailing component. An
unrecognized GUID — or a name that is not a `{GUID}\tail` at all — is returned
verbatim, so unknown or non-path tokens (`AppUserModelId`, Control-Panel tokens)
survive unchanged. The GUID→folder table is a hardcoded literal set, but it is not
a special-case hack: it is Microsoft's documented, fixed `KNOWNFOLDERID`
mapping — a genuine, citable discontinuity in the domain — so baking the constants
in is correct by the domain's own definition.

## Consequences

The audit sees real paths, so a `System32` launch reads as `System32` and does
not fire the relocation finding; the false-positive flood is gone (commit
`94b4f4b` records "zero false relocations after the GUID-resolution fix" on the
CFReDS hive). The resolution happens once, in the reader, so every consumer of
`UserAssistEntry` — CLI, audit, downstream correlation — gets resolved paths for
free. The mapping is only as complete as the enumerated set; a `KNOWNFOLDERID`
not in the table degrades gracefully to the verbatim `{GUID}\...` form rather than
guessing, and new folders can be added additively.

## Status

Accepted.
