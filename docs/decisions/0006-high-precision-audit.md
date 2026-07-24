# 6. High-precision, quiet auditing gated on executable-image type

Date: 2026-07-24
Status: Accepted

## Context

UserAssist is a high-signal execution artifact, but most of its entries are
benign everyday launches. An audit that grades broadly would bury the examiner in
noise and train them to ignore it. The value of a graded finding here is triage:
it must stay silent on ordinary launches and fire only on a genuinely anomalous
pattern that is worth an analyst's attention. Two patterns clear that bar for
UserAssist evidence, and both must reuse the fleet's shared classification
knowledge rather than re-deriving system-binary or staging-directory lists
locally.

A bring-up pivot sharpened the second check: the initial staging-directory rule
fired on any UserAssist entry, including `.lnk` shortcuts sitting on the Public
Desktop — but a shortcut is not "a binary staged in a malware directory."
Commits `f39d20f` (RED: `.lnk` shortcuts must not fire) and `2683b53` (GREEN: gate
on executable-image type) narrowed it.

## Decision

`audit` (`forensic/src/lib.rs`) emits exactly two graded anomalies:

- **`USERASSIST-SYSTEM-BINARY-RELOCATED`** — **High**, `Concealment`, MITRE
  `T1036.005`. Fires when `forensicnomicon::processes::is_system32_binary(name)`
  is true but the recorded path contains neither `\SYSTEM32\` nor `\SYSWOW64\` —
  a Windows system-binary name launched from elsewhere (masquerading). This is
  why ADR 0005's path resolution is a prerequisite.
- **`USERASSIST-SUSPICIOUS-PATH`** — **Medium**, `Threat`, MITRE `T1204`. Fires
  when the path is an executable image *and*
  `forensicnomicon::heuristics::paths::is_suspicious_exec_path` flags it (Temp,
  Downloads, `$Recycle.Bin`, …). The executable-image gate uses a local
  `EXECUTABLE_IMAGE_EXTENSIONS` list so a `.lnk` shortcut or non-file shell token
  never fires.

Both the system-binary set and the suspicious-path set are reused from
`forensicnomicon`, not hand-maintained here. Anomalies implement
`forensicnomicon::report::Observation`, carrying severity, category, code, a
"consistent with …" note, MITRE refs, and a `filesystem`/`executable`
`SubjectRef` — so findings render uniformly through the fleet report model and
read as observations, never verdicts.

## Consequences

The audit is quiet on benign hives and loud only on the two triage-worthy
patterns; on the CFReDS hive it produces the real staged-`.exe` findings
(icloudsetup, the dotNetFx setup, `Au_.exe`) and drops the two false Public-Desktop
shortcut findings. Reusing `forensicnomicon`'s classifiers keeps the lists DRY and
consistent with every other fleet analyzer. The `EXECUTABLE_IMAGE_EXTENSIONS`
list is a local duplicate of intent already present in
`forensicnomicon::heuristics`; a shared `is_executable_image` helper belongs
upstream and is noted in-source for centralization. The two published codes are a
contract (`ronin-issen/CLAUDE.md`, "code is a published contract") — they will not
be renamed; new patterns get new codes.

## Status

Accepted.
