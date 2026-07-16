# userassist-forensic

[![Crates.io](https://img.shields.io/crates/v/userassist-forensic.svg)](https://crates.io/crates/userassist-forensic)
[![CI](https://github.com/SecurityRonin/userassist-forensic/actions/workflows/ci.yml/badge.svg)](https://github.com/SecurityRonin/userassist-forensic/actions)
[![Rust 1.85+](https://img.shields.io/badge/rust-1.85%2B-orange.svg)](https://www.rust-lang.org)
[![unsafe forbidden](https://img.shields.io/badge/unsafe-forbidden-success.svg)](https://github.com/rust-secure-code/safety-dance)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-blue.svg)](LICENSE)
[![Sponsor](https://img.shields.io/badge/sponsor-h4x0r-ea4aaa?logo=github-sponsors)](https://github.com/sponsors/h4x0r)

**Prove which GUI programs a user launched — and how many times, and when they last ran — straight from `NTUSER.DAT`, on any OS.** A panic-free-by-construction reader for the Windows UserAssist artifact plus an analyzer that flags masquerading and staging-directory execution.

## Run it

```console
$ cargo install userassist-forensic          # installs the userassist4n6 binary
$ userassist4n6 /path/to/NTUSER.DAT
UserAssist: 61 entries
Findings (5):
  [MEDIUM] USERASSIST-SUSPICIOUS-PATH  C:\Users\informant\Downloads\icloudsetup.exe
    icloudsetup.exe at C:\Users\informant\Downloads\icloudsetup.exe (run count 0) sits in a directory commonly used to stage malware — consistent with suspicious execution.
  [MEDIUM] USERASSIST-SUSPICIOUS-PATH  C:\Users\informant\AppData\Local\Temp\~nsu.tmp\Au_.exe
    Au_.exe … sits in a directory commonly used to stage malware — consistent with suspicious execution.
```

`--all` lists every launch (run count, last-execution time, path) sorted by recency.

## What it decodes

UserAssist lives in each user's hive at
`Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{GUID}\Count`. There are two `{GUID}`
subkeys — one for executables, one for Start-Menu shortcuts. The value **names** are **ROT13**-encoded
program paths; the value **data** is a fixed binary struct:

- **Modern (Windows 7+)** — 72 bytes: session id, **run count** (offset 4), **focus count** (8),
  **focus time ms** (12), **last-execution `FILETIME`** (60) → `UserAssistEntry`.
- **Legacy (Windows XP)** — 16 bytes: run count (offset 4), last-execution `FILETIME` (8).

The `UEME_CTLSESSION` / `UEME_CTLCUACount` bookkeeping counters are skipped.

> **UserAssist is per-user evidence of *interactive GUI launch*** — Explorer only records programs a
> user started from the shell (double-click, Start menu, taskbar), not services or command-line
> execution. A non-zero run count with a last-execution time is strong evidence the user ran that
> program. Findings are observations ("consistent with …"), never verdicts.

## Layers

- **`userassist-core`** — `parse_bytes(&[u8]) -> Vec<UserAssistEntry>`. Walks the hive with
  [`winreg-core`], ROT13-decodes names, bounds-checks every struct read. `#![forbid(unsafe_code)]`,
  panic-free by lint.
- **`userassist-forensic`** — `analyze_bytes` + `audit` (graded [`forensicnomicon`] findings) and the
  `userassist4n6` CLI.

## Validation

Tier-1 against a **real `NTUSER.DAT`** — the NIST **CFReDS Data-Leakage Case** hive (public domain) —
cross-checked with an independent oracle, **regipy**:

| Decoded path | Run count | Last-execution `FILETIME` |
|---|---|---|
| `C:\Users\Public\Desktop\Google Chrome.lnk` | 2 | `130716052100840000` |
| `C:\Users\informant\Desktop\Download\ccsetup504.exe` | 1 | `130717690768820000` |
| `C:\Users\informant\AppData\Local\Temp\~nsu.tmp\Au_.exe` | 0 | `0` |

regipy and `userassist-core` agree on the entry count (**61**, counters excluded) and on every
decoded field. See `core/tests/data/README.md`.

## Findings

| Code | Severity | MITRE | Fires when |
|---|---|---|---|
| `USERASSIST-SYSTEM-BINARY-RELOCATED` | High | T1036.005 | A Windows system-binary name launched from a non-`System32` path (masquerading). |
| `USERASSIST-SUSPICIOUS-PATH` | Medium | T1204 | A program launched from a common staging directory (Temp, Downloads, `$Recycle.Bin`, …). |

---

[Privacy Policy](https://securityronin.github.io/userassist-forensic/privacy/) · [Terms of Service](https://securityronin.github.io/userassist-forensic/terms/) · © 2026 Security Ronin Ltd
