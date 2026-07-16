# Validation

`userassist-core` is validated against a **real `NTUSER.DAT`** — the NIST **CFReDS Data-Leakage
Case** hive (public domain) — cross-checked with an independent oracle, **regipy** (its
`user_assist` plugin plus a raw key/value cross-read).

## Tier-1 (real data + independent oracle)

| Hive | UserAssist GUID subkeys | Entries (UEME counters excluded) |
|---|---|---|
| CFReDS Data-Leakage `NTUSER.DAT` | `{CEBFF5CD-…}` (executables) + `{F4E57C4B-…}` (shortcuts) | 61 |

regipy and `userassist-core` agree on the entry count (61, after skipping the `UEME_CTLSESSION`
and `UEME_CTLCUACount` counter values) and on every decoded field. Sample entries the Rust reader
reproduces byte-for-byte against the oracle:

| Decoded path | Run count | Last-execution `FILETIME` |
|---|---|---|
| `C:\Users\Public\Desktop\Google Chrome.lnk` | 2 | `130716052100840000` (2015-03-23T17:26:50.084Z) |
| `C:\Users\informant\Desktop\Download\ccsetup504.exe` | 1 | `130717690768820000` (2015-03-25T14:57:56.882Z) |
| `C:\Users\informant\AppData\Local\Temp\~nsu.tmp\Au_.exe` | 0 | `0` (never executed / focus-only) |

## Struct layout

The value **names** under `…\UserAssist\{GUID}\Count` are **ROT13**-encoded program paths. The value
**data** is a fixed binary struct. The modern (Windows 7+) layout is 72 bytes:

| Offset | Size | Field |
|---|---|---|
| 0 | 4 | session id |
| 4 | 4 | run count |
| 8 | 4 | focus count |
| 12 | 4 | focus time (ms) |
| 60 | 8 | last-execution `FILETIME` |

Windows XP uses a 16-byte struct (run count at offset 4, last-execution `FILETIME` at offset 8).
Offsets confirmed against **regipy**'s `user_assist` plugin (the reference implementation, derived
from libyal `winreg-kb`) and Didier Stevens' UserAssist research; the decoded timestamps match
regipy's independent parse. Committed fixture and provenance are in `core/tests/data/README.md`.
