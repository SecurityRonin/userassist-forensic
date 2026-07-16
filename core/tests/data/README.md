# userassist-core test data — provenance

| File | Description | Size |
|---|---|---|
| `ntuser.hve` | A real `NTUSER.DAT` registry hive containing a populated `UserAssist` key | ~1 MiB |

## Source

`ntuser.hve` is the **`informant` user's `NTUSER.DAT`** from the **NIST CFReDS "Data Leakage Case"**
scenario image — a public-domain reference dataset published by the U.S. National Institute of
Standards and Technology.

- Scenario: <https://cfreds.nist.gov/all/NIST/DataLeakageCase>
- Extracted from the CFReDS Data-Leakage `.E01` disk image (`C:\Users\informant\NTUSER.DAT`),
  no transaction-log replay (plain hive read).

CFReDS datasets are produced by NIST and released into the **public domain**, so the hive is
committed directly (it is ≤ 1 MiB).

## Integrity

| Algorithm | Digest |
|---|---|
| MD5 | `58dd41e60ed8cc9f91944a81335a07dd` |
| SHA-256 | `2190b57e2908d36f835589cc530c8c471ea48952f8edea70cc91488d9b5d1f64` |

## Ground truth / oracle

Cross-validated with **regipy** (its `user_assist` plugin and a raw key/value cross-read that
ROT13-decodes the names and parses the binary struct independently):

- `…\Explorer\UserAssist` has two `{GUID}` subkeys — `{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}`
  (executables) and `{F4E57C4B-2036-45F0-A9AB-443BCFE33D9F}` (shortcuts).
- **61** entries after skipping the `UEME_CTLSESSION` and `UEME_CTLCUACount` counter values (65
  raw `Count` values − 4 counters). regipy and `userassist-core` agree.
- Sample decoded entries (raw ROT13 decode, no `KNOWNFOLDER`-GUID substitution):
  - `C:\Users\Public\Desktop\Google Chrome.lnk` — run count 2, last-execution `FILETIME`
    `130716052100840000`.
  - `C:\Users\informant\Desktop\Download\ccsetup504.exe` — run count 1, `FILETIME`
    `130717690768820000`.
  - `C:\Users\informant\AppData\Local\Temp\~nsu.tmp\Au_.exe` — run count 0, `FILETIME` 0.

This is the single committed fixture; it exercises the full modern (Windows 7+) 72-byte struct
decode path.
