# userassist-forensic

Read a Windows **`NTUSER.DAT`** — the per-user **UserAssist** record of GUI program launches (path,
run count, last-execution time, focus time) — on any OS.

`userassist-core` is the reader (`parse_bytes(&[u8]) -> Vec<UserAssistEntry>`; ROT13-decodes the
value names and decodes the binary run-count/`FILETIME` struct); `userassist-forensic` adds graded
findings and the **`userassist4n6`** CLI.

```console
$ cargo install userassist-forensic
$ userassist4n6 /path/to/NTUSER.DAT
```

See the [project README](https://github.com/SecurityRonin/userassist-forensic) for full usage and
the findings table, and [Validation](validation.md) for how correctness is established.
