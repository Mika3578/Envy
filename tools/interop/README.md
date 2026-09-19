# ENVY ↔ eMule / aMule interoperability harness (issue #160)

Opt-in **live integration** infrastructure. It does **not** prove that ENVY is
fully interoperable with eMule Community or aMule, and it does **not** replace
the deterministic first-party tests tracked by [#91](https://github.com/Mika3578/Envy/issues/91).

This harness exists so [#160](https://github.com/Mika3578/Envy/issues/160),
[#86](https://github.com/Mika3578/Envy/issues/86), and
[#87](https://github.com/Mika3578/Envy/issues/87) can attach reproducible
evidence instead of opcode-presence claims.

**Required PR CI never launches eMule/aMule and never depends on the public
ED2K/Kad network.**

## What this is / is not

| Class | Where | Required for unit tests / PR CI? |
| --- | --- | --- |
| Deterministic first-party tests | `tests/EnvyTests` + harness golden parse | Yes (EnvyTests on Windows; harness unit tests on Ubuntu) |
| Opt-in local integration | `--live` with isolated profiles | No |
| Public-network tests | scenarios marked `external` + `--allow-external-network` | No |
| Captured evidence | `--hello-capture` / `--ingest-hello` | No |

Do **not** patch ED2K/Kad production code to make a scenario PASS. Record FAIL
with artifacts and open/link a focused issue.

## One command

From the repository root:

```bash
python3 tools/interop/run.py --dry-run
```

Self-tests (no network, no reference binaries):

```bash
python3 tools/interop/run.py --self-test
```

Live run (operator-provided binaries only — never downloaded by CI):

```bash
python3 tools/interop/run.py --live \
  --envy-exe "/path/to/Envy.exe" \
  --amule-exe "/usr/bin/amuled" \
  --reference-client amule \
  --reference-version "2.3.3" \
  --scenarios phase1
```

Windows eMule Community example (paths may contain spaces or Unicode):

```text
python3 tools/interop/run.py --live --config tools/interop/config.example.json --envy-exe "D:\Build\Envy.exe" --emule-exe "C:\Program Files\eMule\emule.exe" --reference-client emule-community --reference-version "0.70a"
```

## Configuration

Priority: CLI > `ENVY_INTEROP_*` environment variables > JSON `--config`.

| Setting | CLI | Environment |
| --- | --- | --- |
| ENVY executable | `--envy-exe` | `ENVY_INTEROP_ENVY_EXE` |
| eMule executable | `--emule-exe` | `ENVY_INTEROP_EMULE_EXE` |
| aMule / amuled | `--amule-exe` | `ENVY_INTEROP_AMULE_EXE` |
| Working directory | `--work-dir` | `ENVY_INTEROP_WORK_DIR` |
| Artifact directory | `--artifact-dir` | `ENVY_INTEROP_ARTIFACT_DIR` |
| ENVY TCP port | `--envy-tcp-port` | `ENVY_INTEROP_ENVY_TCP_PORT` |
| Reference TCP port | `--reference-tcp-port` | `ENVY_INTEROP_REFERENCE_TCP_PORT` |
| Timeouts | `--startup-timeout-sec` / `--scenario-timeout-sec` / `--shutdown-timeout-sec` | matching `ENVY_INTEROP_*` |
| Scenario list | `--scenarios` | `ENVY_INTEROP_SCENARIOS` |
| Hello capture | `--hello-capture` | `ENVY_INTEROP_HELLO_CAPTURE` |

See `config.example.json`. No developer machine paths are hard-coded.
Process arguments are a list (`shell=False`); spaces and Unicode in paths are
safe and are not interpolated into a shell command.

## Reference clients

Not vendored. Not downloaded during CI.

| Client | Role | Isolation |
| --- | --- | --- |
| eMule Community | Primary ED2K/Kad2 wire reference | `APPDATA` / `LOCALAPPDATA` redirected into the run scratch tree. There is no `--config-dir` in this harness. **Never** write `config\` next to the operator's `emule.exe`. |
| aMule / `amuled` | Second interop target; easier headless | `amuled -c <isolated-profile>` |

Supported versions: whichever build the operator records with
`--reference-version`. Record the exact string in the run report. Typical
targets are current eMule Community releases and aMule 2.3.x, but the harness
does not gate on a version tuple.

## Isolation and cleanup

Each run creates `scratch/<run-id>/` under the artifact/work directory:

- `profiles/envy`, `profiles/emule`, `profiles/amule`
- `share/` (generated fixture)
- `incoming/`

Default `--cleanup` deletes **only** that owned scratch tree. Cleanup refuses
home directories, `C:\Users`, the process temp directory, POSIX temp roots
matched by path components (`tmp` under `/` or `/var`; never opened as scratch),
and any path not under the owned root. Children of the process temp directory
remain deletable when they are the owned scratch tree.

**Limitations**

- ENVY has no `--datadir`. Isolation uses redirected `APPDATA`. ENVY also takes
  a `Global\Envy` mutex; a second instance will not start. The harness **never**
  kills an existing user ENVY/eMule/aMule process.
- eMule Community similarly uses a single-instance mutex on many builds.
- Do not point `--work-dir` at a real user profile.

## Networking

- Prefer loopback. Default ports: ENVY `4662`, reference `4663`.
- Scenarios that need public ED2K/Kad infrastructure are marked `external` and
  stay `NOT_IMPLEMENTED` or `SKIP` unless `--allow-external-network`.
- Every wait is bounded. There are no indefinite polls.

Packet capture (`--enable-pcap`) is **optional**. Baseline operation does not
require dumpcap/tcpdump/Wireshark.

## Scenarios and results

Machine-readable states: `PASS`, `FAIL`, `SKIP`, `NOT_IMPLEMENTED`.

Phase 1 (`--scenarios phase1`):

| Id | Default dry-run | Notes |
| --- | --- | --- |
| `harness_self_check` | PASS | Harness version + git SHA |
| `envy_capability_honesty` | PASS | Advertised Hello bits vs implemented capabilities |
| `golden_envy_hello_parse` | PASS | Committed Envy *self-golden* (not eMule) |
| `golden_envy_helloanswer_parse` | PASS | Same for HelloAnswer |
| `fixture_generation` | PASS | 64 KiB harmless file + ED2K/SHA-256 |
| `hello_capture_import` | SKIP | Needs `--hello-capture` |
| `envy_startup` / `reference_startup` | SKIP | Need `--live` + binaries |
| `ed2k_connection` / `hello` / `hello_answer` / `muleinfo` / `peer_transfer` / `source_exchange` | SKIP | Need live processes **and** packet/log evidence. A process launch alone is not a protocol PASS. |

Future ids (`compressed_transfer_*`, `lowid_*`, `kad_*`) always return
`NOT_IMPLEMENTED` in this PR so later work can plug in handlers without
redesigning the runner.

`--scenarios all` includes the future rows (still `NOT_IMPLEMENTED`).

## Capability honesty (current `develop`)

The harness **records** these advertise vs implement facts. It does not change
`SendHello`.

| Feature | Advertised | Implemented | Issue |
| --- | --- | --- | --- |
| AICH C2C | 0 | no | #87 |
| SecureIdent RSA | 0 | no | #75 |
| CryptLayer TCP obfuscation | 0 | no | #121 |
| Ext Multipacket | 0 | no | #129 / #87 |
| Kad nibble | 0 | not app-integrated | #86 |
| Source Exchange v1/v2 | 2 / bit | yes (IPv4-only wire) | live unverified |
| Large files | 1 | yes | live unverified |
| Compression | nibble 1 | receive yes, **send no** | #87 |

Compression advertisement while upload compression is missing is **known debt**,
not a silent PASS of compressed transfer.

## Artifacts

Each run writes `tools/interop/artifacts/run-<UTC>/` (gitignored) containing:

- `run-summary.json` — schema version 1, scenario results, artifact *names*
  (not log bodies)
- `run-summary.md` — human summary for issue attachments
- `config.sanitized.json`, `versions.txt`
- `logs/`, `sanitized/logs/`
- optional `captures/` (raw pcaps stay out of git)

JSON fields: `schema_version`, `timestamp`, `harness_version`,
`harness_git_sha`, `envy_revision`, `reference_client`, `reference_version`,
`mode`, `scenario`, `result`, `duration_ms`, `reason`, `artifacts`.

## Privacy

Sanitize before attaching to GitHub. The sanitizer redacts:

- username / `USERPROFILE` / `APPDATA` / `/home/<user>` / `C:\Users\...`
- non-loopback IPv4/IPv6
- `BEGIN PRIVATE KEY` blocks
- `password=` / `token=` style assignments

Raw captures must not be committed unless reviewed. Committed goldens may
include only protocol bytes with documented normalization.

## Updating golden Hello captures

1. Capture on an isolated test profile (no personal shares).
2. `python3 tools/interop/run.py --ingest-hello dump.hex --reference-client emule-community --reference-version <exact>`
3. Review the candidate JSON: origin, version, direction, opcode, date,
   normalization.
4. Copy into `fixtures/golden/emule-community/` or `amule/` only after review.
5. Golden tests must check wire structure (opcode, userhash field layout,
   ClientID, TCP port, MiscOptions bits) — not application version strings alone.

Envy self-goldens in this tree duplicate
`tests/test_ed2k_hello_golden.cpp` for the Python parser. eMule/aMule slots are
**empty** until a real capture is reviewed.

## Process management

The harness tracks only PIDs it started, signals only those PIDs (and their
process group on POSIX), and never runs `pkill -f emule` / `killall amuled`.

## Test data

`fixture_generation` writes `envy-interop-fixture.bin` (64 KiB), contents
`ENVY-ED2K-INTEROP-FIXTURE\n` plus a repeating byte pattern. Size, ED2K (MD4),
and SHA-256 are recorded. Not copyrighted network content.

ENVY has no headless share-import CLI, so automated `peer_transfer` stays SKIP
until evidence is attached or a later headless/Remote hook exists.

## CI

`python3 tools/interop/run.py --self-test` and `--dry-run` run on Documentation
Check when `tools/interop/` or docs change. They must not require Windows, ENVY,
eMule, aMule, or Internet P2P.

## Follow-up issues

Protocol failures belong in focused issues, not in this harness:

- Kad routing / SEARCH_RES / Buddy — #86
- ED2K compressed upload, LowID/callback, AICH C2C, multipacket — #87
- CryptLayer honesty — #121
- SecureIdent RSA — #75
- Deterministic parser seam — #91
