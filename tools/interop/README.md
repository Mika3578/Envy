# ENVY ↔ eMule / aMule interoperability harness (issue #160)

Opt-in **live integration** infrastructure. It does **not** prove that ENVY is
fully interoperable with eMule Community or aMule, and it does **not** replace
the deterministic first-party tests tracked by [#91](https://github.com/Mika3578/Envy/issues/91).

This harness exists so [#160](https://github.com/Mika3578/Envy/issues/160),
[#86](https://github.com/Mika3578/Envy/issues/86), and
[#87](https://github.com/Mika3578/Envy/issues/87) can attach reproducible
evidence instead of opcode-presence claims.

**Status after this preparation PR:** live interoperability evidence is still
**pending a Windows operator run**. Cursor Cloud validates Python dry-run /
self-test only — never native `Envy.exe`.

**Required PR CI never launches eMule/aMule and never depends on the public
ED2K/Kad network.**

## What this is / is not

| Class | Where | Required for unit tests / PR CI? |
| --- | --- | --- |
| Deterministic first-party tests | `tests/EnvyTests` + harness golden parse | Yes (EnvyTests on Windows; harness unit tests on Ubuntu) |
| Opt-in local integration | `--live` with isolated profiles | No |
| Public-network tests | scenarios marked `external` + `--allow-external-network` | No |
| Captured evidence | `--hello-capture` / `--packet-evidence` / `--ingest-hello` | No |

Do **not** patch ED2K/Kad production code to make a scenario PASS. Record FAIL
with artifacts and open/link a focused issue.

## Three orthogonal states

Every scenario and capability row tracks:

| Axis | Meaning |
| --- | --- |
| **production** | `implemented` / `partial` / `not_implemented` in ENVY source |
| **harness** | `automated` / `evidence_hooks` / `registered_only` / `not_applicable` |
| **evidence** | `verified` / `unverified` / `pending_operator` / `not_applicable` |

Examples:

- ED2K compressed upload — production **implemented** (#252), harness
  **evidence_hooks**, live evidence **unverified**.
- Buddy — production **not_implemented**, harness **registered_only**,
  evidence **not_applicable**.

### Final run results

| Result | Meaning |
| --- | --- |
| `PASS` | Documented PASS criteria met (see `pass_criteria.py`) |
| `FAIL` | Evidence present and wrong, or honesty-table regression |
| `SKIP` | Gated (dry-run, missing binaries/tools, no evidence yet, external not opted in). **Not** “production missing”. |
| `NOT_IMPLEMENTED` | Production behavior genuinely absent (Buddy, UDP firewall, …) |

A process being alive is a PASS only for explicit startup scenarios. Protocol
scenarios require packet/log evidence.

## One command

From the repository root:

```bash
python3 tools/interop/run.py --dry-run
python3 tools/interop/run.py --dry-run --scenarios current
python3 tools/interop/run.py --self-test
```

Windows live helper (operator machine):

```powershell
.\tools\interop\windows\run-live.ps1 -EnvyExe "D:\Build\Envy.exe" -EmuleExe "C:\Program Files\eMule\emule.exe" -ReferenceVersion "0.70a" -Scenarios current
```

Manual GUI steps: [`OPERATOR_CHECKLIST.md`](./OPERATOR_CHECKLIST.md).

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
| Packet evidence dump | `--packet-evidence` | `ENVY_INTEROP_PACKET_EVIDENCE` |
| Hello capture | `--hello-capture` | `ENVY_INTEROP_HELLO_CAPTURE` |
| Timeouts | `--startup-timeout-sec` / … | matching `ENVY_INTEROP_*` |
| Scenario list | `--scenarios` | `ENVY_INTEROP_SCENARIOS` |
| External network | `--allow-external-network` | `ENVY_INTEROP_ALLOW_EXTERNAL_NETWORK` |
| Optional pcap | `--enable-pcap` | `ENVY_INTEROP_ENABLE_PCAP` |
| Pcap interface | (env only) | `ENVY_INTEROP_PCAP_IFACE` |

See `config.example.json`. No developer machine paths are hard-coded.
Process arguments are a list (`shell=False`); spaces and Unicode in paths are
safe.

## Capability honesty (current `develop`)

Recalculated from production units (not opcode constants alone). The harness
**records** these facts; it does not change `SendHello`.

| Feature | Advertised | Production | Harness | Live evidence | Cite |
| --- | --- | --- | --- | --- | --- |
| AICH C2C | 0 | not implemented | n/a | n/a | `Ed2kAichAdvertisedVersion` |
| SecureIdent RSA | 0 | not implemented | n/a | n/a | #75 |
| CryptLayer TCP obfuscation | 0 | not implemented | n/a | n/a | #121 |
| Ext Multipacket | 0 | not implemented | n/a | n/a | #129 |
| Source Exchange v1/v2 | 2 / bit | implemented | evidence hooks | unverified | IPv4-only wire |
| Large files | 1 | implemented | evidence hooks | unverified | I64 parts |
| Compressed receive | nibble 1 | implemented | evidence hooks | unverified | inflate path |
| Compressed send | nibble 1 | **implemented** (#252) | evidence hooks | unverified | `Ed2kCompressedUpload.h` |
| PUBLICIP | — | partial (#255/#258) | evidence hooks | unverified | `Ed2kLowIdCallback.h` |
| C2C CALLBACK | — | partial (#255/#258) | evidence hooks | unverified | 38-byte layout |
| REASKCALLBACKTCP | — | not implemented | registered | n/a | needs Buddy |
| Kad source search | Hello nibble **0** | implemented (#261) | evidence hooks | unverified | app-trigger SearchSource |
| Kad SEARCH_RES → ED2K | 0 | implemented (#251) | evidence hooks | unverified | `KadSearchResDelivery` |
| Kad routing | 0 | implemented (#257) | evidence hooks | unverified | `KadRoutingTable` |
| Kad TCP firewall | 0 | partial (#256) | evidence hooks | unverified | `KadFirewallCheck` |
| Kad UDP firewall | 0 | not implemented | registered | n/a | |
| Buddy / FINDBUDDY | 0 | not implemented | registered | n/a | |
| Kad callback | 0 | not implemented | registered | n/a | |
| nodes.dat v1/v2/v3 | — | implemented (#254) | evidence hooks | local ≠ live | `KadNodesDat.h` |

Hello Kad nibble stays **0** until Buddy/UDP firewall and live interop are
verified. Do not change the advertised nibble from this harness.

## Scenario aliases

| Alias | Contents |
| --- | --- |
| `phase1` | Deterministic + baseline live hooks |
| `current` | phase1 + compression / LowID partial / Kad partial |
| `deferred` | Buddy / REASK / UDP firewall / Kad callback (production absent) |
| `all` | Everything |

## Optional packet capture

`--enable-pcap` uses `dumpcap`, `tshark`, or `tcpdump` when on `PATH`. Bounded
filters use the configured TCP ports. Raw pcaps stay gitignored. Missing tools
→ SKIP (never silent install).

`--packet-evidence` accepts a hex/binary dump of ED2K **TCP** frames
(`0xE3`/`0xC5` sized headers) and Kad2 **UDP** datagrams (`0xE4` + opcode,
e.g. `SEARCH_SOURCE_REQ` 0x34 / `SEARCH_RES` 0x3B / `FIREWALLED_*`).
Observed public IPv4 values are never written into evidence JSON (presence
only). Fail closed on malformed frames.

## Golden reference captures

Envy self-goldens are committed. eMule Community / aMule slots stay empty until
a reviewed Windows capture exists — **do not fabricate** captures in Cloud VMs.

Required metadata for every committed golden: reference client, exact version,
direction, opcode, capture date, normalization, provenance.

```bash
python3 tools/interop/run.py --ingest-hello dump.hex \
  --reference-client emule-community --reference-version 0.70a
```

## Artifacts

Each run writes `tools/interop/artifacts/run-<UTC>/` (gitignored):

- `run-summary.json` / `run-summary.md` — schema v2 with production/harness/
  evidence states, PASS criteria, binary identity, process exits
- `config.sanitized.json`, `versions.txt`, `binaries.json`
- `logs/`, `sanitized/logs/`, optional `captures/`, `evidence/`

## Privacy

Sanitize before attaching to GitHub. Redacts username / profile paths /
APPDATA / non-loopback IPs / private keys / password= token= style secrets.
Protocol fields needed for deterministic interop evidence are normalized
deliberately (see golden ingest), not blindly erased.

## CI

`python3 tools/interop/run.py --self-test` and `--dry-run` run on Documentation
Check when `tools/interop/` or docs change. They must not require Windows, ENVY,
eMule, aMule, Wireshark, or Internet P2P.

Opt-in `workflow_dispatch` job `ED2K interop harness` repeats self-test/dry-run
only and is **not** a required Protect develop check.

## Follow-up

- Live Windows evidence attachment → #160 (owner of Envy ↔ eMule/aMule proof)
- Protocol gaps → focused issues under #86 / #87 (not this harness PR)
- CryptLayer honesty → #121
- SecureIdent RSA → #75
- Deterministic parser seam → #91
