# Windows operator checklist — ENVY ↔ eMule/aMule live evidence (#160)

This checklist is for a **local Windows** development machine (Cursor IDE /
Visual Studio). Cursor Cloud (Linux) can only validate Python dry-run/self-test;
it does **not** validate native `Envy.exe`.

Live interoperability evidence remains **pending** until this checklist is
completed and artifacts are attached to issue #160. Completing the harness PR
alone is **not** an interoperability claim.

## Before you start

1. Build Release|x64 `Envy.exe` with the repo’s MSBuild/v145 path (no absolute
   VS path is hard-coded in the harness).
2. Install or locate **eMule Community** and/or **aMule** yourself. The harness
   never downloads them.
3. Optional: install Wireshark so `dumpcap` / `tshark` are on `PATH`. Absence is
   SKIP for capture scenarios — do not let the harness install software.
4. Close any running personal Envy / eMule / aMule instances (single-instance
   mutex). The harness **never** kills user processes.
5. Read `tools/interop/README.md` result meanings (PASS ≠ process alive).

## One-shot helper

```powershell
.\tools\interop\windows\run-live.ps1 `
  -EnvyExe "<path>\Envy.exe" `
  -EmuleExe "<path>\emule.exe" `
  -ReferenceClient emule-community `
  -ReferenceVersion "<exact version string>" `
  -Scenarios current `
  -EnablePcap
```

Or call Python directly:

```text
python tools\interop\run.py --live --envy-exe "..." --emule-exe "..." --reference-client emule-community --reference-version "..." --scenarios current
```

## What the harness automates

| Step | Automated? |
| --- | --- |
| Verify `Envy.exe` / `emule.exe` exist | Yes |
| Refuse to kill foreign processes | Yes (by design) |
| Create isolated work/profile dirs | Yes (`APPDATA` redirect / aMule `-c`) |
| Generate deterministic fixture | Yes (`envy-interop-fixture.bin`) |
| Launch owned processes | Yes |
| Optional bounded pcap | Yes if tool present |
| Stop only owned processes | Yes |
| Sanitize logs / write summaries | Yes |

## Manual clicks ENVY cannot automate today

ENVY has no complete headless/control surface. Expect to click:

1. **First-run / wizard dialogs** (language, folders, firewall prompts) — dismiss
   or accept defaults **inside the isolated profile**, never your real profile.
2. **Shared folder** — add the harness `share\` directory (contains the
   generated fixture) as a shared library folder in both clients if sharing is
   required for the scenario.
3. **Incoming / download folder** — point at harness `incoming\` when prompted.
4. **ED2K network enable** — ensure eDonkey/Kad checkboxes match the scenario
   (local HighID tests may use no public server).
5. **Connect to server** — only for scenarios that need classic server callback
   / public search; requires `--allow-external-network` and is opt-in.
6. **Add / import transfer** — start a download of the fixture hash on the peer
   that should receive, or force an upload from the sharing side.
7. **Initiate local peer action** — if clients do not auto-connect on loopback,
   use “add source” / friend / known-client IP:`port` for the other harness
   instance (ENVY port default 4662, reference 4663).
8. **Compression scenarios** — confirm both sides negotiated compression
   (Hello nibble) and that the upload side actually sent `COMPRESSEDPART`;
   attach pcap or `--packet-evidence` dump. Process-alive is not enough.
9. **Kad scenarios** — enable Kad, ensure a `nodes.dat` is available under the
   isolated profile if testing bootstrap; distinguish local parse evidence from
   live DHT interop.
10. **Close prompts / UAC / Windows Firewall** — allow the **test** binaries for
    private networks only as needed; do not weaken the host firewall globally.
11. **Capture goldens** — after a clean Hello/HelloAnswer/MuleInfo exchange,
    export frames and run `--ingest-hello` / `--packet-evidence`. Commit only
    after provenance review (client, exact version, direction, opcode, date,
    normalization). Do **not** fabricate captures on Cloud VMs.

## PASS reminders

| Scenario class | PASS needs |
| --- | --- |
| `envy_startup` / `reference_startup` | Owned process stayed alive for startup timeout |
| `hello` / `hello_answer` / `muleinfo` | Parsed packet evidence |
| `compressed_transfer_*` | Expected COMPRESSEDPART / I64 opcode + transfer correctness |
| `kad_search_res` | SEARCH_RES delivery into ED2K sources — not “Kad thread running” |
| Buddy / REASK / UDP firewall / Kad callback | Cannot PASS — production absent |

## After the run

1. Open `tools/interop/artifacts/run-*/run-summary.md`.
2. Confirm `production_state` / `harness_state` / `evidence_state` columns.
3. Attach **sanitized** logs and evidence JSON to issue #160.
4. Keep raw `.pcap` out of git.
5. Open focused protocol issues for any FAIL — do not patch production inside
   the harness PR.
