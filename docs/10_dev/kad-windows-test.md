# Kad Windows test (isolated, no eMule or aMule needed)

Last updated: 2026-10-24

Purpose: let a maintainer start one CI build of Envy, let it bootstrap Kad2 for about ten
minutes, restart it once and send back an anonymised log, without touching a personal
installation. This is a smoke test of Envy against the public Kad network. It is **not** an
interoperability result for HELLO, PING or any other opcode: a log line saying a request
was sent proves nothing; a reply from a peer is only shown by `valid_responses` or
`res_received` above 0.

## What is tested

The integration branch `test/kad-integration-511-502-462` combines the nodes.dat byte order
fix (#511), the HELLO layout and inbound limits (#502) and the bootstrap rotation (#462);
each has its own pull request. A build of a single pull request tests only that change.

## Getting the build

1. Open the GitHub Actions run named in the hand-over (workflow **Build**), scroll to
   **Artifacts** and download `envy-x64-Release` (kept 7 days for pull requests, 14 days for
   manual runs).
2. Unzip it. `artifact-provenance.json` names the commit that was built (`built_commit`).
3. Use the `artifacts\portable` folder: it holds `Envy.exe` with `Data\`, `Skins\` and the
   other runtime folders. `Envy.exe` links MFC and the C runtime statically.

Without an artifact, build `Visual Studio\Envy.sln` (Release, x64, toolset v145) in Visual
Studio 2026 and run `scripts\release\stage-portable.ps1 -Platform x64`; the result is
`artifacts\portable`.

## Isolation

Envy reads `Path`, `UserPath`, `DataPath` and `MultiUser` from `HKCU\Software\Envy\Envy`,
falling back to `HKLM\Software\Envy\Envy`; the installer writes `Path` and `UserPath` to HKCU
and `MultiUser` to HKLM. A copy of the program folder therefore uses the installed profile.
Two supported ways:

1. **Windows Sandbox** (Windows Pro, Enterprise or Education):
   `tools/kad-test/New-KadSandboxConfig.ps1 -BuildFolder <...>\artifacts\portable` makes a
   `.wsb` file. The sandbox has its own registry and profile and is erased on close; the
   build folder is mapped read-only.
2. **Copy and check** (no installed Envy): `tools/kad-test/Run-KadTest.ps1` copies the build
   folder to `%USERPROFILE%\EnvyKadTest\<time>\` and starts the copy. It first reads, without
   changing anything, the four registry values in HKCU and HKLM and stops if any points
   outside the copy, which is always the case with an installed Envy.

Neither script deletes or rewrites `HostCache.dat`, `nodes.dat` or any registry value of an
existing installation.

## Windows Sandbox run

The sandbox script sets, in the sandbox registry only, `DebugLog` = 1, `LogLevel` = 4
(debug) and `Settings\FirstRun` = 0, so the QuickStart wizard is skipped and Envy connects on
its own (`Connection.AutoConnect` is on by default; `eDonkey.EnableKad` too). Envy then runs
for `-Minutes` (default 10), is closed normally (which saves `HostCache.dat`), and is started
again for `-RestartMinutes` (default 3).

Optional migration check: `-HostCacheFile <copy of an old HostCache.dat>` places a copy of
that file in the sandbox `Data` folder before the first run. The original is not modified.
The file holds peer addresses from that profile, so do not send it or the raw logs.

Results in the `out` folder: `summary.txt`, `Envy-after-run1.log`, `Envy-after-run2.log`.

## What to look for

| Check | Expected | If not |
| --- | --- | --- |
| Start | `Kad2 initialized` | Kad disabled or init failure |
| Import | `Kad nodes.dat imported N of M accepted contacts`, N > 0 | No usable `Data\nodes.dat`; then the HTTPS `K` download should follow |
| Destinations (build of #511 alone) | The first `Kad2: Sent bootstrap request to` targets equal the addresses decoded from `Data\nodes.dat` (decoder in PR #511). The integration build logs counters only; there `valid_responses` > 0 is the proof | Byte-order regression (#511) |
| Bootstrap | Every minute a `Kad2 status:` line; `valid_responses` > 0 and `routing` > 0 and growing | `sent` grows but `valid_responses` stays 0: UDP reachability or peers silent, not the parser; `Kad2: UDP bootstrap response not yet validated` then appears |
| Rotation | While `routing` is 0, `sent` and `timed_out` keep growing and `deferred` rises as unanswered endpoints back off; `send_failed` stays near 0 once connected | Rotation or backoff defect (#462) |
| Malformed | `malformed` and `rejected` stay small | Many malformed replies: compare with #462 framing notes |
| HELLO | `Kad2 hello:` line with `req_sent`, `res_received` and `res_verified` above 0 once contacts exist; `res_malformed` small | HELLO layout (#502), or peers keeping Envy unverified (no UDP keys) |
| Migration (optional) | `Kad host cache: dropped N contact(s) imported from nodes.dat by an earlier build`, then a nodes.dat import; `summary.txt` shows version 2 before and 3 after run1 | Migration not applied (#511) |
| Restart | `summary.txt`: version 3 after run1 and run2; run2 has no `dropped` line and reaches `routing` > 0 again | Saved state not usable after restart |

## Limits of this test

- Peers are public Kad nodes (mostly eMule and aMule). Replies show that those clients
  answer Envy's requests; they do not prove every opcode or the reverse direction.
- A local controlled peer cannot be used for the bootstrap path: the nodes.dat reader rejects
  loopback and private addresses, and the host cache rejects reserved ones, as eMule and aMule
  do with their default LAN filtering. Malformed replies, rotation, backoff and HELLO parsing
  are covered by the deterministic EnvyTests suites instead.
- Windows Sandbox uses NAT; inbound Kad requests from peers do not reach Envy, so Envy stays
  firewalled there. Outbound bootstrap and its replies work.

## Report

`Anonymise-KadLog.ps1 -LogFile out\Envy-after-run2.log` writes an anonymised copy:
IP addresses become `<ipN>`, drive paths `<path>`, 32 to 64 digit hex strings `<hex>`, `urn:`
values and e-mail addresses are masked, and only Kad lines are kept. Read the file once
before sending it, together with `summary.txt` and `artifact-provenance.json`.
