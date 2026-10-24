# Kad Windows test (isolated, no eMule or aMule needed)

Last updated: 2026-10-24

Purpose: let a maintainer start one CI build of Envy, let it bootstrap Kad2 for about ten
minutes and send back an anonymised log, without touching a personal installation.
This is a smoke test of Envy against the public Kad network. It is **not** an
interoperability result for HELLO, PING or any other opcode: a log line saying a request
was sent proves nothing, and a reply from a reference client is only shown by a
`valid_responses` or `Hello response` line.

## What is tested

The build under test and its commit are named by whoever hands you the artifact. The
integration branch `test/kad-integration-511-502-462` combines the nodes.dat byte order
fix, the HELLO layout and the bootstrap rotation; each of those has its own pull request.

## Isolation

Envy keeps part of its configuration in the registry (`HKCU\Software\Envy\Envy`), so a
plain copy of the program folder is not isolated. Two supported ways:

1. **Windows Sandbox** (Windows Pro, Enterprise or Education): `tools/kad-test/New-KadSandboxConfig.ps1`
   makes a `.wsb` file. The sandbox has its own registry and is erased on close.
2. **Copy and check**: `tools/kad-test/Run-KadTest.ps1` copies the build folder to
   `%USERPROFILE%\EnvyKadTest\<time>\` and starts the copy. Before starting it reads, without
   changing anything, the registry values `Path`, `UserPath`, `DataPath` and `MultiUser`; if
   they point outside the copy it stops. Settings such as `DebugLog` stay shared with your
   installation, so they are changed by hand in Envy (Settings, Advanced) and can be put back.

Neither script deletes or rewrites `HostCache.dat`, `nodes.dat` or any registry value of an
existing installation.

## Settings needed

- `eDonkey.EnableKad` is on by default (it appears as `EnableKad` in the Advanced settings).
- Set `General.DebugLog` on and `General.LogLevel` to the highest level (debug) so the
  `Kad2 status` lines appear. In Windows Sandbox the script sets both.

## Where the log is

`Envy.log` is written to the `Data` folder of the running copy, for example
`<copy>\Data\Envy.log`; with `MultiUser` on it is `%APPDATA%\Envy\Data\Envy.log`.

## What to look for (ten minutes)

- `Kad2 initialized` and `Kad nodes.dat imported N of M accepted contacts` (N must be above 0).
- Every minute a `Kad2 status:` line: `cached` (local contacts), `sent`, `valid_responses`,
  `accepted_contacts`, `malformed`, `rejected`, `send_failed`, `routing`.
- Success for bootstrap: `valid_responses` above 0 and `routing` above 0 and growing.
- If `sent` grows but `valid_responses` stays 0, the message
  `UDP bootstrap response not yet validated` appears; that points at reachability, not at
  the parser.

## Report

`Run-KadTest.ps1` writes `Envy-kad-report-anonymised.txt`. `Anonymise-KadLog.ps1` does the
same for an `Envy.log` taken from the sandbox. IP addresses become `<ipN>`, drive paths
`<path>`, 32 to 64 digit hex strings `<hex>`, `urn:` values and e-mail addresses are masked.
Only Kad lines are kept. Read the file once before sending it.
