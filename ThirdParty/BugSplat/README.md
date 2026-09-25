# BugSplat Windows SDK (redistributable slice)

Envy x64 links the official BugSplat 7 **static `/MT`** libraries and ships the
out-of-process runtime next to `Envy.exe`. This directory is populated by
maintainers — it is **not** the full SDK archive.

## Obtain the SDK

1. Download the **Windows Native C++** package from BugSplat (account required):
   https://app.bugsplat.com/browse/download_item.php?item=native
2. Unzip locally (do not commit the zip).
3. Establish trust baseline (first time or SDK upgrade — **separate maintainer PR**):

```powershell
pwsh scripts/establish-bugsplat-sdk-trust.ps1 `
  -SourceRoot C:\path\to\unzipped-sdk `
  -SdkVersion 7.0.5 `
  -WriteReferenceHashes `
  -ConfirmOfficialPortalDownload `
  -ConfirmMaintainerBaselineReview
```

BugSplat does **not** publish an independent SHA-256 manifest for the Native zip.
`SDK-HASHES.json` records a **maintainer-reviewed baseline** (see `trustModel` in that
file). SHA-256 detects drift after that baseline is committed; it is not proof against
a compromised first download. PE binaries (`BugSplatMonitor.exe`, `BugSplatWer.dll`,
`BugSplatRc.dll`) must pass Authenticode with a BugSplat publisher subject when signed.

4. Import into this directory (fail-closed; never rewrites `SDK-HASHES.json`):

```powershell
pwsh scripts/import-bugsplat-sdk.ps1 -SourceRoot C:\path\to\unzipped-sdk
```

For SDK upgrades, re-run `establish-bugsplat-sdk-trust.ps1` with `-AllowBaselineUpgrade`
after review, then `import-bugsplat-sdk.ps1`.

BugSplat **application version** in `Envy.exe` uses the same `major.minor` string as
`GetVersionNumber()` / `FileVersionInfo` (for example `5.0`). Symbol upload CI reads
that value from the built `Envy.exe` so it matches `BugSplat(db, L"Envy", version)`.
Git revision remains in the `envy_revision` crash attribute, not the BugSplat version field.

5. Review `SDK-MANIFEST.json` and `SDK-HASHES.json`, then commit the imported tree.

Self-test (no SDK required): `pwsh scripts/import-bugsplat-sdk.selftest.ps1` (also runs in CI Lint job).

The public [BugSplat-Git/Samples](https://github.com/BugSplat-Git/Samples)
repository ships `/MD` prebuilt libraries only. **Do not** use those libraries
for Envy production builds.

### Why not `BugSplat-Git/bugsplat-crashpad` GitHub releases?

Maintainers evaluated the official public Crashpad bundles (2026-09-25) as a
possible substitute for the login-gated Native zip. They **do not** unblock x64
BugSplat 7 integration for Envy:

| Source | Pin | SHA-256 (asset) | CRT (probe) | Replaces Native SDK? |
| --- | --- | --- | --- | --- |
| `crashpad-db44314-windows-x64.tar.xz` | tag `crashpad-db44314` | `21d90472abeb8ac4595fd4af55b113930c95bb231dc887d0948099ab1ac1970c` | `/MD` (`PREBUILT.json` `extra_cflags="/MD"`; `client.lib` → `msvcrt.lib` / `msvcprt.lib`) | No |
| `crashpad-windows-v20260825-60dd943.tar.gz` | tag `v20260825-60dd943` | `ab478196e6675ca79e1e737afa8a97fc2b06b6dd21deabe0a4f1f6f737801cba` | `/MD` Release + `/MDd` Debug on `client.lib` | No |

Envy x64 uses **static** `/MT` and `/MTd` (`Envy.vcxproj`). Linking these
Crashpad archives would risk LNK2038/LNK2005 CRT mismatches (same class of issue
as Samples `/MD` libs). The archives also lack `BugSplat.lib`, `BugSplatMonitor.exe`,
`BugSplatWer.dll`, and the native consent dialog stack assumed by D-020 / #354.

Win32 already uses Crashpad via vcpkg for legacy Stage A; x64 still needs the
**Native** SDK import path above until a separate, reviewed migration is opened.

## Layout

```
ThirdParty/BugSplat/
  inc/BugSplat.h
  x64/Release/lib/mt/BugSplat.lib
  x64/Debug/lib/mt/BugSplat.lib
  x64/Release/bin/BugSplatMonitor.exe
  x64/Release/bin/BugSplatWer.dll
  x64/Release/bin/BugSplatRc.dll
  (matching Debug/bin for local Debug builds)
```

## Licensing

Verify redistribution terms for the SDK version you import before shipping
installer builds. Record the SDK version and source URL in `SDK-MANIFEST.json`
when updating.

## Database name (not a secret)

Official release builds may pass `/p:EnvyBugSplatDatabase=<name>` to MSBuild.
Forks and PR builds should leave this empty so crash upload stays disabled while
the SDK slice is still required to compile x64.
