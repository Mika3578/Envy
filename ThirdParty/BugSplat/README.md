# BugSplat Windows SDK (redistributable slice)

Envy x64 links the official BugSplat 7 **static `/MT`** libraries and ships the
out-of-process runtime next to `Envy.exe`. This directory is populated by
maintainers — it is **not** the full SDK archive.

## Obtain the SDK

1. Download the **Windows Native C++** package from BugSplat (account required):
   https://app.bugsplat.com/browse/download_item.php?item=native
2. Unzip locally (do not commit the zip).
3. Import the required files:

```powershell
# First import: official portal only, Authenticode on signed binaries, record hashes
pwsh scripts/import-bugsplat-sdk.ps1 `
  -SourceRoot C:\path\to\unzipped-sdk `
  -SdkVersion 7.0.5 `
  -AllowUnlistedSource `
  -ConfirmOfficialSdkSource `
  -RecordReferenceHashes

# Later imports / upgrades: SHA-256 in SDK-HASHES.json must match before copy
pwsh scripts/import-bugsplat-sdk.ps1 -SourceRoot C:\path\to\unzipped-sdk -SdkVersion 7.0.5 -RecordReferenceHashes
```

BugSplat **application version** in `Envy.exe` uses the same `major.minor` string as
`GetVersionNumber()` / `FileVersionInfo` (for example `5.0`). Symbol upload CI reads
that value from the built `Envy.exe` so it matches `BugSplat(db, L"Envy", version)`.
Git revision remains in the `envy_revision` crash attribute, not the BugSplat version field.

4. Review `SDK-MANIFEST.json` and `SDK-HASHES.json`, then commit the imported tree.

The public [BugSplat-Git/Samples](https://github.com/BugSplat-Git/Samples)
repository ships `/MD` prebuilt libraries only. **Do not** use those libraries
for Envy production builds.

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
