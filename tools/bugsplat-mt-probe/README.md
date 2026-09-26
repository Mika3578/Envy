# BugSplat `/MT` integration probe

Isolated gate for [#353](https://github.com/Mika3578/Envy/issues/353). Not part of
`Visual Studio/Envy.sln`. Does not ship in the product.

Target: **BugSplat SDK v8.0.0 `/MT`** for **x64** (Win32 keeps Crashpad). This probe
validates static `/MT` link compatibility before changing `Envy.vcxproj` / `vcpkg.json`.

## Purpose

Prove that the official BugSplat Windows SDK static libraries in `lib\mt`
link with ENVY's runtime model (`/MT` Release, `/MTd` Debug) on VS 2026 / v145 /
x64 without migrating the application to `/MD`.

The public [BugSplat-Git/Samples](https://github.com/BugSplat-Git/Samples) tree
ships prebuilt `BugSplat.lib` files built with `/MD` (`MSVCRT`). Those libraries
are useful for toolchain smoke tests only. The `/MT` gate requires the full SDK
zip from BugSplat's download portal.

## SDK layout (official zip)

After unzipping the Windows Native C++ SDK:

```
<BUGSPLAT_SDK_ROOT>\
  inc\BugSplat.h
  x64\Release\lib\mt\BugSplat.lib
  x64\Debug\lib\mt\BugSplat.lib
  x64\Release\bin\BugSplatMonitor.exe
  ...
```

Download (BugSplat account): `https://app.bugsplat.com/browse/download_item.php?item=native`

Set `BUGSPLAT_SDK_ROOT` to the folder that contains `inc` and `x64` (not the
inner `BugSplat` folder unless that folder matches the layout above).

## Build

```cmd
set BUGSPLAT_SDK_ROOT=C:\path\to\unzipped-sdk
msbuild tools\bugsplat-mt-probe\BugSplatMtProbe.vcxproj ^
  /p:Configuration=Release /p:Platform=x64 /p:PlatformToolset=v145 ^
  /p:BugSplatProbeCrt=mt
```

Optional `/MD` smoke against Samples binaries (not the product gate):

```cmd
set BUGSPLAT_SDK_ROOT=C:\path\to\BugSplat-Git\Samples\BugSplat
msbuild tools\bugsplat-mt-probe\BugSplatMtProbe.vcxproj ^
  /p:Configuration=Release /p:Platform=x64 /p:PlatformToolset=v145 ^
  /p:BugSplatProbeCrt=md
```

When `BUGSPLAT_SDK_ROOT` is unset, the project defaults to
`%REPO%\.local\bugsplat-sdk` if present.

## Pass criteria

- Release + `BugSplatProbeCrt=mt`: links and produces `BugSplatMtProbe.exe`
  without LNK2038/LNK2005 CRT mismatches.
- Debug + `BugSplatProbeCrt=mt`: same for `/MTd`.
- Binary does not require a BugSplat database name at link time; runtime crash
  dialog tests use a disposable database configured locally (not in CI).
