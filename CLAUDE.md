# Claude Code - Envy repository

Authoritative rules: [`AGENTS.md`](./AGENTS.md). Read it first; everything below
is a thin pointer.

## Quick context

- **Stack**: C++ MFC, MSBuild, Visual Studio 2026 (toolset **v145**)
- **C++**: C++20 first-party, C++17 legacy plugins
- **OS**: Windows 10 1809+ (XP/Vista/7/8 dropped)
- **Deps**: vcpkg manifest (`vcpkg.json`)

## Build

```cmd
msbuild "Visual Studio\Envy.sln" /m /p:Configuration=Release /p:Platform=x64 ^
  /p:PlatformToolset=v145 /p:WindowsTargetPlatformVersion=10.0 ^
  /p:VcpkgEnableManifest=true /p:VcpkgTriplet=x64-windows-static
```

## Workflow

- Branch from `develop` using `type/short-kebab-summary` names; no tool prefixes
- Shared tracking: GitHub Issues, Projects, Milestones, PRs
- Session notes: `.local/` (gitignored) — never commit volatile trackers
- Draft PRs only unless maintainer approves merge
- English artifacts; chat may follow the user's language

## See also

- [`AGENTS.md`](./AGENTS.md), [`MODERNIZATION.md`](./MODERNIZATION.md)
- [`.github/CONTRIBUTING.md`](./.github/CONTRIBUTING.md)
