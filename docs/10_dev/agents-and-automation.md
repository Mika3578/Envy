# Envy Development Agents & Automation

**Last Updated:** 2026-09-10

## What exists today

- **CI/CD:** two-speed GitHub Actions (fast PR gate + full `develop` / scheduled analysis). See [CI architecture](#ci-architecture-two-speed) below.
- **Versioning:** `scripts/auto-version.ps1`, `scripts/bump-version.ps1`, `version.json`
- **Build:** `build_all.ps1` (local full-matrix build via MSBuild)
- **AI:** `.github/copilot-instructions.md`, `.cursor/rules/`

## CI architecture (two-speed)

Envy does **not** run the full analysis matrix on every pull request. Heavy work
is moved off the PR critical path without dropping coverage.

```
PR opened / new push
        │
        ▼
 Classify + lint + secrets     (~10-30 s, ubuntu)
        │
  ┌─────┴───────────────────────────┐
  │                                 │
 C++ / build changed            docs only
  │                                 │
  ├─ x64 Release + EnvyTests         └─ docs checks
  ├─ Win32 Release + EnvyTests            │
  ├─ CodeQL C++ `build-mode: none`        ▼
  └─ format diff                     PR Gate  (< 1 min)
        │
        ▼
     PR Gate   (waits only for jobs this PR needed)
```

After merge to `develop` (and weekly/nightly schedules):

- x64 + Win32 Release **and** Debug full solution
- CodeQL C++ **manual** traced MSBuild (more precise than PR `none`)
- CodeQL JavaScript and C#
- MSVC Static Analysis
- advisory clang-tidy

### Path classification

`.github/scripts/classify-changes.sh` (called from
`.github/workflows/classify-changes.yml`) labels a PR as `cpp`, `build`,
`remote`, `csharp`, `dependencies`, `docs`, and/or `workflow`. Jobs use `if:`
so required workflows always **start**. A skipped job is a successful required
check; a workflow skipped with `paths-ignore` can stay **Pending**.

| PR kind | Windows runners | CodeQL C++ | CodeQL JS | CodeQL C# | Remote JS |
| --- | --- | --- | --- | --- | --- |
| Docs-only | no | skip | skip | skip | skip |
| C++ / build | x64 + Win32 Release | `none` on ubuntu | skip | skip | skip |
| Remote only | no | skip | yes | skip | yes |
| SkinUpdater C# | no | skip | skip | yes | skip |

Workflow/classifier changes conservatively enable the jobs they could affect.

### Required `develop` contexts (live ruleset)

Do not rename these without a maintainer ruleset update:

`Build x64 Release`, `Build Win32 Release`, `Lint build files`,
`Vcpkg manifest sanity`, `Format Check`, `secret-scan`, `Analyze (c-cpp)`,
`Analyze (javascript-typescript)`.

`PR Gate` aggregates the jobs that classification said must run. It is **not**
a live required context yet. After it is stable, a maintainer can require only
`PR Gate` (plus `secret-scan` if desired) and drop the rest.

### Caches and CodeQL

- vcpkg uses the `actions/cache` files backend (`vcpkg-v3-…` keys, including
  Win32/`x86`). Current vcpkg has removed `x-gha`; a NuGet GitHub provider is
  a follow-up if that cache starts evicting again.
- PR CodeQL C/C++ uses `build-mode: none` (no second MSBuild). `develop` /
  weekly / manual keep `build-mode: manual` after vcpkg restore.
- Gitleaks and Dependency Review stay. Dependency Review runs when manifests
  change; vcpkg sanity always runs (required name).

### Follow-ups

- Parser fuzzers / sanitizers on nightly (out of the PR gate).
- clang-tidy with a real Windows `compile_commands.json`.
- Promote `PR Gate` to the single required ruleset context once measured.

## Automation reference

| Area | Tools / config |
|------|----------------|
| **Code analysis** | MSVC Code Analysis on `develop`/nightly; CodeQL (`none` on PR C++, manual on `develop`); `.clang-tidy` on `develop`/nightly |
| **Format / docs** | Differential `Format Check` on changed C/C++; markdown link check when docs change |
| **Dependencies** | Dependabot, GitHub dependency review, vcpkg manifest sanity |
| **Testing** | `EnvyTests.exe` after PR and `develop` MSBuild; Remote JS tests when `Remote/` changes |
| **Security** | Gitleaks on every PR, CodeQL, dependency review |

## Related

- [Guide](guide.md) · [Build](build.md) · [Status](status.md) · [AI Coding Guide](ai-coding-guide.md)
- [GitHub Issues](https://github.com/Mika3578/Envy/issues) · [Discussions](https://github.com/Mika3578/Envy/discussions)
