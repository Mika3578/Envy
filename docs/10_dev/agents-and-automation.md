# Envy Development Agents & Automation

**Last Updated:** 2026-09-23

## What exists today

- **CI/CD:** two-speed GitHub Actions (fast PR gate + full `develop` / scheduled analysis). See [CI architecture](#ci-architecture-two-speed) below.
- **Local verify:** `scripts/ci-fast.ps1`, `scripts/ci-verify.ps1` (see [devsecops-envy.md](devsecops-envy.md)).
- **Versioning:** `scripts/auto-version.ps1`, `scripts/bump-version.ps1`, `version.json`
- **Build:** `build_all.ps1` (local full-matrix build via MSBuild)
- **AI / review:** CodeRabbit (advisory, `.coderabbit.yaml`), clang-tidy→reviewdog on PRs, `.github/copilot-instructions.md`, `.cursor/rules/`
- **Cloud Agent Linux env:** `.cursor/environment.json` provisions clang-format-18/clang-tidy (CI-aligned) plus cppcheck as an extra local tool, and `Remote/tests` npm deps (not a Windows MSVC substitute)
- **Dependencies:** Dependabot owns vcpkg, `Remote/tests` npm, and GitHub Actions updates. Renovate is intentionally not active to avoid duplicate dependency PR ownership.

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

| PR kind | Windows runners | CodeQL C++/JS/C# | Remote JS | Format Check |
| --- | --- | --- | --- | --- |
| Docs-only | no | always (own workflows) | skip | always (hunk diff) |
| C++ / build | x64 + Win32 Release | always | skip | always (hunk diff) |
| Remote only | no | always | yes | always (hunk diff) |
| SkinUpdater C# | no | always | skip | always (hunk diff) |

CodeQL workflows do **not** depend on `classify-changes` (classifier failure
must not recreate Code Scanning "configuration not found"). Format Check uses
LLVM `clang-format-diff` on `base...head` hunks under `Envy/`, `TorrentEnvy/`,
`HashLib/` with pinned `clang-format-18`.

### Required `develop` contexts (live ruleset)

Do not rename these without a maintainer ruleset update. Use the correct
GitHub App `integration_id` when editing the ruleset (Actions `15368`,
SonarCloud `12526`, GHAS/gitleaks `57789`).

`Build x64 Release`, `Build Win32 Release`, `Lint build files`,
`Vcpkg manifest sanity`, `Format Check`, `Documentation Check`,
`secret-scan`, `gitleaks` (GHAS check from SARIF upload), `PR Gate`,
`Analyze (c-cpp)`, `SonarCloud Code Analysis`.

Docs-only / non-Windows PRs still **emit** `Build x64 Release` and
`Build Win32 Release` as success no-ops on `ubuntu-latest` when classify
sets `run_windows_build=false` (same always-emit pattern as Documentation
Check). They must not stay SKIPPED under a strict ruleset.

CodeRabbit / reviewdog / Bugbot are **advisory** and must not be the sole
merge blocker. Live native review policy on Protect develop (re-verified
2026-09-20) is **≥1 APPROVED** review from a non-author reviewer. In this
solo-maintainer repo, GitHub Copilot Code Review may satisfy it only when
approval/counting are enabled in the Copilot repository UI, any path
allowlist matches every changed file, and GitHub records an actual
`APPROVED` review. An assessment is not an approval. See
[KNOWN_INCONSISTENCIES](../00_index/KNOWN_INCONSISTENCIES.md) and
[CI_AUDIT_2026-09](CI_AUDIT_2026-09.md). Dismiss stale on push remains on,
`require_last_push_approval` off, conversations resolved, signed commits,
force pushes blocked. PR Gate is CI wait only.

See [devsecops-envy.md](devsecops-envy.md) for the full stack map.
Measured timings, critical path, and CI cost notes live in
[CI_AUDIT_2026-09.md](CI_AUDIT_2026-09.md).

### Caches and CodeQL

- vcpkg uses the `actions/cache` files backend (`vcpkg-v3-…` keys, including
  Win32/`x86`). Current vcpkg has removed `x-gha`; a NuGet GitHub provider is
  a follow-up if that cache starts evicting again.
- PR CodeQL C/C++ uses `build-mode: none` (no second MSBuild). `develop` /
  weekly / manual keep `build-mode: manual` after vcpkg restore.
- PR CodeQL JavaScript/TypeScript and C# always run on every PR without a
  classify-changes dependency (JS: `build-mode: none`; C#: manual SkinUpdater
  with `queries: security-and-quality`).
- Format Check is required and **blocking** via `clang-format-diff-18` on
  changed hunks only (legacy off-diff lines do not fail). Major version pinned
  to 18 in CI.
- PR Gate requires `success` for must_pass checks (rejects `skipped`/`neutral`).
- Gitleaks and Dependency Review stay. Dependency Review runs on every pull
  request so classifier failures cannot suppress the check; vcpkg sanity always
  runs (required name).

### GitHub Actions SHA pinning (#96)

Third-party and GitHub-hosted actions under `.github/workflows/` and
`.github/actions/` are pinned to full commit SHAs with a trailing `# vN`
comment for the human-readable major (or exact) version.

To upgrade an action:

1. Resolve the desired tag to a commit:
   `gh api repos/<owner>/<repo>/git/ref/tags/<tag>`
   (for annotated tags, follow `object.sha` to the peeled commit).
2. Replace the SHA in every workflow/composite that uses that action.
3. Keep the `# v…` comment aligned with the tag you intended.
4. Open a small `ci/` or `security/` PR; confirm required checks still pass.

Do not reintroduce mutable `@vN` tags for external actions.

### Follow-ups

- Parser fuzzers / sanitizers on nightly (out of the PR gate).
- clang-tidy with a real Windows `compile_commands.json`.
- After CodeQL is complete on every PR for several merges: tighten Protect
  develop Code Scanning thresholds for CodeQL/Gitleaks to the strictest
  supported values (do not change thresholds before that evidence).
- Evaluate `security-extended` / `security-and-quality` for C++/JS in a
  measured advisory window before expanding blocking query suites.
- Evaluate dependency auto-merge separately only after review/ruleset behavior
  is stable. The repository currently creates dependency PRs automatically but
  does not auto-approve or auto-merge them.

## Automation reference

| Area | Tools / config |
|------|----------------|
| **Code analysis** | MSVC Code Analysis on `develop`/nightly; CodeQL (`none` on PR C++, manual on `develop`); `.clang-tidy` + reviewdog on PRs (advisory) |
| **Format / docs** | `clang-format-diff-18` on changed hunks under `Envy/`, `TorrentEnvy/`, `HashLib/` (blocking); markdown link check when docs change |
| **Dependencies** | Dependabot (vcpkg, `Remote/tests` npm, GitHub Actions), dependency review, vcpkg manifest sanity |
| **AI review** | Copilot Code Review = target approval reviewer (skill `.github/skills/code-review/SKILL.md`); CodeRabbit/reviewdog/Qodo/Bugbot remain advisory |
| **Testing** | `EnvyTests.exe` after PR and `develop` MSBuild; Remote JS tests when `Remote/` changes; local `.\scripts\ci-verify.ps1` |
| **Security** | Gitleaks on every PR, CodeQL, dependency review |

## Related

- [Guide](guide.md) · [Build](build.md) · [Status](status.md) · [AI Coding Guide](ai-coding-guide.md)
- [GitHub Issues](https://github.com/Mika3578/Envy/issues) · [Discussions](https://github.com/Mika3578/Envy/discussions)
