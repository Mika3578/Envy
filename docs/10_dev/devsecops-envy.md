# Envy DevSecOps map (cost-minimal, Windows-first)

**Last Updated:** 2026-09-19
**Repo:** [Mika3578/Envy](https://github.com/Mika3578/Envy) (not upstream GetEnvy/Envy)
**Full measured CI audit:** [CI_AUDIT_2026-09.md](CI_AUDIT_2026-09.md)

## Principle

Deterministic tools **decide** mergeability. Probabilistic AI **advises**.
Humans retain authority on risky protocol/network/crypto changes.

```text
Cursor Agent → PR → CodeRabbit (advisory)
                  → reviewdog/clang-tidy (advisory)
                  → MSVC + EnvyTests + Format + PR Gate
                  → CodeQL + Sonar + gitleaks
                  → squash auto-merge (update branch + required checks)
                  → develop
```

Personal repositories may not support Merge Queue; **do not block** on enabling
it. Prefer strict required checks + update-branch + squash auto-merge.

## Local commands

| Command | Role |
| --- | --- |
| `.\scripts\ci-fast.ps1` | Pre-push: optional clang-format dry-run on changed C/C++ (warn if missing), conflict-marker scan |
| `.\scripts\ci-verify.ps1` | Local MSVC gate: ci-fast + Envy x64 Release + EnvyTests x64 + run tests |
| `.\scripts\ci-verify.ps1 -Full` | Also Envy/EnvyTests Win32 + run Win32 tests; **requires** clang-format on PATH |

These approximate GitHub gates; they do **not** replace CodeQL/Sonar/gitleaks/PR Gate.

## Merge blockers (develop ruleset)

BLOCK (required status checks): Build x64 Release, Build Win32 Release,
Lint build files, Vcpkg manifest sanity, Format Check, Documentation Check,
secret-scan, gitleaks, PR Gate, Analyze (c-cpp), SonarCloud Code Analysis.

SonarCloud Automatic Analysis exclusions for vendored trees:
`docs/10_dev/sonarcloud-exclusions.md` / `.sonarcloud.properties`. Do not
relax Quality Gate thresholds to pass.
(Docs-only PRs: Build x64/Win32 emit ubuntu success no-ops when classify
`run_windows_build=false` — never leave those required contexts SKIPPED.)

BLOCK (native GitHub review rules on Protect develop — not replaceable by PR Gate):

- **Intended:** ≥ **1** approving GitHub review (not the PR author; not a
  self-approve bot). **Live API 2026-09-19:** `required_approving_review_count: 0`
  — restore to 1 or update this doc after maintainer decision
  ([KNOWN_INCONSISTENCIES](../00_index/KNOWN_INCONSISTENCIES.md)).
- Dismiss stale reviews on new commits (**on**)
- Require approval of the most recent reviewable push (**off** — intentional)
- Resolve all review conversations / threads
- Signed commits; force pushes blocked (`non_fast_forward`)
- Code scanning merge protection: CodeQL + Gitleaks (current thresholds)
- Live ruleset also has a GitHub **Code Quality** rule at severity `notes`
  (docs previously said “none”; prefer SonarCloud + CodeQL + CI for blocking)
- No draft; squash only on `develop`; linear history; **no bypass actors**

ADVISORY: CodeRabbit, clang-tidy + reviewdog, Snyk (when present), Cursor Bugbot
(optional / paid — not primary).

Never require CodeRabbit or Bugbot as the sole merge gate. PR Gate only waits
on classified CI checks; it does **not** approve or merge.

## Dependency automation

| Tool | Owns | Notes |
| --- | --- | --- |
| Dependabot | `vcpkg` baseline only | `.github/dependabot.yml` |
| Renovate | GitHub Actions only | Root `renovate.json` (`enabledManagers: ["github-actions"]`), group non-major, pin digests, Dependency Dashboard; majors need dashboard approval; no blind automerge |

`Mika3578/Envy` is a **fork** of `GetEnvy/Envy`. Mend Renovate Community Cloud
skips forks by default when the GitHub App is installed on **All repositories**.
Official docs require a root file named exactly `renovate.json` (not
`renovate.json5` / `.github/renovate.json`) with `"forkProcessing": "enabled"`
for that pre-check — Renovate only probes the default onboarding filename via
the GitHub API before cloning. Prefer installing the app on **Selected
repositories** including this repo (that path enables fork processing without
relying on the pre-check alone). If the app is on **All repositories**, also
confirm the repo is not stuck in Mend **Silent** mode (`dryRun=lookup`) via the
[Mend Developer Portal](https://developer.mend.io/) job logs.

Do not re-enable `github-actions` under Dependabot (duplicate PRs).
Do not add `regex` to `enabledManagers` unless a real `customManagers` regex entry exists.

## AI review

| Tool | Role | Cost posture |
| --- | --- | --- |
| CodeRabbit | Default automatic PR review | Free for public OSS — install GitHub App |
| reviewdog + clang-tidy | Line annotations on PR diffs | Free Actions minutes |
| Qodo / PR-Agent | Manual on high-risk PRs only | Optional |
| Cursor Bugbot | Exceptional / paid | Not primary |

High-risk paths (extra bar before auto-merge): G1/G2, ED2K/Kad, BitTorrent, NMDC/ADC,
Network/NAT, packet parsing, crypto, threading/locking, serialization, Remote.
Require a regression/protocol test, explicit “no wire-format change”, or reference
comparison notes.

## Manual setup (cannot be completed from repo files alone)

1. **CodeRabbit GitHub App** — If reviews do not appear on ready (non-draft) PRs, open
   GitHub → Settings → Applications → Installed GitHub Apps → **CodeRabbit** → Configure → **Mika3578/Envy**.
   Config: `.coderabbit.yaml` (`drafts: false`, advisory only). Repos with fewer than 10 stars may require a manual `@coderabbitai review` / checkbox trigger.
2. **Renovate GitHub App** — Verify installation mode:
   GitHub → Settings → Applications → Installed GitHub Apps → **Renovate** → Configure.
   Expected: **Selected repositories** with `Mika3578/Envy` checked (best practice for a
   fork). If the app is on **All repositories**, root `renovate.json` must keep
   `"forkProcessing": "enabled"` and Silent mode must be disabled for this repo in the
   Mend portal. Success signal: Renovate check suites leave `queued`, a **Dependency
   Dashboard** issue appears, and (for non-major / approved majors) `renovate/*` branches
   or PRs. Config file: root `renovate.json` only — do not reintroduce `renovate.json5`.
3. **Merge Queue** — **Optional** on personal accounts. Do not treat Merge Queue as required for an operational workflow. Continue with **squash auto-merge** + update-branch + strict required checks + **≥1 GitHub APPROVED review** on `Protect develop`.
4. **Protect develop (live, verified)** — Source of truth is
   **Settings → Rules → Protect develop** (re-check via API before changing
   docs). Snapshot 2026-09-19 + intended knobs:
   - Required approvals: **intended 1** / **live API 0** (reconcile)
   - Dismiss stale pull request approvals when new commits are pushed: **on**
   - Require approval of the most recent reviewable push: **off**
   - Require conversation resolution before merging: **on**
   - Allowed merge methods: **squash** only
   - Signed commits: **on**; Block force pushes: **on**; Bypass list: **empty**
   - Code scanning: CodeQL + Gitleaks (do not tighten thresholds until
     C++/JS/C# analyses are deterministic on every PR)
   - GitHub Code Quality ruleset: live **notes**; blocking still via
     SonarCloud + CodeQL + CI
   - Automatically request Copilot code review: **off**
5. Labels: keep `renovate`, `vcpkg`, `major`, `dependencies`, `ci`.

## Agent PR back-pressure


Max **3** active development PRs (canonical rule in `AGENTS.md`). If at cap: repair CI,
handle CodeRabbit / reviewdog comments, resolve conflicts, ready-for-review,
squash auto-merge — **do not** open another PR. No “small/tooling” exceptions.
Dependabot/Renovate PRs are outside the agent cap but should stay grouped.

## Related

- [agents-and-automation.md](agents-and-automation.md)
- [AGENTS.md](../../AGENTS.md)
- Overnight local policy: `.cursor/rules/10-autonomous-overnight.mdc` (gitignored / local-only)
