# Envy DevSecOps map (cost-minimal, Windows-first)

**Last Updated:** 2026-09-18
**Repo:** [Mika3578/Envy](https://github.com/Mika3578/Envy) (not upstream GetEnvy/Envy)

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

BLOCK: Build x64 Release, Build Win32 Release, Lint build files, Vcpkg manifest sanity,
Format Check, Documentation Check, secret-scan, gitleaks, PR Gate, Analyze (c-cpp),
SonarCloud Code Analysis.

ADVISORY: CodeRabbit, clang-tidy + reviewdog, Snyk (when present), Cursor Bugbot
(optional / paid — not primary).

Never require CodeRabbit or Bugbot as the sole merge gate until a measured low
false-positive period and an explicit Fail-on-unresolved policy.

## Dependency automation

| Tool | Owns | Notes |
| --- | --- | --- |
| Dependabot | `vcpkg` baseline only | `.github/dependabot.yml` |
| Renovate | GitHub Actions only | `renovate.json5` (`enabledManagers: ["github-actions"]`), group non-major, pin digests, Dependency Dashboard; no blind automerge |


Install the **Renovate GitHub App** on Mika3578/Envy if suites appear queued but idle
(no Dependency Dashboard issue / no Renovate PRs). Until then Actions pins are
maintained manually / via PR #156-style SHA pinning.
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
2. **Renovate GitHub App** — If there is no Dependency Dashboard issue and no Renovate PRs, open
   GitHub → Settings → Applications → Installed GitHub Apps → **Renovate** → Configure → **Mika3578/Envy**
   (or install from [renovatebot.com](https://github.com/apps/renovate)).
   Config: `renovate.json5`. Suites may show `QUEUED` until the app processes the repo.
3. **Merge Queue** — **Optional** on personal accounts. Do not treat Merge Queue as required for an operational workflow. Continue with **squash auto-merge** + update-branch + strict required checks on `Protect develop`.
4. Labels: keep `renovate`, `vcpkg`, `major`, `dependencies`, `ci`.

## Agent PR back-pressure

Max **3** active development PRs (canonical rule in `AGENTS.md`). If at cap: repair CI,
handle CodeRabbit / reviewdog comments, resolve conflicts, ready-for-review,
squash auto-merge — **do not** open another PR. No “small/tooling” exceptions.
Dependabot/Renovate PRs are outside the agent cap but should stay grouped.

## Related

- [agents-and-automation.md](agents-and-automation.md)
- [AGENTS.md](../../AGENTS.md)
- Overnight local policy: `.cursor/rules/10-autonomous-overnight.mdc` (gitignored / local-only)
