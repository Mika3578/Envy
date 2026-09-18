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
                  → Merge Queue (when enabled) / squash auto-merge
                  → develop
```

## Local commands

| Command | Role |
| --- | --- |
| `.\scripts\ci-fast.ps1` | Pre-push: optional clang-format dry-run on changed C/C++, conflict-marker scan |
| `.\scripts\ci-verify.ps1` | Local MSVC gate: fast + Envy x64 Release + EnvyTests x64 |
| `.\scripts\ci-verify.ps1 -Full` | Also Envy Win32 Release |

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
| Renovate | GitHub Actions (+ future custom/regex) | `renovate.json`, group non-major, pin digests, Dependency Dashboard |

Install the **Renovate GitHub App** on Mika3578/Envy if suites appear queued but idle.
Do not re-enable `github-actions` under Dependabot (duplicate PRs).

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

## Agent PR back-pressure

Max **3** active agent development PRs. If at cap: repair CI, handle CodeRabbit /
reviewdog comments, resolve conflicts, merge — **do not** open another PR.
Dependabot/Renovate PRs are outside the agent cap but should stay grouped.

## Related

- [agents-and-automation.md](agents-and-automation.md)
- [AGENTS.md](../../AGENTS.md)
- Overnight local policy: `.cursor/rules/10-autonomous-overnight.mdc` (gitignored / local-only)
