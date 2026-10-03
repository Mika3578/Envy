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
                  → MSVC + EnvyTests + Format
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

These approximate GitHub gates; they do **not** replace CodeQL, Sonar, or
secret scanning.

## Merge blockers (develop ruleset)

Target required status checks: Build x64 Release, Build Win32 Release,
Lint build files, Vcpkg manifest sanity, Format Check, secret-scan,
Analyze (c-cpp), and SonarCloud Code Analysis. Documentation Check and the
duplicate gitleaks status remain visible as advisory checks; Protect develop
does not require them as status contexts.

SonarCloud Automatic Analysis exclusions for vendored trees:
`docs/10_dev/sonarcloud-exclusions.md` / `.sonarcloud.properties`. Do not
relax Quality Gate thresholds to pass.
(Docs-only PRs: Build x64/Win32 emit ubuntu success no-ops when classify
`run_windows_build=false` — never leave those required contexts SKIPPED.)

BLOCK (native GitHub review rules on Protect develop):

- **Live Protect develop (re-verified 2026-09-20):** ≥ **1** approving GitHub
  review from a reviewer other than the PR author. GitHub Copilot Code Review
  may satisfy the approval only when repository Copilot settings allow Copilot
  approvals to count and GitHub records an actual `APPROVED` review. Never
  manufacture approval with Actions/self-approval.
- Dismiss stale reviews on new commits (**on**)
- Require approval of the most recent reviewable push (**off** — intentional)
- Resolve all review conversations / threads
- Force pushes blocked (`non_fast_forward`); branch commits are not required
  to be signed by Protect develop.
- Code scanning merge protection: CodeQL + Gitleaks (current thresholds)
- GitHub **Code Quality** severity **All** (live). Code Quality complements —
  it does not replace — SonarCloud/CodeQL/MSVC/tests for the C++ core.
- Copilot ruleset target: `review_on_push` **off**, draft review **off**.
- No draft; squash only on `develop`; linear history; **no bypass actors**

ADVISORY: CodeRabbit, clang-tidy + reviewdog, Snyk (when present), Cursor Bugbot
(optional / paid — not primary).

Never require CodeRabbit or Bugbot as the sole merge gate. Native checks and
GitHub review rules are the merge authority.

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
| GitHub Copilot Code Review | Required approval reviewer when auto-approval/counting are enabled | Balanced review effort recommended |
| CodeRabbit | Advisory automatic/manual review | Free for public OSS — install GitHub App |
| reviewdog + clang-tidy | Advisory line annotations on PR diffs | Free Actions minutes |
| Qodo / PR-Agent | Manual on high-risk PRs only | Optional |
| Cursor Bugbot | Exceptional / paid | Not primary |

**Copilot request discipline** (see `AGENTS.md` §5 *Review and Copilot economy*):

- GitHub default: one review per PR unless ruleset **Review new pushes** is on
  ([Configure code review](https://docs.github.com/en/copilot/how-tos/copilot-on-github/set-up-copilot/configure-code-review)).
  Envy keeps review-on-push **off** on Protect develop.
- Auto-approval and **count toward merge requirements** must be enabled for a
  real `APPROVED` state; assessment-only output does not satisfy Protect develop
  ([Using Copilot code review](https://docs.github.com/en/copilot/how-tos/agents/copilot-code-review/using-copilot-code-review)).
- Agents: treat and **resolve** all threads, batch fixes, then **one** Copilot
  request per stable head — not per thread, not during Draft correction batches.
- OSS pattern: PR readiness checklist before any sponsored review (CI green,
  mergeable, test plan) — e.g. community `copilot-instructions.md` checklists.

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
3. **GitHub Copilot Code Review (safe AI approval)** — Repository
   Settings → Copilot → Code review (UI-only; not in the ruleset API):
   - Review effort: **Balanced**
   - **Allow Copilot to approve pull requests:** ON
   - **Allow Copilot approvals to count toward merge requirements:** ON
   - Path allowlist (≤15 globs; every changed file must match, or the
     approval does **not** count). Do **not** leave the allowlist blank:
     a blank list matches every path and would let Copilot’s `APPROVED`
     count on privileged governance changes (`AGENTS.md`,
     `.github/copilot-instructions.md`, `.github/skills/**`,
     `.github/settings.yml`, `.github/workflows/**`, `.github/rulesets/**`,
     and gate scripts under `.github/scripts/`). Those files are loaded
     from the PR head, so counted Copilot approval on them is a
     self-authorization loop. Prefer an ordinary-code allowlist such as:
     `Envy/**`, `HashLib/**`, `Plugins/**`, `TorrentEnvy/**`,
     `Unpacker/**`, `SkinBuilder/**`, `Remote/**`, `Services/**`,
     `tests/**`, `docs/**`, `Languages/**`, `Skins/**`, `Data/**`,
     `Installer/**`, `Visual Studio/**` (adjust within the 15-glob cap).
     Omit `AGENTS.md` and `.github/**` from the allowlist. PRs that touch
     privileged paths then need an independent human `APPROVED` even if
     Copilot comments. Skill
     `.github/skills/code-review/SKILL.md` also forbids Copilot
     `APPROVED` on those paths (defense in depth; UI allowlist is the
     independent control). Manual squash merge stays required.
   - Protect develop should request Copilot when the pull request is
     **mergeable** (required checks green, up to date, not draft); keep
     review-on-push and draft review **off**.
   Assessment ≠ approval. Copilot-authored PRs still need a human.
   A Copilot `APPROVED` review is not proof of correctness (business
   logic, production behavior, missed security, performance, or
   architecture). Independent checks (builds, EnvyTests when C++
   changes, CodeQL, SonarCloud, gitleaks, and secret-scan) stay
   required.

   **How merge proof works (GitHub, public preview since 2026-09-01):** By
   default Copilot leaves a **Comment** review, which does **not** satisfy
   Protect develop. With **both** Auto-approval toggles on (see above), Copilot
   can submit a real **`APPROVED`** review on the current head when it considers
   the pull request ready. The **approval assessment** in the overview comment
   is informational only and never counts. New commits dismiss Copilot’s
   approval like a human’s; re-request after mergeability returns. Official
   references:
   [Using Copilot code review](https://docs.github.com/en/copilot/how-tos/agents/copilot-code-review/using-copilot-code-review),
   [Configure code review](https://docs.github.com/en/copilot/how-tos/copilot-on-github/set-up-copilot/configure-code-review),
   [Changelog: Copilot can approve PRs](https://github.blog/changelog/2026-09-01-copilot-code-review-can-now-approve-pull-requests/).

   **Request review when mergeable** (review-on-push stays off):

   ```powershell
   gh pr edit <N> --repo Mika3578/Envy --add-reviewer copilot-pull-request-reviewer
   ```

   Copilot reads `.github/copilot-instructions.md` and
   `.github/skills/code-review/SKILL.md` from the **PR head** branch; those
   files require **`APPROVED`** when there are no blocking findings.

   **Verify approval counts before merge:**

   ```powershell
   gh pr view <N> --repo Mika3578/Envy --json mergeable,mergeStateStatus,reviewDecision
   gh api repos/Mika3578/Envy/pulls/<N>/reviews --jq ^
     "[.[] | select(.user.login==\"copilot-pull-request-reviewer\") | {state, commit_id, submitted_at}] | last"
   ```

   Expect `state: APPROVED` on the PR head commit, `reviewDecision: APPROVED`
   (or mergeable with approval satisfied), and merge blocked only by
   non-review gates if any remain. If you only see `COMMENTED` or an overview
   assessment, the UI toggles, org policy, or path allowlist still block
   counting — or auto-approval did not run; re-request on a mergeable head.

   **Org/enterprise:** If counting stays off, check organization Copilot policy
   (“Count Copilot approvals toward merge requirements”) is not **Disabled
   everywhere** for this repository.
4. **Merge Queue** — **Optional** on personal accounts. Do not treat Merge Queue as required for an operational workflow. Use **manual squash merge** (curated squash body; live `squash_merge_commit_message: BLANK`), update-branch, strict required checks, and **≥1 GitHub `APPROVED` review** on `Protect develop`. Do **not** enable squash auto-merge when a curated squash body is required (`AGENTS.md` rule 16).
5. **Protect develop (live, re-verified 2026-09-20)** — Source of truth is
   **Settings → Rules → Protect develop** (re-check via API before changing
   docs):
   - Required approvals: **1** (live)
   - Dismiss stale pull request approvals when new commits are pushed: **on**
   - Require approval of the most recent reviewable push: **off**
   - Require conversation resolution before merging: **on**
   - Additional approval for unattributed Copilot PRs: **off** for the
     solo-maintainer/agent workflow
   - Allowed merge methods: **squash** only
   - Require branches up to date before merging: **on**
   - Signed commits: **off for develop**; block force
     pushes: **on**; deletion blocked; bypass list: **empty**
   - Code scanning: CodeQL + Gitleaks with existing thresholds unless a
     separate measured change justifies tightening
   - GitHub Code Quality: severity **All** (live)
   - Restrict code coverage: **off for now** — do not enable until PR coverage
     data is uploaded reliably and a baseline has been measured
   - Copilot ruleset: review new pushes **off**; review drafts **off**
6. Labels: keep `renovate`, `vcpkg`, `major`, `dependencies`, `ci`.

## Agent PR back-pressure


Soft target of **5** active development PRs (canonical rule in `AGENTS.md`).
Prefer finishing or merging existing PRs first. Opening a sixth (or more)
needs a concrete documented reason in the PR body (blocking reliability or
security fix, required CI hotfix, or a dependency that cannot wait). Overflow
is not a loophole for unbounded parallel work, and “small/quick/tooling” is
not by itself a reason. Dependabot/Renovate PRs are outside the agent target
but should stay grouped.

## Related

- [agents-and-automation.md](agents-and-automation.md)
- [AGENTS.md](../../AGENTS.md)
- Overnight local policy: `.cursor/rules/10-autonomous-overnight.mdc` (gitignored / local-only)
