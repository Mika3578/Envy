# CI/CD audit — Envy (Mika3578/Envy) — 2026-09-19

**Scope:** GitHub Actions, required checks, Protect develop / Protect main
rulesets, dependency automation, local verify scripts.
**Method:** Live GitHub API + recent workflow runs (not chat history).
**Repo tip at audit:** `develop` @ `fc04d85` (after #214).

---

## 1. Executive summary

Envy’s PR CI is already a **two-speed** design (change-aware Windows builds,
CodeQL `build-mode: none` for C++/JavaScript on PRs, plus a manual
**Analyze (csharp)** SkinUpdater build, Debug on push to `main`/`develop` or
manual Debug `workflow_dispatch`). Typical **code PR** wall-clock to green is
**~7 minutes**, dominated by parallel **Build x64 Release** (~6.5–7 min) and
**Analyze (c-cpp)** (~6.5–7 min). Fast checks (Format, secret-scan, Vcpkg
sanity, Lint) finish in **15–45 seconds**.

Push-to-`develop` wall-clock is dominated by **CodeQL C++ with traced MSBuild**
(**~32–33 min**), not by the Build matrix (~8–10 min with four configs).

Strengths: SHA-pinned Actions, concurrency + cancel-in-progress on PRs,
composite `windows-msbuild`, classify-changes gating, gitleaks + CodeQL +
SonarCloud required, PR Gate stricter than GitHub skip semantics.

**Open gaps:**
- MSBuild `/m:1` is intentional (PCH C1083) and must not be “optimized”
  without a re-benchmark.
- Four identical classify jobs per PR (~8–10 s each) — centralizing is P3.
- Repository Copilot UI approve/count toggles, Balanced effort, and the
  optional Stage-3 path allowlist still need manual UI verification (not
  on the ruleset API). Automatic review is already live via Protect develop.

**Live Protect develop re-verification (2026-09-20):** required approvals **1**,
Code Quality severity **All**, Copilot `review_on_push` **on**, draft review
**off**, coverage restriction **off**. Older rows below that show approvals
**0** / Code Quality `notes` / `review_on_push: false` are the **2026-09-19
historical snapshot**, not current live state.

**Pre-change findings resolved in this PR:** empty NuGet restore (~22 s/job
no-op) skipped; Documentation Check always emits a terminal conclusion;
PR build logs upload on failure only. PR Gate keeps script-default
`POLL_SEC=15` (no 10 s override — API quota headroom).

---

## 2. Current architecture

```text
PR opened/updated
  ├─ Classify (×4 reusable calls: Build, Quality, Deps, PR Gate)
  ├─ Fast (ubuntu): Format Check, secret-scan, Vcpkg sanity, Lint build files,
  │                 Dependency review, Docs?, Remote JS?, labeler, clang-tidy PR
  ├─ Windows: Build x64 Release + Build Win32 Release (if classify)
  ├─ CodeQL: Analyze (c-cpp) ubuntu build-mode:none | (js) | (csharp) Windows
  ├─ External: SonarCloud, gitleaks app, Snyk (advisory)
  └─ PR Gate: poll until must_pass / may_skip set is terminal

Push develop/main
  ├─ Build: Release x64+Win32 + Debug x64+Win32
  ├─ CodeQL c-cpp: full traced MSBuild on windows-2025-vs2026 (~32 min)
  ├─ Code Quality Static Analysis (MSVC /analyze, continue-on-error)
  └─ Remote JS always
```

### Inventory table (measured 2026-09-19)

| Workflow/job | Trigger | Function | Depends | Duration (typ.) | Critical? | Required? | Redundancy | Runner cost |
| --- | --- | --- | ---: | ---: | --- | --- | --- | --- |
| Classify (×4) | PR via workflow_call | Path buckets | — | ~8–10 s each | No | No | Same script ×4 | Low (ubuntu) |
| Lint build files | PR/push Build | Toolset/self-tests | — | ~13 s | Yes (fast fail) | Yes | — | Low |
| Build x64 Release | PR if classify / push | MSVC + EnvyTests | Classify | **~6.5–7 min** | **Yes** | Yes | vs CodeQL push rebuild | **High** (Win) |
| Build Win32 Release | PR if classify / push | MSVC + EnvyTests | Classify | ~5–7 min | Parallel | Yes | — | High |
| Build Debug matrix | push `main`/`develop` + Debug `workflow_dispatch` | x64+Win32 Debug | Classify | ~5–8 min | No (PR) | Protect main requires Debug | — | High |
| Format Check | PR | clang-format-18 hunks | — | ~15 s | Fast feedback | Yes | Manual format-check.yml | Low |
| Documentation Check | PR (no-op when docs flag false) | README notice + link check | Classify | ~45–60 s when docs; seconds for no-op | Soft | Yes (ruleset) | link check `continue-on-error` | Low |
| Remote JS tests | PR if Remote / push | npm test | Classify | ~10 s | When Remote | PR Gate if classify | — | Low |
| secret-scan | PR/push/weekly | gitleaks binary + SARIF | — | ~20–25 s | Yes | Yes | + gitleaks app | Low |
| Vcpkg manifest sanity | PR | jq schema | — | ~7 s | Fast | Yes | — | Low |
| Dependency review | PR | GH dependency-review | — | ~10 s | Yes | PR Gate always | — | Low |
| Analyze (c-cpp) PR | PR | CodeQL no-build | — | **~6.5–7 min** | **Yes** | Yes | lighter than push | Med (ubuntu) |
| Analyze (c-cpp) push | push/schedule | Traced MSBuild + analyze | — | **~32–33 min** | Post-merge | ruleset/CS | Rebuilds vs Build job | **Very high** |
| Analyze (javascript-typescript) | PR/push | CodeQL | — | ~1 min | Parallel | PR Gate | — | Low |
| Analyze (csharp) | PR/push | SkinUpdater MSBuild | — | ~3–4 min | Parallel | PR Gate | Small surface | Med (Win) |
| PR Gate | PR | Wait classified checks | Classify | = critical path | Merge UX | Yes | Polls Actions | Low |
| Static Analysis | push/nightly | MSVC /analyze | — | ~8–9 min | Advisory | No | Soft fail | High |
| clang-tidy PR | PR paths | reviewdog | — | ~30 s | Advisory | No | — | Low |
| Release | tags | Installers/ZIP | — | long | Release | — | — | High |
| Stale / labeler | schedule/PR | Hygiene | — | seconds | No | No | — | Low |

**Protect develop required contexts (live ruleset `16457466`):**
Build x64 Release, Build Win32 Release, Lint build files, Vcpkg manifest sanity,
Format Check, Documentation Check, secret-scan, gitleaks (app `57789`),
PR Gate, Analyze (c-cpp), SonarCloud Code Analysis (`12526`).

**PR Gate additionally requires (not all ruleset-required):** Dependency
review, Analyze (javascript-typescript), Analyze (csharp); optionally builds /
Remote JS per classify.

---

## 3. Measurements (representative)

### PR #214 (code change, successful) — started 2026-09-19T10:01:31Z

| Signal | Value |
| --- | --- |
| First useful fail opportunity (Format / Lint / secrets) | **~15–25 s** |
| Wall to all required green (PR Gate) | **~7.0 min** |
| Build x64 Release job | 10:01:44 → 10:08:27 (~6.7 min) |
| Build Win32 Release job | 10:01:44 → 10:07:00 (~5.3 min) |
| Analyze (c-cpp) | 10:01:34 → 10:08:22 (~6.8 min) |
| Code Quality Format | ~14 s |
| Documentation Check | ~55 s |
| secret-scan | ~25 s |

**x64 Release composite breakdown (from job log):**

| Step | Approx. |
| --- | ---: |
| Checkout + setup-msbuild + VS verify | ~15 s |
| vcpkg cache restore | ~3 s |
| vcpkg install (registry fetch; pkgs cached) | **~43 s** |
| NuGet restore (“Nothing to do”) | **~22 s** |
| MSBuild solution (`/m:1`) | **~5.0 min** |
| EnvyTests | &lt;1 s |
| Upload logs | ~2 s |

### Push #201 to develop — started 2026-09-19T09:38:56Z

| Workflow | Wall |
| --- | ---: |
| Build (4 configs parallel) | ~7.7 min |
| Code Quality Static Analysis | ~8.7 min |
| CodeQL Advanced (traced C++) | **~31.8 min** |
| CodeQL C# | ~3.2 min |

### Aggregate (last ~100 workflow runs sampled)

| Workflow | Median wall | Notes |
| --- | ---: | --- |
| CodeQL Advanced | 6.8 min | P90 ~33 min (push traced builds) |
| Build | 6.5 min | PR Release pair / push matrix |
| PR Gate | 6.7 min | Tracks critical path |
| CodeQL C# | 3.2 min | |
| Code Quality | 1.1 min | Push static analysis inflates p90 |
| Security | 0.4 min | |

Cancelled runs appear when concurrency cancels superseded PR pushes (expected).

---

## 4. Critical path

### Pull requests (code touching C++ / build)

```text
Classify (~10s) ─┬─► Build x64 Release (~6.7m) ─┐
                 ├─► Build Win32 Release (~5.3m) │
                 └─► (parallel)                  ├─► PR Gate done @ ~7m
Analyze (c-cpp) (~6.8m) ─────────────────────────┘
```

**Critical path ≈ max(Build x64, Analyze c-cpp) ≈ 7 minutes.**

### Push to develop

```text
CodeQL c-cpp traced build (~21m) + analyze (~9m) ≈ 32m  ← dominates
Build matrix (~8m) and Static Analysis (~9m) finish earlier
```

---

## 5. Redundancies

| Item | Observation | Verdict |
| --- | --- | --- |
| Classify ×4 per PR | Independent reusable calls; ~40 s ubuntu total | Acceptable; centralizing is P3 |
| CodeQL push vs Build x64 | Second full MSBuild under CodeQL tracer | Intentional precision; keep |
| secret-scan job + gitleaks app | Both required | Complementary (SARIF upload vs app) |
| NuGet restore | `windows-msbuild` skips when no first-party packages.config; Static Analysis same skip and **fails** if restore errors (no `continue-on-error` on restore) | **Done this PR** |
| Build log artifacts on green PRs | Upload every success | **Failure-only on PR** (done this PR) |
| Format workflow_dispatch vs PR Format Check | Separate manual dry-run of first-party tracked C/C++ under Envy/, TorrentEnvy/, HashLib/ (not a full tree) | Keep |

---

## 6. Security (Actions)

| Control | Status |
| --- | --- |
| Default `permissions` least-privilege | Mostly yes; Build/Dep-review need `pull-requests: write` for comments |
| Action SHA pins | Yes (full commit SHA pins with version comments; Dependabot owns updates) |
| `pull_request_target` | `labeler.yml` only |
| Cache poisoning | vcpkg binary cache writable from PR jobs — GitHub restricts cache writes from forks; same-repo PRs share cache (accepted risk) |
| gitleaks binary | Version + SHA256 pinned in `security.yml` |
| Secrets in PR workflows | Uses `GITHUB_TOKEN` only for listed scopes |
| CodeQL / code scanning ruleset | Active (CodeQL + Gitleaks thresholds) |

No `permissions: write-all` found. Release workflow is higher privilege by nature — out of PR critical path.

---

## 7. Rigidity / merge gates

### Live Protect develop (`gh api .../rulesets/16457466`)

| Rule | Live value | Docs / AGENTS.md |
| --- | --- | --- |
| Required approvals | **0** | Claim ≥1 |
| Dismiss stale reviews | true | Match |
| `require_last_push_approval` | false | Match |
| Thread resolution | true | Match |
| Squash only | true | Match |
| Linear history | true | Match |
| Signed commits | true | Match |
| Force push / delete | blocked | Match |
| Bypass | never | Match |
| Required status checks | 11 contexts (see §2) | Match list |
| Code scanning | CodeQL + Gitleaks | Match |
| Code quality notes | severity notes | Docs say “no GQ rule” — **ruleset has `code_quality` notes** |

**Decision 2026-09-20 + live apply 2026-09-20:** the table above remains the
**2026-09-19 measured snapshot**. Current live Protect develop now enforces
**1 required approval**, Code Quality severity **All**, Copilot
`review_on_push` **off**, draft review **off**, and coverage restriction
**off**. Copilot may satisfy the approval only with a real `APPROVED` review
when repository Copilot approve/count settings are enabled (UI verification
still required).

### Live Protect main (`gh api .../rulesets/16457407`)

| Rule | Live value |
| --- | --- |
| Required approvals | **1** |
| Dismiss stale reviews | true |
| `require_last_push_approval` | false |
| Thread resolution | true |
| Squash only | true |
| Linear history | true |
| Force push / delete | blocked |
| Required status checks (strict) | Build x64/Win32 **Release**, Build x64/Win32 **Debug**, Code Quality, Security, Dependency review, CodeQL C# Manual Build |
| Copilot code review | enabled (`review_on_push: false`) |

Protect main is stricter on **Debug builds** and uses some **workflow-level**
check names (`Code Quality`, `Security`) that differ from Protect develop’s
per-job contexts. Operators validating `main` must run the Debug matrix
(push or Debug `workflow_dispatch`), not only Release.

### What should block a PR

| Tier | Checks |
| --- | --- |
| Blocking PR | Builds (when classify), Format, Lint, Vcpkg, secret-scan, gitleaks, CodeQL c-cpp (+ js/cs via Gate), Sonar, PR Gate |
| Informative PR | clang-tidy reviewdog, CodeRabbit, Snyk, markdown link check (`continue-on-error`) |
| Push / nightly | Debug builds, MSVC Static Analysis, traced CodeQL C++ |
| Weekly | Security schedule, CodeQL Sunday cron |
| Release | `release.yml` only |

---

## 8. Cost model (runner minutes)

Rough **per code PR** (Windows dominates):

| Job | Minutes (approx.) |
| --- | ---: |
| Build x64 + Win32 Release | 6.7 + 5.3 ≈ **12** |
| CodeQL C# Windows | ~3.5 |
| Ubuntu CodeQL c-cpp + js + misc | ~8–10 |
| **Total runner-minutes** | **~24–26** |

Per **push to develop** add Debug×2 (~12) + traced CodeQL (~32) + Static Analysis (~9)
≈ **+50+** Windows-heavy minutes.

Concurrency cancel-in-progress on PRs already cuts waste from force-pushes
(observed cancelled Build/CodeQL when PR updated).

---

## 9. External comparison (2026 practices)

Sources (primary first):

- [GitHub secure use](https://docs.github.com/en/actions/reference/security/secure-use) — least privilege, SHA pins
- [Concurrency](https://docs.github.com/en/actions/how-tos/write-workflows/choose-when-workflows-run/control-workflow-concurrency)
- [Dependency caching](https://docs.github.com/en/actions/reference/workflows-and-actions/dependency-caching)
- [MSVC MTT / parallelism](https://devblogs.microsoft.com/cppblog/improved-parallelism-in-msbuild/)
- [C++ build throughput](https://devblogs.microsoft.com/cppblog/cpp-build-throughput-investigation-and-tune-up/)
- [qBittorrent Windows CI](https://github.com/qbittorrent/qBittorrent/blob/master/.github/workflows/ci_windows.yaml) — concurrency cancel; Ninja/CMake; vcpkg
- [Bitcoin Core ci.yml](https://github.com/bitcoin/bitcoin/blob/master/.github/workflows/ci.yml) — cache restore/save split; ccache; concurrency

| Idea | Source | Gain | Cost | Risk | Maint. | Rec. |
| --- | --- | ---: | ---: | ---: | ---: | --- |
| Concurrency cancel PR | GH / qBT | High on busy PRs | Low | Low | Low | **Done** |
| SHA-pin Actions | GH secure use | Security | Low | Low | Dependabot | **Done** |
| Path-aware PR builds | Envy #116 | High | Med | Med | Med | **Done** |
| CodeQL none on PR | Envy #116 | ~25 min | Precision | Med | Low | **Keep** |
| Skip empty NuGet | This audit | ~22 s/job | Low | Low | Low | **Done** |
| Failure-only PR logs | This audit | Storage + ~2 s | Low | Low | Low | **Done** |
| Always emit Docs check | This audit | Unblock required skip | Low | Low | Low | **Done** |
| Faster PR Gate poll | This audit | ≤5 s wall vs 15 s default | Low | API quota if &lt;15 s | Low | **Keep 15 s** |
| `/m` + MTT | MSVC blogs | Potentially large | High | **C1083 PCH** | Med | **Do not** until A/B |
| sccache | LLVM/Bitcoin | Unknown on MSVC MFC | High | High | High | **P4** |
| Merge queue | GH | Serialization | Org limits | Med | Med | Optional (docs) |
| Shared classify once | Abstractions | ~30 s ubuntu | Coupling | Med | Med | **P3** |
| Pin vcpkg registry fetch | Bitcoin-style | ~40 s/job | Med | Med | Med | **P2** |

---

## 10. Prioritized proposals

### P0 — Correctness / unsafe merge posture

1. **Reconcile Protect develop ruleset:** **Done for ruleset knobs
   2026-09-20** — live now has 1 approval, Code Quality = All,
   review-on-push on, draft review off. Remaining: verify repository Copilot
   UI approve/count toggles, Balanced effort, and optional Stage-3 path
   allowlist (`docs/10_dev/devsecops-envy.md`).
2. **Documentation Check always reports** a terminal conclusion — **Done**
   (`if: always()` no-op path when classify says docs out of scope; cancelled
   classify from concurrency supersede also emits success no-op so a superseded
   run does not fail the required context).
2b. **Build x64/Win32 Release always report** on PRs — **Done** (same pattern:
   `if: always()`; ubuntu no-op when `run_windows_build=false`; real MSBuild on
   `windows-2025-vs2026` when true). Strict Protect develop treats SKIPPED
   required contexts as unsatisfied.

### P1 — Reliability / notable time

3. **Skip NuGet when no packages** — **Done this PR** (~22 s × Windows jobs).
4. Keep `/m:1` until a dedicated A/B proves no C1083 on `windows-2025-vs2026`.
5. Document traced CodeQL push cost; do not move it onto every PR.

### P2 — Measurable micro-optimizations

6. PR Gate keeps `POLL_SEC` at script default **15** (no yaml override). A
   10 s override was considered (≤5 s earlier detection vs default) but each
   poll hits both HEAD and merge SHAs; long concurrent Gate waits can stress
   Actions API quota — keep 15 unless rate-limit-aware backoff is added.
7. Upload build logs on PR **failure only**.
8. Investigate vcpkg “Fetching registry information from HEAD” (~40 s) with
   pinned baseline / downloads cache (Bitcoin pattern).

### P3 — Maintainability

9. Collapse classify to one workflow_call feeding multiple consumers (careful
   with reusable output wiring).
10. Align `.github/settings.yml` prose with live ruleset after human decision.

### P4 — Experimental

11. sccache / CL server mode / MTT with `CL_MPCount` cap — only with measured
    before/after on the same runner image.

---

## 11. Quantification (this change set)

| Change | Current (pre) | Expected | Measured on `0b81f15` | Feedback | Impact | Risk |
| --- | ---: | ---: | ---: | ---: | ---: | --- |
| Skip empty NuGet | ~22 s × 2 Release jobs | ~0 s | **Confirmed** skip &lt;1 s (log) | −~22 s on x64 path | ~−44 s runner time | Low |
| Failure-only log upload | ~2 s upload on green | 0 on green | No log artifact on green x64 | negligible | −artifact storage | Low |
| Docs check always emit | skip possible | always success/fail | **pass** (emitted) | stability | gate reliability | Low |
| PR Gate poll | script default **15 s** | keep 15 s | No 10 s override (API quota) | 0 vs default | no wall change | Low |
| **PR critical path** | #214 Gate **~7.0 min**; x64 **~6.7 min** | ~6.6–6.8 min | Gate **~5m53s–6m25s**; x64 **~5m17s–6m22s** (samples) | **~−35–70 s wall** (NuGet-dominated) | ~−1 min wall | Low |

One-sample confirmation only — treat multi-run medians as still pending. Variance across runners can exceed the NuGet saving.

**Not changed:** `/m:1` (PCH reliability), CodeQL PR/push split, required check
names, Win32 PR builds, Sonar/gitleaks requirements.

---

## 12. Local vs GitHub CI

| Layer | Local | GitHub |
| --- | --- | --- |
| `scripts/ci-fast.ps1` | Format warn + markers | — |
| `scripts/ci-verify.ps1` | x64 Release + tests (`/m`) | Build jobs use `/m:1` |
| `ci-verify.ps1 -Full` | + Win32 + clang-format required | Format Check = diff hunks |
| Missing locally | CodeQL, Sonar, gitleaks, PR Gate, Dependency review | Required |

**Drift note:** local verify uses `/m` while CI uses `/m:1` for PCH safety.
Documented; not unified in this PR (would either slow local or risk CI flakes).

---

## 13. Health notes

- Cancelled PR workflows: concurrency (healthy).
- PR Gate failures often accompany early Format/Quality failures or mid-update
  cancels — not evidence of Gate flakiness alone.
- Static Analysis `continue-on-error: true` — advisory by design.
- No systematic Win32-only flake identified in the sampled window.

---

## 14. Follow-ups (out of this PR)

- Manual GitHub Settings → Copilot → Code review only: confirm approve/count
  ON, effort **Balanced**, and optional Stage-3 path allowlist. Protect
  develop ruleset knobs (1 approval, Code Quality All, automatic Copilot
  review + review-on-push, draft review off) are already applied.
- P2: vcpkg registry fetch / downloads cache experiment.
- P3: single classify fan-out.
- P4: controlled `/m` + MTT A/B on a throwaway branch.
