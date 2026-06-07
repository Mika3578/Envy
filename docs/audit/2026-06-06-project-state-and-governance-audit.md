# Project State & Governance Audit — 2026-06-06

> Scope: end-to-end audit of repository state, open pull requests, CI/CD,
> governance rules, the development plan, dependency posture, and documentation
> hygiene. Includes a comparison against peer P2P projects and a prioritized,
> PR-sized action plan.
>
> Method: read of the working tree on `develop` (plus a local feature branch),
> the 14 GitHub Actions workflows, `.github/settings.yml`, the governance docs
> (`AGENTS.md`, `CLAUDE.md`, `MODERNIZATION.md`, `docs/DEVELOPMENT_PLAN.md`,
> `docs/DEV_TRACKER.md`), and the live state of PRs #48 and #51 and their CI
> check runs.

---

## 0. TL;DR

The modernization is in much better shape than the top-level governance files
admit. The single most important fact the trackers do not yet state plainly:

- **The v145 build is GREEN.** PR #51 produced passing `Build x64 Release`,
  `Build x64 Debug`, `Build Win32 Release` and `Build Win32 Debug` jobs on the
  `windows-2025-vs2026` runner. Phase 1 ("first green build") is effectively
  achieved, but `MODERNIZATION.md`, root `DEV_TRACKER.md` and the dashboard in
  `docs/DEV_TRACKER.md` still describe it as pending.

The two things holding the project back are **not** code; they are
**governance drift** and **documentation/CI sprawl**:

1. The canonical rule files (`AGENTS.md`, `CLAUDE.md`, `MODERNIZATION.md`) point
   at a branch and base (`claude/code-audit-modernization-nJcTT` → `main`) and
   forbid artifacts (`CMakeLists.txt`) that the live repository has already
   moved past. AI assistants and humans reading the "single source of truth"
   are being told the wrong thing.
2. There are **3 development trackers, 3 roadmaps, 3 contributing guides, 5
   modernization-plan documents, duplicated root vs `docs/audit/` audit files,
   and an exact-duplicate PR template.** The team has *started* consolidating
   (some files are now "moved"/"superseded" stubs) but stopped halfway.
3. CI has **14 workflows with real duplication** (format check ×2, dependency
   review ×3), a **required-status-check list in `settings.yml` whose contexts
   match no existing job**, and a version-bump workflow that **pushes directly
   to a protected branch**.

None of these are hard to fix. The rest of this document is the evidence and a
sequenced plan.

---

## 1. Current state snapshot

| Item | State (2026-06-06) | Source |
|---|---|---|
| Default branch | `develop` (linear history enforced) | `.github/settings.yml:27`, `docs/DEVELOPMENT_PLAN.md:22` |
| Build status | **Green** on x64+Win32 / Debug+Release, v145 | PR #51 check runs |
| Runner | `windows-2025-vs2026` (VS 2026 / MSVC 14.5x) | `.github/workflows/build.yml:43` |
| Toolset | v145 enforced; no `v141_xp`/`_ATL_XP_TARGETING` left | `build.yml:285` lint job |
| C++ standard | C++20 first-party, C++17 plugins (per rules) — but `docs/10_dev/status.md` claims a C++17 baseline | `AGENTS.md:24`, `docs/10_dev/status.md:4` |
| Version | **Inconsistent**: `vcpkg.json` = 5.0.0, `version.json` = 4.1.0.53, `docs/10_dev/dev-tracker.md` = 4.1.0.54 | see §6 |
| Open PRs | 2 (#48 CI/docs, #51 Dependabot vcpkg) | GitHub |
| Open issues | 0 | GitHub |
| vcpkg deps | zlib, bzip2, sqlite3, miniupnpc, openssl | `vcpkg.json` |
| vcpkg cutover | Declared but **incomplete** — `Services/` vendored libs still present | §7 |

---

## 2. Open pull requests — keep / rebase / redo

### PR #51 — `deps(vcpkg): bump vcpkg-baseline group` (Dependabot)

- Base `develop`. **All checks green**, including the full Windows build matrix.
- Bumps `builtin-baseline` `56bb2411…` → `db64a3af…` (vcpkg 2026.05.25).
- **Verdict: MERGE.** It is the canonical proof the build is green and it is
  exactly the Dependabot flow the plan wants exercised. No redo needed.
  (Note: auto-merge is gated to "actions minor/patch only"; vcpkg baseline
  bumps require a human approval by design — `MODERNIZATION.md:391`.)

### PR #48 — `CI: add PR Quick Checks workflow and split Full CI pipeline`

- Base `develop`. Author Mika3578. Open since 2026-05-21, last touched
  2026-06-01. Mixes **two concerns**: (a) a CI split (fast PR checks vs full
  matrix) and (b) governance docs (`.github/CONTRIBUTING.md`,
  `.github/settings.yml`, `docs/CONTRIBUTING.md`, `docs/DEVELOPMENT_PLAN.md`,
  `docs/PR_PLAYBOOK.md`).
- CI on the PR: `SonarCloud Code Analysis` **failed** (2026-05-27 run); the rest
  passed. The full build matrix did **not** run on the PR — which is the PR's
  own intent (it moves builds out of the PR path), so the PR cannot demonstrate
  that the split keeps builds working.
- It is **partially stale**: several of its doc changes (linear-history
  workflow, settings alignment) have **already landed on `develop`** via commit
  `7ea8b46` ("docs: document linear history workflow"). Re-validate for conflicts.
- **Verdict: REDO as two scoped PRs, do not merge as-is.**
  1. *Docs PR*: rebase on `develop`, drop whatever already merged, keep only the
     net-new governance content. Small, low-risk.
  2. *CI PR*: this is the right idea (see §5) but it must be reconciled with the
     duplication this audit found (it should *delete* `code-quality.yml`'s
     duplicated jobs, not add a parallel pipeline beside them) and must keep the
     build reachable as a required gate. Splitting concerns also lets the
     failing SonarCloud check be addressed in isolation.

---

## 3. Governance & rules drift (highest-leverage fixes)

The repository declares `AGENTS.md` the "single source of truth" and routes
`CLAUDE.md`, `.cursorrules`, `.clinerules`, etc. to delegate to it. That
contract is currently broken:

| Rule file says | Reality | Fix |
|---|---|---|
| Develop on `claude/code-audit-modernization-nJcTT`; base `main`; "do not push to `main`, `develop`, or `legacy`" (`AGENTS.md:30`) | Default branch is `develop`; work flows through `develop` + ephemeral `claude/*` branches; PRs target `develop` | Rewrite the branch-model paragraph to describe the `develop` linear-history model |
| "Don't introduce `CMakeLists.txt` files yet … CMake migration is not in scope" (`AGENTS.md:174`) | Root `CMakeLists.txt` exists; `README.md` documents a CMake build; `docs/DEVELOPMENT_PLAN.md` lists CMake migration as a roadmap item | Replace with the real policy: "VS solution is authoritative; CMake is partial (HashLib + tests)" |
| `MODERNIZATION.md` target branch `…nJcTT`, base `main`, "10 workflows" | 14 workflows; base `develop` | Either fold `MODERNIZATION.md` into `docs/DEVELOPMENT_PLAN.md` or mark it historical |
| `CLAUDE.md` → read root `DEV_TRACKER.md` | Root `DEV_TRACKER.md` is stale (2026-05-17, PR #35 shown "in progress" though merged as `f223a62`); README + plan name `docs/DEV_TRACKER.md` canonical | Point `CLAUDE.md` at `docs/DEV_TRACKER.md`; retire the root one to a stub |

**Why this matters:** every AI assistant configured for this repo (Copilot,
Claude, Cursor, Cline, Aider, Windsurf, Continue) reads these files first. Drift
here multiplies into every automated change.

---

## 4. Documentation sprawl

The repo has real, high-quality content, but the same topic lives in several
places with no enforced canonical. The team's own
`docs/00_index/KNOWN_INCONSISTENCIES.md` acknowledges part of this.

| Topic | Copies | Canonical (recommended) |
|---|---|---|
| Dev tracker | `DEV_TRACKER.md` (root, stale), `docs/DEV_TRACKER.md`, `docs/10_dev/dev-tracker.md` (already a "superseded" stub) | `docs/DEV_TRACKER.md` |
| Roadmap | `.github/ROADMAP.md` (stale: dated 2024-11-05, "Q4 2024"), `docs/ROADMAP.md` (redirect stub), `docs/10_dev/roadmap.md` | `docs/10_dev/roadmap.md` |
| Contributing | `.github/CONTRIBUTING.md`, `docs/CONTRIBUTING.md`, `docs/10_dev/contributing.md` | `.github/CONTRIBUTING.md` (GitHub-native location) + thin links |
| Modernization plan | `MODERNIZATION.md`, `docs/DEVELOPMENT_PLAN.md`, `docs/00_index/MASTER_PLAN.md`, `.github/UPGRADE_SUMMARY.md` (Nov 2024), `docs/10_dev/modernization-summary.md` | `docs/DEVELOPMENT_PLAN.md` |
| Audit reports | root `CODE_QUALITY_AUDIT.md` + `SECURITY_AUDIT.md` **differ from** `docs/audit/` copies | `docs/audit/` (per decision 2026-04-22) |
| Modern C++ guide | `.github/MODERN_CPP_GUIDE.md`, `docs/10_dev/modern-cpp-guide.md` | `docs/10_dev/modern-cpp-guide.md` |
| Doc index | `docs/00_index/README.md` + `README_old.md` | drop `_old` |
| PR template | `.github/pull_request_template.md` **==** `.github/PULL_REQUEST_TEMPLATE.md` (byte-identical) | keep one (`.github/PULL_REQUEST_TEMPLATE.md`) |

**Note on process:** `PR_PLAYBOOK.md` and `AGENTS.md` both forbid silently
deleting docs. So consolidation must be done as an explicit, reviewed PR that
replaces duplicates with redirect stubs (the pattern already used by
`docs/STATUS.md`, `docs/ROADMAP.md`, `docs/10_dev/dev-tracker.md`) rather than
hard deletions, and updates every inbound link.

---

## 5. CI/CD audit

14 workflows: `build`, `clang-tidy`, `code-quality`, `codeql`, `codeql-csharp`,
`copilot-setup-steps`, `dependabot-auto-merge`, `dependency-review`,
`format-check`, `labeler`, `release`, `security`, `stale`, `version-management`.

### 5.1 Duplication

- **Format check ×2:** `format-check.yml` and `code-quality.yml`'s `lint-check`
  job both run `clang-format --dry-run`.
- **Dependency review ×3:** `dependency-review.yml`, `code-quality.yml`'s
  `dependency-check` job ("Dependency Review"), and the check named "Dependency
  review" all appear on PRs. `security.yml:17` even comments "Dependency review
  is handled by code-quality.yml" — stale guidance.
- `code-quality.yml`'s heavy `static-analysis` job runs
  `choco install visualstudio2026buildtools` **on every run** and then builds
  the whole solution with `RunCodeAnalysis=true`. The `build.yml` matrix already
  has a working VS 2026 runner; this re-installs the toolchain redundantly.
- `code-quality.yml` triggers on `master` (`code-quality.yml:5-7`), a branch
  that does not exist.

The genuinely-unique jobs hiding inside `code-quality.yml` are
**Static Analysis** (MSVC `/analyze`), **Documentation Check** (markdown link
check), and **Remote JS Security Tests** (the Remote web-UI regression suite,
which `docs/DEVELOPMENT_PLAN.md:50` lists as a deliberate gate). If
`code-quality.yml` is deleted, those three must be re-homed first — this is what
PR #48 should be doing.

### 5.2 Required status checks do not match real jobs

`.github/settings.yml:203-207` requires these contexts on `develop`:

```
- "Build and Test (Win32)"
- "Build and Test (x64)"
- "CodeQL Security Scan"
```

None of these strings is an actual job name. The real names are
`Build x64 Release` / `Build x64 Debug` / `Build Win32 Release` /
`Build Win32 Debug` (`build.yml:39`), `CodeQL` and `Analyze (csharp)`. If this
file is (or becomes) the source of branch protection via the Probot Settings
app, **every PR would block forever** waiting on checks that never report.
`docs/DEVELOPMENT_PLAN.md:28` already hedges that CI is not yet a mandatory gate
— consistent with this being unresolved. Fix: align the contexts to the real
job names before promoting any check to "required".

### 5.3 `version-management.yml` pushes to a protected branch

`version-management.yml:84-119` runs `git commit`/`git push` and
`git push origin <tag>` directly. With the `Protect develop` ruleset (linear
history, PR required, no direct pushes — `docs/DEVELOPMENT_PLAN.md:27`), a direct
push to `develop` will be rejected. Either run it on a release branch and open a
PR, or grant a bypass actor explicitly and document it.

### 5.4 Docs-only PRs run the full Windows matrix

`build.yml` has `paths-ignore: ["**.md", …]` on **push** but not on
**pull_request** (`build.yml:14-15`). A documentation-only PR to `develop` still
spins up four serialized Windows builds. This is the waste PR #48's "PR Quick
Checks" split is meant to remove; pair it with a `pull_request` path filter.

### 5.5 SonarCloud is an out-of-repo check, currently failing

`SonarCloud Code Analysis` appears on PRs #48 and on `develop` but there is **no
Sonar configuration in the repo** (no workflow, no `sonar-project.properties`).
It runs via the SonarCloud GitHub App (automatic analysis). It is **failing** on
`develop` (2026-05-27). Decide: either commit a `sonar-project.properties` +
workflow so it is reviewable and reproducible, or remove the App if SonarCloud
overlaps too much with CodeQL + clang-tidy. Do not leave a failing, invisible
gate.

### 5.6 What is good (keep)

- Strict v145 verification step that fails fast on runner regressions
  (`build.yml:72-111`).
- PCH C1083 mitigation via serialized build (`build.yml:57-59`).
- vcpkg binary cache keyed on manifest hash (`build.yml:113-120`).
- gitleaks pinned by version **and SHA-256** (`security.yml:30-41`) — textbook
  supply-chain hygiene.
- Automatic build-failure triage comment on PRs (`build.yml:190-270`).
- Concurrency cancellation on PRs (`build.yml:29-31`).

---

## 6. Versioning inconsistency

Three sources disagree:

- `vcpkg.json:version-string` = **5.0.0**
- `version.json` = **4.1.0** / display **4.1.0.53**, `lastTag` `v4.1.0`
- `docs/10_dev/dev-tracker.md` header = **4.1.0.54**

Pick one source of truth (recommend `version.json`, since
`version-management.yml` already drives it) and make `vcpkg.json` track it (or
drop the version from `vcpkg.json`, which is optional for a top-level manifest).

---

## 7. Dependency / vcpkg posture

- `vcpkg.json` declares zlib, bzip2, sqlite3, miniupnpc, openssl with a real
  `builtin-baseline` (good — the placeholder era is over). `openssl` is new
  vs the original plan.
- **Cutover is incomplete:** the vendored trees under `Services/{zlib, Bzlib,
  SQLite, MiniUPnP, …}` still exist, so it is not yet proven that the build
  links the vcpkg builds rather than the in-tree copies. Phase 3 in both
  `MODERNIZATION.md` and `docs/DEVELOPMENT_PLAN.md` is still open.
- Not yet declared: **`libmaxminddb`** (GeoIP replacement) and a **`libutp`**
  decision — both are named in the plan.
- `MODERNIZATION.md`'s audit calls out CVEs in the *old vendored* bzip2 1.0.5
  and zlib 1.2.10; finishing the cutover is the remediation, so this is a
  security item, not just hygiene.

---

## 8. Security posture

Strong foundation, a few gaps:

- **Present & good:** CodeQL (cpp + dedicated csharp), `dependency-review`,
  gitleaks secret scan (SHA-pinned), `.gitleaks.toml`, `.cppcheck-suppressions`,
  `.clang-tidy`, `SECURITY.md`, and protocol-parser hardening already shipped
  (ED2K Source Exchange bounds checks, Kad publish bounded copy — see CHANGELOG).
- **Gaps:**
  - No fuzzing of the protocol parsers. P2P clients ingest hostile bytes by
    design; this is the single highest-value security investment (see §9).
  - `_CRT_SECURE_NO_WARNINGS` is still repo-wide (Phase 2 item) — masks unsafe
    CRT calls in new code despite the rule against relying on it.
  - The failing/invisible SonarCloud gate (§5.5).
  - No SBOM artifact on release (planned, Phase 3).

---

## 9. Comparison with peer P2P projects

Findings below are from each project's actual repository files (workflow YAML,
CONTRIBUTING, configs) fetched 2026-06-06, with URLs. Two tiers: strong models
to copy, and same-domain peers that mostly validate *where the gap is*.

### 9.1 Strong models to copy

**qBittorrent** (`qbittorrent/qBittorrent`) — the closest toolchain match: a
desktop C++ GUI client that ships a **signed Windows installer** built with
**MSVC + vcpkg**, exactly Envy's target.
- One workflow **per platform** (`ci_windows.yaml`, `ci_ubuntu.yaml`, …) — each
  fast and independently restartable.
- Windows: `windows-latest` + MSVC + **Ninja** + vcpkg with a custom static
  triplet and **GHA binary caching** `--binarysource="clear;x-gha,readwrite"`;
  produces an **NSIS installer** artifact; matrix over 3 libtorrent versions.
- Ubuntu: **ccache**, hardening flags `-D_FORTIFY_SOURCE=3
  -D_GLIBCXX_ASSERTIONS -Werror`, tests via a `check` target.
- Governance: **rebase, not merge**; atomic commits; `Closes #N.`;
  `CODING_GUIDELINES.md` mandates **uncrustify** and precise commit rules
  (50-char imperative subject, no trailing period, 72-char body). Issue
  templates are GitHub forms.
- Dependencies: vcpkg pinned by triplet/baseline; **Dependabot watches
  `github-actions` + `pre-commit` only — it deliberately does NOT auto-bump
  vcpkg ports.** (Contrast with Envy, which *does* auto-track the vcpkg baseline
  via PR #51 with human review — a defensible but opposite choice; see §9.3.)
- Security: `SECURITY.md` directs to **GitHub private vulnerability reporting**;
  supports latest stable only.
- Release: **GPG-signed** tarballs and binaries since v3.3.4.
- Sources: <https://github.com/qbittorrent/qBittorrent/tree/master/.github/workflows>,
  `/blob/master/CODING_GUIDELINES.md`, `/blob/master/.pre-commit-config.yaml`,
  `/security/policy`.

**Transmission** (`transmission/transmission`) — the **CI-efficiency** gold
standard for a large build matrix.
- A single `actions.yml` with a **`what-to-make` change-detection job**: it
  diffs against the merge base over path groups and emits `*-changed` flags, so
  GUI/macOS/**docs** jobs only run when their files changed — **docs-only edits
  skip the build entirely.** This is the principled version of what Envy needs
  in §5.4 and what PR #48 gestures at.
- `concurrency: cancel-in-progress`; **two-phase clang-tidy** (core lib, then UI
  in a matrix) so tidy cost is split; **clang-format** `code-style` job uploading
  a `style.diff` on failure; **ASan/UBSan/TSan** via a reusable composite
  action; **CTest + GoogleTest**; Windows **MSI via vcpkg**; separate
  `codeql.yml` (C++ + JS, push/PR/weekly).
- **Changelog automation:** every PR adds a `Notes: …` line that a release
  script harvests — far cheaper than hand-maintaining changelog prose.
- CONTRIBUTING mandates C++ Core Guidelines, `constexpr`/`enum class`,
  **dependency injection for testability**, and "fix warnings in new code."
- Sources: <https://github.com/transmission/transmission/blob/main/.github/workflows/actions.yml>,
  `/blob/main/CONTRIBUTING.md`.

**libtorrent** (`arvidn/libtorrent`) — the **protocol-hardening** benchmark, the
exact problem class Envy faces (untrusted G2/ED2K/Kad/BT bytes).
- **CIFuzz on every PR** (`cifuzz.yml`, `fuzz-seconds: 300`, uploads crash
  artifacts) and **continuous OSS-Fuzz** (libFuzzer + AFL + honggfuzz).
- Matrix over **C++14/17/20**, Clang + **clang-tidy-18**, **ASan+UBSan** and
  **TSan** cells, tests run with `warnings-as-errors=on invariant-checks=full`.
- **`libsimulator`**: a discrete-event sim implementing the `boost.asio` API on a
  single deterministic timeline, so DHT/swarm/ip-filter tests are
  **deterministic instead of flaky**. The single most transferable testing idea
  for a P2P stack.
- Sources: <https://github.com/arvidn/libtorrent/tree/RC_2_0/.github/workflows>,
  <https://github.com/google/oss-fuzz/tree/master/projects/libtorrent>,
  <https://github.com/arvidn/libsimulator>.

### 9.2 Same-domain peers (validate the gap, not the target)

- **aMule** (`amule-project/amule`) — closest functional cousin. `ccpp.yml`
  builds ubuntu/macos/windows (MSYS2/MinGW), **CMake+Ninja**, Debug+Release,
  **runs CTest**; `codeql.yml` is modern and **deliberately runs on push +
  weekly cron, not PRs** ("a merged PR is just a push — the push trigger already
  covers it"), an explicit minutes-saving rationale worth copying. Source:
  <https://github.com/amule-project/amule/tree/master/.github/workflows>.
- **eMule** (community fork `irwir/eMule`) — VS2019→VS2022, libs split into
  separate repos, "consistent formatting" refactors, **but no GHA CI**. This is
  essentially "where Envy is"; it validates the gap, not the target.
- **EiskaltDC++** — CMake, multi-platform, but README still cites **Travis /
  Sibuserv** rather than a modern GHA matrix.
- **DC++** — still on **Launchpad + Bazaar**; **Shareaza** (ancestor) — on
  **SourceForge SVN**, VS2008-era solution. These are the baseline Envy is
  escaping.
- **Deluge** (Python) — uses a **`develop` working branch (GitFlow), PRs only,
  pre-commit, and SHA256 checksums** on release tarballs. Notably, Envy's own
  `develop`-default + linear-history model already matches this; it is a
  reasonable, peer-validated choice.

### 9.3 Cross-project pattern table

| Practice | qBittorrent | Transmission | libtorrent | aMule | **Envy today** |
|---|---|---|---|---|---|
| Per-platform / path-filtered jobs | ✔ | **✔ change-detection** | ✔ | partial | ✖ (4-way matrix on every PR) |
| vcpkg + binary cache | ✔ x-gha | ✔ | ✔ | MSYS2 | ✔ files cache (no x-gha) |
| clang-format / tidy gate | uncrustify | **✔ 2-phase** | tidy | – | advisory only |
| Sanitizers (ASan/UBSan/TSan) | partial | **✔** | **✔** | – | ✖ |
| CodeQL | partial | ✔ | ✔ | ✔ | ✔ (cpp+csharp) |
| Fuzzing (CIFuzz/OSS-Fuzz) | – | – | **✔** | – | ✖ |
| Deterministic protocol/sim tests | – | DI+gtest | **libsimulator** | CTest | ✖ (prose in status.md) |
| SECURITY.md + private reporting | **✔** | ✔ | OSS-Fuzz | – | partial |
| Changelog discipline | tags | **✔ PR `Notes:`** | notes | docs/Changelog | manual (3 trackers) |
| Signed releases | **GPG** | macOS | – | distro | ✖ (Azure signing planned) |

**Durable takeaways for Envy:** (1) copy qBittorrent's **MSVC+vcpkg+x-gha
binary cache** Windows job and **pin** the baseline you choose to track; (2) copy
transmission's **change-detection / path-filtered** matrix and **`Notes:`
changelog automation**; (3) the highest-ROI security/robustness investment is
libtorrent-style **parser fuzzing (CIFuzz → OSS-Fuzz)** plus a
**libsimulator-style deterministic transport seam**. Adopting even the P0+P1
items below would place Envy ahead of every same-domain peer except aMule, and
approaching the qBittorrent/Transmission/libtorrent tier.

---

## 10. Prioritized action plan

Each item is intended to be **one small, reviewable PR** (per `PR_PLAYBOOK.md`).

### P0 — correctness & "stop the bleeding" (this week)

1. **Reconcile the rule files with reality.** Update `AGENTS.md`, `CLAUDE.md`,
   `MODERNIZATION.md` for the `develop` branch model and the real CMake policy;
   repoint `CLAUDE.md` at `docs/DEV_TRACKER.md`. (Docs-only, zero build risk.)
2. **Fix `settings.yml` required-check contexts** to match real job names; keep
   them advisory until consistently green, then promote. (§5.2)
3. **Merge PR #51** (green Dependabot vcpkg bump) and let it stand as the
   "build is green" record. Then refresh the trackers to say so. (§0, §2)
4. **De-conflict PR #48**: rebase on `develop`, split into a docs PR and a CI PR.

### P1 — CI consolidation & version sanity (next)

5. **Collapse CI duplication.** Delete `code-quality.yml` *after* moving its
   unique jobs (Static Analysis, Documentation Check, Remote JS Security Tests)
   into dedicated workflows or the new "Full CI"; remove the duplicate format /
   dependency-review jobs; drop the `master` trigger. (§5.1)
6. **Add a `pull_request` path filter to `build.yml`** so docs-only PRs skip the
   Windows matrix; introduce the fast PR lane. (§5.4) *Peer model:* transmission's
   `what-to-make` change-detection job; add qBittorrent's vcpkg **x-gha** binary
   cache (`--binarysource="clear;x-gha,readwrite"`) to keep the full build fast.
7. **Fix version drift** — single source in `version.json`; make `vcpkg.json`
   match or drop its version. (§6)
8. **Fix `version-management.yml`** to not push to a protected branch (open a PR
   or use a release branch + bypass actor). (§5.3)
9. **Resolve SonarCloud**: commit config + workflow, or remove the App. (§5.5)

### P2 — documentation consolidation & robustness (sequenced)

10. **Doc consolidation PR** (reviewed, redirect-stub pattern, no hard deletes):
    one canonical per topic from §4; dedupe the PR template; remove
    `README_old.md`; reconcile root vs `docs/audit/` audit copies.
11. **Finish the vcpkg cutover** (Phase 3): prove the build links vcpkg libs,
    then retire vendored `Services/` trees lib-by-lib; add `libmaxminddb`;
    decide `libutp`. Security-relevant (§7).
12. **Stand up protocol fuzzing** for the packet parsers (G2/ED2K/Kad/BT),
    seeded from the existing bounded-parse functions; wire into CI as advisory
    first. (§9) *Peer model:* libtorrent's `cifuzz.yml` (`fuzz-seconds: 300` on
    every PR) is a copy-ready template; graduate to OSS-Fuzz once stable.
    Highest-ROI security investment for an untrusted-input parser.
13. **Automate interop fixtures** from the eMule/aMule comparisons currently
    described in `docs/10_dev/status.md`. (§9) *Peer model:* libtorrent's
    `libsimulator` (deterministic transport) + transmission's
    dependency-injection-for-testability; introduce a thin socket seam so core
    tests run without real network flakiness.
14. **Phase 2 hardening** as already planned: `/permissive-`, `/sdl`,
    `/guard:cf`, Spectre, and retiring repo-wide `_CRT_SECURE_NO_WARNINGS`.

---

## 11. Appendix — what was verified

- Git: on a local feature branch, with `origin/develop` at `7ea8b46`.
- PR #51 check runs: full Windows matrix **success**; SonarCloud **success**.
- PR #48 check runs: SonarCloud **failure**; builds not run (by design).
- Workflows read in full: `build.yml`, `code-quality.yml`, `security.yml`,
  `version-management.yml`; inventory of all 14 confirmed on disk.
- `settings.yml` required contexts cross-checked against live job names.
- Duplicate-doc inventory confirmed by filesystem listing; PR templates verified
  byte-identical; root vs `docs/audit/` audit files verified to **differ**.
- `vcpkg.json` / `version.json` / `docs/10_dev/dev-tracker.md` versions compared.
