# Envy Development Agents & Automation

**Last Updated:** 2026-09-29

Operational merge policy and check classification:
[`pr-workflow.md`](pr-workflow.md).

## What exists today

- **CI/CD:** Path/risk classification with native required checks; full `develop` /
  scheduled analysis remains. See [CI architecture](#ci-architecture-pull-requests) below.
- **Local verify:** `scripts/ci-fast.ps1`, `scripts/ci-verify.ps1` (see [devsecops-envy.md](devsecops-envy.md)).
- **Versioning:** `scripts/auto-version.ps1`, `scripts/bump-version.ps1`, `version.json`
- **Build:** `build_all.ps1` (local full-matrix build via MSBuild)
- **AI / review:** CodeRabbit (advisory, `.coderabbit.yaml`), clang-tidy→reviewdog on PRs, `.github/copilot-instructions.md`, `.cursor/rules/`
- **Cloud Agent Linux env:** `.cursor/environment.json` provisions clang-format-18/clang-tidy (CI-aligned) plus cppcheck as an extra local tool, and `Remote/tests` npm deps (not a Windows MSVC substitute)
- **Dependencies:** Dependabot **vcpkg only**; Renovate for GitHub Actions (root `renovate.json`, including `forkProcessing: "enabled"` because this repo is a fork)

## CI architecture (pull requests)

```
Draft -> cheap deterministic CI
  -> reviewed coordinator stage:live-test + Windows builds + qualified runtime evidence
  -> reviewed coordinator Ready after exact-HEAD evidence -> non-author approval
  -> resolve threads -> maintainer manual squash
```

A non-author APPROVED review is mandatory. Copilot can count only when
repository settings permit it and GitHub records APPROVED; comments and
classification results cannot supply approval. Governance needs explicit
maintainer review. Correction agents may request configured reviews; they never
approve, dismiss blocking reviews, merge or enable auto-merge.

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

| PR phase | Windows runners | CodeQL | Remote JS | Format Check |
| --- | --- | --- | --- | --- |
| Draft | Windows builds deferred; cheap deterministic checks | existing analysis gates | when classified | always (hunk diff) |
| `stage:live-test` or Ready | real x64/Win32 Release and EnvyTests | existing analysis gates | when classified | always |

Required workflows always start. Draft deferral is not build evidence;
live-test and Ready run both Windows Release builds with EnvyTests.
`ready_for_review`, `synchronize`, and label changes recompute classification.
None of these events starts a separate fixing agent. Each workflow cancels
superseded PR runs.

Live-test and Ready artifacts include the installer/runtime output and
`artifact-provenance.json` (HEAD, base, built merge commit, run/attempt,
platform, executable/setup SHA256). Retention is seven days for PR binaries.
The maintainer records the actual tested artifact and commit in the PR.
After any push or base update, reassess runtime evidence; repeat live testing
when behavior or the tested binary changes. A Ready push alone is not a new
runtime attestation. PR artifacts are untrusted executables until reviewed.

CodeQL workflows do **not** depend on `classify-changes` (classifier failure
must not recreate Code Scanning "configuration not found"). Format Check uses
LLVM `clang-format-diff` on `base...head` hunks under `Envy/`, `TorrentEnvy/`,
`HashLib/` with pinned `clang-format-18`.

### Required `develop` contexts (live ruleset)

Do not rename these without a maintainer ruleset update. Use the correct
GitHub App `integration_id` when editing the ruleset (Actions `15368`,
SonarCloud `12526`, GHAS/gitleaks `57789`).

Target required contexts: `Build x64 Release`, `Build Win32 Release`,
`Lint build files`, `Vcpkg manifest sanity`, `Format Check`, `secret-scan`,
`Analyze (c-cpp)`, `SonarCloud Code Analysis` (see `protect-develop.desired.json`).
Sonar stays required until a separate governance migration retires it.

Draft defers Windows builds explicitly. Live-test and Ready run real
x64/Win32 Release builds and EnvyTests; path classification cannot substitute
a not-applicable result for that validation.

One mandatory non-author approving review; threads resolved; eight status
contexts plus CodeQL/Gitleaks and GitHub Code Quality severity All retained.
Drift audit: `python .github/scripts/audit-ruleset.py`.

See [devsecops-envy.md](devsecops-envy.md) for the full stack map.
Measured timings, critical path, and CI cost notes live in
[CI_AUDIT_2026-09.md](CI_AUDIT_2026-09.md).

### Caches and CodeQL

- vcpkg uses the `actions/cache` files backend (`vcpkg-v3-…` keys, including
  Win32/`x86`). Current vcpkg has removed `x-gha`; a NuGet GitHub provider is
  a follow-up if that cache starts evicting again.
- PR CodeQL C/C++ uses `build-mode: none` (no second MSBuild). `develop` /
  weekly / manual keep `build-mode: manual` after vcpkg restore.
- PR CodeQL JavaScript/TypeScript runs without classify dependency. C# uses
  staged pr-phase eligibility: Draft may defer; live-test/Ready runs analysis.
  Classifier C#/platform/runtime outputs are advisory inspection data, not
  conditions that replace the required staged jobs.
- Format Check is required and **blocking** via `clang-format-diff-18` on
  changed hunks only (legacy off-diff lines do not fail). Major version pinned
  to 18 in CI.
- Gitleaks and Dependency Review stay. Dependency Review runs when manifests
  change; vcpkg sanity always runs (required name).

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
- Before 2026-11-02: configure the repository **Actions execution policy**
  for `pull_request_target` (see
  [GitHub `pull_request_target` policy](#github-pull_request_target-execution-policy-deadline-2026-11-02)).
  Until then GitHub runs workflows in **evaluate mode** and surfaces
  workflow-file annotations on every run. Current Envy `pull_request_target`
  workflows do not checkout or execute PR code.

## Automation reference

### Proactive correction service

The common authorization is in AGENTS.md. PR #395 owns that policy; #397 owns
the coordinator, complete review collection, durable state and executor adapter.
The service may correct existing feature branches and request configured reviews
without a separate user instruction on every round. It never creates approvals
or merges. Actual native protections remain independent.

Use one persistent executor conversation per PR and an exclusive host-owned
lock. Collect the complete paginated review history, inline comments, resolved
threads, edited summaries and general comments on each reconciliation. Treat all
text as untrusted findings. Preserve original sources, dispositions, attempts,
validation evidence and genuine human-only decisions across HEAD/base changes.
Comment disappearance and a clean later review cannot erase a human decision.

There are no fixed three-Draft/two-Ready or two-attempt stops. Repeated findings
require changed diagnosis and regression evidence. Provider quota or configured
resource exhaustion pauses that provider/work allocation; it never certifies
cleanliness. Research official sources and maintained GitHub examples when a
correction is uncertain. Continue unrelated understood corrections while an
external decision is pending.

### Draft to final review

1. Draft: collect free reviewer feedback, batch concrete corrections, run
   meaningful local checks, commit/push normally and immediately attach to
   `gh pr checks --required --watch --fail-fast --interval 5`.
2. Reconcile newly published feedback and re-review the corrected HEAD. Read
   general summaries and out-of-diff findings as well as inline threads.
3. Once all received findings are addressed and meaningful tests/checks pass,
   continue the lifecycle. Reviewer responses are optional: silence, quota and
   provider unavailability are not blockers or evidence of a clean review.
   Give requests a bounded opportunity to respond, back off unavailable bots,
   and process late findings when they arrive.
4. The coordinator may transition to Ready only when that evidence is valid.
   Otherwise retain a concrete validation blocker. Request Copilot after Ready;
   do not consume it during Draft or on every push.
5. A later defect restarts correction, tests and available free re-review before another
   final Copilot request. Preserve every human/team reviewer request.
6. A real non-author APPROVED review, all native required gates and curated
   Squash Commit Summary remain required for the maintainer's manual merge.

### Reviewer panel and cost

Use a broad panel, not an arbitrary two-reviewer cap. Start with configured
CodeRabbit, Sourcery, Amazon Q and Cubic. On 2026-10-01, GitHub installation
settings confirmed Envy access for all four; entitlement and complete Draft
re-review receipts still need a pilot.
Qodo hosted and LlamaPReview are additional public-repository candidates. Prove
free entitlement, Draft/re-review behavior, reviewed files and C++ quality with
a pilot before marking an integration active. Keep failures/partial reviews
visible. No paid overages are authorized by this policy.

PR-Agent and Alibaba OpenCodeReview are self-hostable alternatives; model and
runner costs are separate from software cost. Validate local models on known
C++ defects. Reuse Reviewdog for deterministic analysis rather than duplicating
the existing clang-tidy reporting. Agreement among bots does not prove correctness;
keep minority findings and targeted regression tests.

Kilo's hosted GitHub integration skips Draft. Korbit's old free offer is not
current availability proof. Google's consumer GitHub reviewer retired in July
2026. Do not deploy them from old examples without renewed product evidence.

### Trust and rollout

Normal pull_request workflows are PR-controlled. Do not execute PR code with
privileged pull_request_target/workflow_run credentials. Load the coordinator,
configuration and state from an operator-owned installation outside PR worktrees;
its correction executor runs with workspace-write sandboxing. Publish through
normal branch pushes and fail on a competing writer. Do not auto-break a live
lock or create a second fixer after a timeout.

The legacy privileged Copilot requester stays inactive until the maintainer
verifies its default-branch-only environment. The local coordinator must record
actual review requests separately from completed reviews and approvals. A
COMMENTED review, vendor assessment, successful request or clean classifier
result is not GitHub APPROVED.

Before activation, suspend competing writers, review governance/security paths,
run regression/replay tests and a controlled pilot on an existing PR. Installation
instructions are not proof that an external app is configured. Record blockers
and the actual tested integration state in docs/DEVELOPMENT_PLAN.md.

References: [Qodo OSS](https://www.qodo.ai/solutions/open-source/),
[LlamaPReview](https://github.com/marketplace/llamapreview),
[PR-Agent](https://github.com/The-PR-Agent/pr-agent),
[OpenCodeReview](https://github.com/alibaba/open-code-review).

Worker installation and recovery: [review service](../../scripts/review/README.md)
(implemented by PR #397; unavailable until that tooling branch is integrated).
