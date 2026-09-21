# Post-merge Copilot review audit (2026-09-20)

Read-only audit of merged pull requests on `Mika3578/Envy`. This document
records the merge-race, not the individual historical findings.

## Counts

| Item | Count |
| --- | --- |
| Total pull requests | 233 |
| Closed | 231 |
| Merged | 185 |
| GraphQL review threads | 734 |
| Unresolved threads (all PRs) | 154 |
| Root findings created after `merged_at` | 46 |
| Merged PRs that received those 46 findings | 20 |

Examples of the race (findings arrived after merge):

- #292 — about 12 minutes after merge
- #293 — about 4 minutes after merge
- #294 — four findings about 18 minutes after merge

This PR does **not** fix those historical bugs (#294, #251, #256, #261,
#273, and similar). The next dedicated follow-up is
`fix/interop-review-followups` for the four post-merge findings on #294.

## Why thread resolution was not enough

Protect develop enforces `required_review_thread_resolution: true`
(`VERIFIED VIA API`). That rule only blocks conversations that already
exist when GitHub evaluates mergeability.

Copilot Code Review is asynchronous. The observed cycle is:

`push HEAD → request/start Copilot review → PR still mergeable → merge →
findings arrive later`

GitHub GraphQL has no PullRequest field meaning “Copilot review for SHA X
is in progress.” `VERIFIED VIA API`: Copilot-related schema on this
repository is ruleset `CopilotCodeReviewParameters` (`reviewOnPush`,
`reviewDraftPullRequests`) plus Copilot endpoint metadata. Completion is
observable after the fact from:

1. a `PullRequestReview` by `copilot-pull-request-reviewer` whose
   `commit.oid` equals the PR HEAD (`VERIFIED VIA API`);
2. the dynamic Actions check `copilot-pull-request-reviewer` on that HEAD
   (`VERIFIED VIA AVAILABLE GITHUB STATE`; workflow path
   `dynamic/agents/copilot-pull-request-reviewer`). In-progress means the
   review is still running. Success coincides with the submitted review.
   Cancelled (seen on #294 HEAD) means that SHA’s review job did not
   finish.

Do not infer completion from elapsed time, absence of comments, or a
sticky Copilot review *request* (Copilot often remains requested after it
has already reviewed).

## Mechanism retained

Two CI pieces (the Review Lifecycle Gate is not a Protect develop
required context in this change):

1. **Advisory pre-review** — Amazon Q, Sourcery, Cubic, Cursor Bugbot /
   Security / Approval, CodeRabbit. Live #299 HEAD signals: mostly
   skipped/rate-limited check-runs plus GitHub `COMMENTED` reviews that
   are not SHA-completion gates. None of these is required (Sourcery
   quota `skipped` would deadlock a required check).
2. **Final reviewer — Copilot Code Review**, requested only after
   required technical checks including **PR Gate** succeed
   (`workflow_run` of `PR Gate` on the default branch, plus
   `workflow_dispatch`). Do **not** enable
   `copilot_code_review.review_on_push` on Protect develop; that would
   run Copilot on every push before pre-review. Protect develop and
   Protect main still have **no** develop `copilot_code_review` rule
   (`VERIFIED VIA API` 2026-09-21). Protect main has the rule with
   `review_on_push: false`.

`Review Lifecycle Gate` (`REVIEW_GATE_ADVISORY=false`,
`require_copilot_approval=true`):

- Recalculates on pull_request, review, and review-comment events.
  Copilot finishing a HEAD review emits `pull_request_review`.
- SKIP draft PRs. Copilot and CodeRabbit do not review drafts.
- Recalculate on `review_requested` when Copilot is the requested
  reviewer, so a same-HEAD re-request goes pending instead of keeping a
  stale PASS.
- Do **not** fail this CI check on unresolved review threads. Protect
  develop already enforces `required_review_thread_resolution`, and
  Actions cannot subscribe to thread resolution.
- PASS only when Copilot submitted `APPROVED` on the current HEAD, that
  review is not `DISMISSED`, Copilot is not in-flight, there is no
  active `CHANGES_REQUESTED`, and required technical checks for that
  HEAD succeeded. Human or other-bot `APPROVED` is not enough.
  `COMMENTED` is never rewritten as `APPROVED`.
- Fail closed on missing data, API errors, truncated pagination, or a
  cancelled Copilot check without a HEAD-tied Copilot review.
- Pending/fail both fail the Actions job. Do not map pending to success.

The request helper `.github/workflows/request-copilot-review.yml` is
`workflow_run`/`workflow_dispatch` only (trusted default-branch
definition, no PR checkout, `cancel-in-progress: false`). It revalidates
live state and no-ops when Copilot is already requested, running, or has
already reviewed this HEAD unless `force_rerequest` is set.
`workflow_run` cannot self-host on #299 until this file is on `develop`;
bootstrap is a manual Copilot request after required checks are green.

## Live Copilot / ruleset notes (2026-09-20)

| Setting | Verification | Value |
| --- | --- | --- |
| Protect develop `copilot_code_review` | `VERIFIED VIA API` | absent |
| Protect main `copilot_code_review` | `VERIFIED VIA API` | present, `review_on_push: false`, `review_draft_pull_requests: false` |
| Ready develop PRs get Copilot reviews + HEAD check | `VERIFIED VIA AVAILABLE GITHUB STATE` | yes (#297 and others) |
| Draft PRs get Copilot reviews | `VERIFIED VIA AVAILABLE GITHUB STATE` | no (#298, #299) |
| Copilot can approve / count / effort / path allowlist | `NOT EXPOSED BY AVAILABLE API` | documented target only |
| `require_extra_approval_for_unattributed_changes` on develop | `VERIFIED VIA API` | false |

GitHub’s extra-approval knob applies when Copilot opens an *unattributed*
PR (own app identity). It does **not** implement repository policy that
Copilot cloud-agent PRs still need a non-Copilot reviewer. It was left
false.

## Remaining limits

- No native merge rule waits for Copilot completion of the current HEAD.
- Automatic Copilot review-on-push is **not** the intended cycle (other
  AI pre-review first, Copilot last). Do **not** add
  `copilot_code_review` with `review_on_push: true` on Protect develop.
- `Review Lifecycle Gate` is strict (`REVIEW_GATE_ADVISORY=false`) but
  must not be added to required checks until a maintainer confirms it on
  normal PRs. Until that check is required, a PR can still merge while
  Copilot has not `APPROVED` the current HEAD if a human/other approval
  satisfies Protect develop. This document must not call the race
  “closed.”
- `pull_request` events run the gate from the PR; the request helper
  stays on the default branch (`workflow_run`).
- Workflow runs whose triggering actor is Copilot
  (`pull_request_review` / review comments) can complete as
  `action_required` and never evaluate. Recalculation that must run
  without that approval uses `pull_request` (user/agent) or
  `workflow_dispatch`.
- Copilot approve/count/path-allowlist UI settings are
  `NOT EXPOSED BY AVAILABLE API` (**BLOCKER ADMIN SETTING** for native
  ruleset counting). The CI gate still requires a real Copilot
  `APPROVED` review and does not fake success.
