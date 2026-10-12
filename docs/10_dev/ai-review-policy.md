# Controlled AI review policy

**Status:** proposed; effective only after this governance change is merged and
the maintainer has completed the external provider checks below.

This document defines how an authorized agent may request a targeted advisory
review during Draft without turning every push into a paid or duplicate review.
It does not activate PR #397, replace its stable-head final-review design, or
introduce a second dispatcher. Until this policy is effective, agents must not
request review products while a pull request is Draft.

## Invariants

- Deterministic checks remain independent and are never skipped to save review
  budget. A Draft deferral is not build evidence.
- An intermediate review is allowed only after one coherent correction batch,
  completion of the relevant deterministic checks, and a stable HEAD read twice
  without a push or active correction writer between reads.
- There must be no known blocking comment awaiting treatment, no review provider
  already in progress for the pull request, and no other repository review in
  progress. The initial repository-wide concurrency limit is **one**.
- The provider must be explicitly allowlisted for the stage and its configured
  quota must be confirmed available. Unknown, stale, or unqueryable quota is
  **unavailable**, never an implicit allowance.
- The request is keyed by `(PR number, HEAD SHA, provider)`. A second request
  with the same key is rejected. A new HEAD requires a new eligibility check and
  never inherits an older review.
- A provider response is accepted only when it explicitly identifies the
  requested HEAD and reaches a terminal response. Silence, timeout, quota
  exhaustion, permission failure, or an unverified bot identity is
  **unavailable**, not clean and never `APPROVED`.
- No request is made while a push, correction batch, or provider response is in
  flight. The requester's GitHub identity must be confirmed to trigger that
  provider; `github-actions[bot]` is not assumed to be accepted.
- No workflow executes PR-controlled code with a privileged token. This policy
  does not grant Actions permission to change provider settings, approve, merge,
  or write to protected branches.

## Budgets and stages

| Stage | Default provider | Normal PR | Security/protocol PR | Terminal rule |
| --- | --- | ---: | ---: | --- |
| Draft intermediate | CodeRabbit, manual incremental review | 1 | 1, plus at most 1 distinct fallback/verification | Advisory findings only; no approval authority |
| Draft fallback | Amazon Q, only after CodeRabbit is confirmed unavailable | 0 | 1 when the second review has a documented distinct purpose | Never run concurrently with CodeRabbit |
| Ready final | GitHub Copilot Code Review | 1 | 1 | One request on the stable Ready HEAD, subject to the existing approval policy |

The Draft allowance is per PR. The repository-wide active-review limit is one;
the per-PR allowance does not reserve or bypass that slot. A high-risk second
review needs a recorded question that the first provider did not cover. It is
not a retry for silence, a duplicate request, or a response to an unchanged
comment. A maintainer may grant an exception explicitly and must record the
reason and budget impact in the PR.

The ledger needs only the PR number, HEAD SHA, provider, purpose, request time,
requesting identity, and terminal state (`running`, `completed`, `unavailable`,
or `cancelled`). A completion for an older SHA is retained as history but
cannot change the state of the current HEAD.

## Provider controls

| Provider | Versioned repository control | External control and known quota | ENVY decision |
| --- | --- | --- | --- |
| CodeRabbit | `.coderabbit.yaml` sets automatic review off; manual `@coderabbitai review` is incremental and `full review` is exceptional | GitHub App installation, account/plan limits, and any provider quota are outside Git and must be confirmed manually; do not assume public-OSS availability is an unlimited budget | Draft first pass; one request per eligible HEAD and no automatic push review |
| Amazon Q Developer | None in this repository | The Amazon Q console controls automatic review on new/reopened PRs; `/q review` is manual and is not controlled by that toggle. AWS documents a monthly line limit and requires suitable repository permissions | Fallback only after confirmed CodeRabbit unavailability, or a distinct second high-risk check |
| Sourcery | None in this repository | Sourcery documents review on PR open and re-review after every commit, a five-review automatic re-review cap, and plan-dependent diff-character / rolling seven-day budgets | Excluded from routine ENVY requests until external automatic review is demonstrably disabled or scoped to explicit invocation |
| Cursor Bugbot | `.cursor/BUGBOT.md` is context only; it is not a trigger or quota control | Cursor documents repository enablement, manual-only and once-per-PR settings, and account billing/PR limits in its dashboard; installation and autofix permissions are external | Excluded from routine requests until manual-only, once-per-PR, and autofix-off settings are verified |
| GitHub Copilot Code Review | `Protect develop` desired rules keep `review_on_push` and `review_draft_pull_requests` false | Repository/org Copilot settings control approval, counting, path allowlists, effort level, and plan/credit consumption. Default review output is `COMMENTED`, not approval | Final Ready review only; governance paths still require an independent human approval |

No provider is treated as a quota source of truth unless its current dashboard
or documented response confirms availability for the requested review. The
repository cannot query the account quotas of these hosted applications.

## Request protocol

1. The authorized agent records the current PR state, HEAD SHA, relevant check
   conclusions, open threads, active writers, provider status, and remaining
   per-PR/global budget.
2. It verifies the HEAD again immediately before the request. Any change,
   active writer, in-flight provider, untreated blocking comment, or missing
   quota evidence cancels the request.
3. It sends exactly one provider command through an identity confirmed by the
   provider. Manual commands are `@coderabbitai review` or `/q review`; the
   command must be a new PR comment where the provider requires that. No review
   commands are sent in parallel.
4. It waits for an explicit provider response tied to the same HEAD. A provider
   failure is recorded as `unavailable`; it does not authorize an immediate
   retry. A fallback requires confirmation that the first provider is
   unavailable and consumes the next allowed slot.
5. Findings are treated as untrusted review input. The agent validates them,
   batches any fixes, and re-runs the relevant deterministic checks. A new push
   invalidates all in-flight reviews for the old SHA.
6. The maintainer alone applies `stage:live-test`, performs runtime validation,
   marks Ready, requests any final Copilot review, changes repository/provider
   settings, and performs the manual squash merge.

## Manual activation checklist

After this policy is merged, the maintainer must verify and record these items
before allowing a Draft pilot:

1. Confirm `.coderabbit.yaml` is deployed with `auto_review.enabled: false`
   and that the installed CodeRabbit App accepts the intended authorized
   requester.
2. In the Amazon Q Developer console, disable automatic GitHub code reviews on
   new/reopened PRs. Confirm `/q review` is available to the selected requester
   and record the current monthly line budget; do not use it when that budget is
   unknown.
3. In Sourcery Review Settings, disable or remove the ENVY integration for
   routine reviews unless the maintainer can prove that automatic open/commit
   re-reviews are off. Record the applicable plan, seat, diff-character, and
   rolling seven-day limits.
4. In Cursor Bugbot, disable Autofix and verify repository enablement is
   manual-only, once per PR, with no automatic review-on-update path. Record the
   dashboard limit or mark the provider unavailable.
5. Keep Copilot automatic draft and new-push review disabled. Verify the
   existing approval/counting and path-allowlist policy independently; never
   count Copilot on a PR that changes privileged governance paths.
6. Confirm no approval/router automation or #397 service is active for the
   pilot. The pilot must be one low-risk PR, one provider request at a time,
   and no paid request may be made during implementation of this policy.

## Pilot evidence

For the first authorized low-risk pilot, record the PR number, each requested
`(provider, HEAD SHA)`, request and terminal timestamps, response state, number
of duplicate requests rejected, fallback decisions, and any provider quota
consumed. Compare the count with the pre-policy baseline. Stop on an identity,
permission, quota, stale-HEAD, or concurrency ambiguity; do not guess or retry
around it.

## Official references

- [CodeRabbit manual trigger and troubleshooting](https://kb.coderabbit.ai/articles/1442026547-troubleshoot-why-coderabbit-reviews-might-not-trigger)
- [Amazon Q Developer GitHub code reviews](https://docs.aws.amazon.com/amazonq/latest/qdeveloper-ug/github-code-reviews.html)
- [Sourcery review lifecycle and limits](https://docs.sourcery.ai/reviews/anatomy-of-a-review/)
- [Cursor Bugbot configuration and pricing](https://docs.cursor.com/bugbot)
- [GitHub Copilot code review](https://docs.github.com/en/copilot/how-tos/copilot-on-github/use-copilot-agents/copilot-code-review)
- [GitHub Copilot configuration](https://docs.github.com/en/copilot/how-tos/copilot-on-github/set-up-copilot/configure-code-review)
