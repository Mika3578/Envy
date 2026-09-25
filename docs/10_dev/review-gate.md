# Review Gate — staged review/correction/final-approval loop

**Status:** advisory (not in the Protect develop ruleset yet). Promote to
required only after several green runs — see rollout below.

## Why this exists

PR #298 merged with a `cursor[bot]` APPROVED review while Copilot Code Review
only COMMENTED ("Needs a closer look", final human review required). The live
ruleset counts any non-author approval toward `required_approving_review_count`,
and PR Gate evaluated CI checks only — so nothing bound the merge to the
designated final reviewer. This gate closes that hole without weakening branch
protection, manufacturing approvals, or merging anything itself.

## Reviewer roles

**Stage A — advisory/cheap.** CodeRabbit, Cursor Bugbot, Amazon Q, Sourcery.
They find problems early. Their GitHub APPROVED state never authorizes merge;
clean means "no actionable/blocking findings per documented semantics".
`cursor[bot]` APPROVED is hard-ignored by the evaluator.

**Stage B — final.** GitHub Copilot Code Review only, requested at
`FINAL_CANDIDATE` (CI green, Stage A clean, threads acceptable). Balanced
effort for protocol/parser/network/security/memory/concurrency/CI-governance
paths. Its APPROVED on the exact HEAD is required; COMMENTED with findings,
"Needs a closer look", CHANGES_REQUESTED, missing, or pending all block.

**Low-risk path.** `docs/**`, `Languages/**`, `CHANGELOG.md`,
`MODERNIZATION.md`, adapters (`AGENTS.md` skill docs): Stage A + CI green
suffices, no Copilot final required.

## State machine (bound to PR HEAD SHA)

`DRAFT, VALIDATING, CHEAP_REVIEW, FIX_REQUIRED, REVALIDATING,
FINAL_CANDIDATE, COPILOT_PENDING, COPILOT_FIX_REQUIRED, COPILOT_APPROVED,
READY_TO_MERGE, HUMAN_REQUIRED`

Dedup key `(PR, HEAD SHA, reviewer, generation)`; one reviewer runs at most
once per HEAD. Obsolete generations cancel via the workflow concurrency group
and never count as success. `MAX_REVIEW_FIX_ITERATIONS=3` per PR (counted from
completed Review Gate runs); over budget or oscillating findings lead to
`HUMAN_REQUIRED` with reviewer, files, iterations, and last HEAD in the summary.

## Quota / anti-spam policy (free tier only)

Zero new spend: only free tiers plus repo-owned scripts on public-repo Actions
minutes. Reviewers must post useful comments only — quota/rate-limit/off-topic
messages are classified as noise by explicit patterns (tested, fail closed on
unknown output) and never trigger corrections. Quota exhaustion fails closed to
`HUMAN_REQUIRED` via the check status and step summary, never via PR comments.
Each Copilot review costs 13 premium requests, so Copilot runs once per
`FINAL_CANDIDATE`, never per cheap iteration.

## Files

- `.github/scripts/review-gate.sh` — deterministic read-only evaluator
  (reviews API + review threads with pagination; fails closed on malformed data).
- `.github/scripts/review-gate.selftest.sh` — 28 fixture-based cases,
  including the #298 regression and both happy/correction paths.
- `.github/workflows/review-gate.yml` — advisory `Review Gate` check.
- `.coderabbit.yaml` — `request_changes_workflow: true`, so CodeRabbit
  APPROVED implies fresh HEAD, resolved threads, and green pre-merge checks.

## Manual steps (outside the repo)

1. Repository Settings → Copilot → Code review: enable approvals and allow
   them to count toward merge requirements, paths blank.
2. External Cursor "Pull Request Router and Approver" → Router + Fixer:
   no APPROVED posts, no merges on Bugbot-clean. The gate protects Envy even
   before this change lands.
3. Ruleset: add the `Review Gate` context as required only after green
   advisory evidence. Never via PR.

## PR-Agent evaluation

[The-PR-Agent/pr-agent](https://github.com/The-PR-Agent/pr-agent) (MIT,
13k+ stars, active) is the chosen second cheap voice if needed: self-hosted
Action, BYOK free model route (Gemini primary, Groq fallback), reads
`AGENTS.md` by default, restricted-permissions mode. Not yet wired: needs a
maintainer-provided free-tier key (reserved secret name `PR_AGENT_LLM_KEY`)
and a pinned-SHA workflow in a follow-up. Rejected: Robin Review and
pr-review-bot (too young / third-party hosted, supply-chain risk), Qodo SaaS
and CodeRabbit Autofix (paid), Ouija runtime (external infra).
