---
name: envy-pr-workflow
description: Open, update, stabilize or finalize an Envy pull request toward develop. Use when creating a branch or PR, reacting to CI failures, merging develop into a branch, or preparing the Squash Commit Summary.
---

# Envy PR workflow

Rules come from root `AGENTS.md`; this skill is the procedure.

## Lifecycle

1. Branch from the latest `origin/develop` (`type/short-kebab-summary`).
2. Check open PRs and issues that touch the same files or topic. Extend the
   owning PR when one exists; do not open a competing implementation.
3. Make the smallest compatible change, with a regression test when fixing a
   bug. For many identical mechanical edits, use a throw-away script rather
   than hand-editing each file.
4. Run the cheap local checks that apply (see below), commit, push with
   `git push -u origin <branch>`, and open a **Draft** PR from
   `.github/pull_request_template.md`. Tick only checkboxes that apply.
5. Stabilize in Draft: deterministic CI runs on every push; batch related
   fixes into one push instead of pushing each one.
6. When the head is clean (checks green, threads treated, summary current),
   say so in one PR comment. The maintainer applies `stage:live-test`, runs
   the runtime test, marks Ready and squash-merges. Ready and live-test run
   x64 and Win32 Release with EnvyTests; any later push invalidates recorded
   runtime evidence.

Prefer finishing open PRs to opening new ones. There is no hard PR count, but
each new PR should be independent of the open ones.

## Cheap local checks

Run only those matching the changed paths:

- `bash .github/scripts/classify-changes.selftest.sh` (classifier edits)
- `python3 .github/scripts/check-agent-config.py` (agent instruction files)
- `BASE_SHA=$(git merge-base origin/develop HEAD) bash .github/scripts/check-source-encoding.sh`
- `python3 .github/scripts/check-agent-attribution.py --from <merge-base> --to HEAD`
- `bash .github/scripts/format-check.sh` when clang-format 18 is available
- `git diff --check`

Windows builds and EnvyTests run in CI. Never claim a Windows build passed
from a Draft deferral result.

## CI failures

- Wait on checks without sleeps: `gh pr checks <PR> --required --watch
  --fail-fast` (or the PR-activity events of your environment).
- Read the failing job log (`gh run view <RUN_ID> --log-failed`, or the
  provider page for SonarCloud) before changing code.
- Fix the root cause and push once per coherent batch. Re-run a job only when
  it died before running tests (checkout, install, runner loss).
- Escalate per `AGENTS.md` *Autonomy* when the same failure persists after two
  attempts with no new information, or when it is unrelated to the PR (then
  say which check, why, and whether a fix exists elsewhere).

## Merging develop into the branch

Merge (do not rebase) `origin/develop` when the branch is behind or
conflicted. Regenerate generated files with their tools, never by hand.

## Squash Commit Summary (manual squash merge)

`develop` uses `squash_merge_commit_title: PR_TITLE` and
`squash_merge_commit_message: BLANK`, so the maintainer pastes the PR's
**Squash Commit Summary** into the squash description. Keep it current:

- First line: `Fixes #n.` / `Closes #n.` when fully resolved, `Related to #n.`
  otherwise, or nothing.
- One to five bullets: root problem, resulting behavior, compatibility /
  security effects, regression coverage.
- Never: review-process text ("address review comments", "fix CI"), bot
  summaries, intermediate history, AI attribution, personal emails, template
  checkboxes, CI logs.
- PR title = squash title. Do not add `(#n)`; GitHub's preview shows it once.
- Do not enable auto-merge: it cannot fill the curated body.

## Documentation in the same PR

Update docs when behavior, APIs, protocol handling, UI/config, build/CI,
security or troubleshooting change. If no doc change is needed, say why in
the PR body.
