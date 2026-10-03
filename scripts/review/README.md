# Trusted correction service

This worker reconciles one existing Envy PR per invocation. It collects all
review bodies and paginated inline/general comments, including resolved and
outside-diff findings. A persistent executor conversation produces corrections
and individual dispositions. The host validates, commits with the configured
human noreply identity, pushes normally, watches required CI and publishes
evidence. It never approves or merges.

Routine GitHub mutations use GitHub MCP when practical. If MCP needs an
interactive Cursor confirmation that is unavailable, authenticated `gh` OAuth
is the supported fallback (`gh pr edit`, `gh api`, `gh api graphql`,
`gh pr checks`). Do not use `gh` to bypass rulesets, required reviews, or
maintainer-only Ready/merge transitions. Copilot is requested at most once per
stable HEAD (`union=true`). The Actions commit status `Final review gate` is
advisory until a maintainer adds it to Protect develop; auto-merge stays off.

## Installation and activation

1. Review the worker, configuration and validation commands. Copy this directory
   to an operator-owned location outside every managed PR worktree. Do not run
   privileged publication from a PR-controlled checkout or GitHub workflow.
2. Copy `config.example.json` into that host installation. Configure actual
   existing worktrees, meaningful checks and proven reviewer identities. Keep
   configuration, SQLite state, logs and GitHub credentials inaccessible to the
   sandboxed executor. A path outside the checkout alone is not an ACL boundary;
   verify the executor sandbox on the host before enabling publication.
3. Authenticate `gh`, configure the real contributor's GitHub noreply identity
   and `user.useConfigOnly=true`, and retain normal hooks/signing. Install the
   supported Codex CLI and Python 3.11+. Corrections use the operator's Codex
   allocation; free reviewer entitlement does not make executor compute free.
4. Disable competing correction writers and approval automation. Inspect the
   live required checks and run the offline tests below. Keep activation flags
   false until the host configuration and governance changes have been reviewed.
5. Run observation against GitHub before a controlled correction pilot:

   ```powershell
   python C:/trusted-review/service.py --config C:/trusted-review/config.json --observe
   ```

6. After that review, set `activation_reviewed` and
   `competing_writers_disabled` to true in the host-owned configuration. Set
   `host_isolation_verified` only after testing the operator's absolute-path
   `executor_launcher` and `validation_launcher`. Both must deny access to host
   credentials, configuration/state, trusted code and publication Git metadata,
   and deny credential-bearing network access. Neither launcher inherits host
   secret/profile variables. Supply an isolated executor profile explicitly.
   Configure `trusted_hooks_path` as an absolute, frozen reviewed installation
   outside PR worktrees; its dependencies must also be host-owned. Normal hooks
   and signing still run. Publication refuses an unconfigured isolation boundary. Supply
   `trusted_policy_path` as an absolute host copy of `AGENTS.md` outside PR
   worktrees; the executor treats any worktree `AGENTS.md` as untrusted data.
   Invoke
   the same command without `--observe` to execute one reconciliation. Use an
   operator-owned scheduler for recurring invocations; `register-task.ps1`
   provides an observation-first Windows adapter. Scheduler intervals reconcile
   new events; CI always uses `gh pr checks --required --watch` immediately.

The scheduler must run a frozen reviewed copy, not follow the changing PR copy.
The native OS lock covers collection, correction, publication and CI watching.
A second invocation cannot become another writer. No fixed correction-attempt
limit exists; preserve attempts and change diagnosis when a finding recurs.

## Reviewer receipts and lifecycle

The sample includes four configurable receipts without a fixed reviewer cap.
Add all proven free integrations to `reviewers`. CodeRabbit, Cubic, Amazon Q and
Sourcery have Envy installation access verified on 2026-10-01. Installation alone
does not establish free repeated Draft reviews, exact changed-file coverage or
review completion. Pilot those properties before including a provider in the
optional panel. Empty `command` means review requests are externally configured;
the worker treats received findings, without requiring every bot to respond.

Provider errors, quota messages and stale reviews do not pass. A fresh COMMENTED
receipt is a review, not approval. The operator must validate each integration's
complete-scope receipt contract; the worker cannot infer coverage from silence.
The diagnostic `complete_scope_verified` flag describes receipt coverage only;
it never makes that provider a mandatory lifecycle gate. Unknown public commenters are archived but
cannot supply correction tasks; host configuration selects trusted identities.
Request intent is persisted before publication to avoid duplicate quota-spending
requests after ambiguous network failures. Reconcile such requests manually from
the provider's receipt before resetting their state.

When all received findings have dispositions, no human decisions or unresolved
threads remain and all live required checks are present and green,
`allow_live_test_transition` may trigger live-test. Bot responses are optional.
A shared configured review opportunity defaults to 600 seconds after a request;
missing responses then release that advisory wait. Quota/unavailable responses
back off requests (24 hours by default), without blocking corrections or Ready.
Late findings restart correction. Silence never constitutes review or approval.
Ready and the final Copilot request require host-owned `runtime_evidence` with
the exact `head` and `base`, a 64-character `artifact_sha256`, `tested_by`, and
`release_x64`, `release_win32`, `envy_tests`, `live_runtime` all equal to `passed`.
Those fields must describe real runs; they are not a checklist to fill blindly.
Set `allow_ready_transition` and `allow_final_copilot_request` only after the
controlled pilot. New HEAD/base invalidates evidence. Copilot is requested once
per validated HEAD/base, preserving all human/team requests. A request or quota
response never constitutes APPROVED. Merge remains manual.

## Recovery

SQLite commits retain the exact executor session, attempts, source digests,
dispositions and sticky human decisions. Failed local validation preserves the
worker's own patch for a changed correction approach. Foreign dirty worktrees,
remote advances and uncertain timeout ownership require reconciliation; never
discard the patch or force-push. After a timeout, inspect the executor and its
children and confirm that all writers stopped before repairing host ownership
state. A recurring scheduler cannot clear that state automatically.

A genuine decision can be cleared only through an authenticated maintainer
disposition, with technical evidence:

```powershell
python C:/trusted-review/service.py --config C:/trusted-review/config.json --pr 397 --dispose-stop KEY --reason 'Evidence for the resolved decision'
```

Contributor replies are excluded from self-triggering. Individual publication
markers make network retries idempotent. Original review comments are retained.
Publication rejects personal mailboxes and tool-attribution signatures; native
authorship/security checks remain required. Keep diagnostics local because logs
can contain private information.

## Verification

```powershell
python scripts/review/service.selftest.py
python scripts/review/required_checks.selftest.py
python .github/scripts/classify-copilot-review.selftest.py
python .github/scripts/finding-ledger.selftest.py
python .github/scripts/evaluate-review-loop.selftest.py
```

Offline tests cover exclusive ownership, persistent sessions/decisions, missing
required checks, overview edits, privacy, malformed API results and quota/stale
receipts. They do not establish that external apps reviewed a live Draft or that
a Windows runtime test passed. Record live pilot results separately.

## Observed pilot constraints (2026-10-01)

On Draft #397, CodeRabbit acknowledged a full-review request, Cubic rejected it
at a 40,000-line workspace monthly limit (reset reported for 2026-10-18), and
Sourcery rejected the diff above 150,000 characters. These are actual provider
responses, not completed reviews. Do not enable paid upgrades, suppress findings
or certify stability from those refusals. Verify public-repository entitlement
and supported scope before activating the whole panel. Amazon Q published review
5377035297 on `9ea505fc` with seven inline findings, but warned that more than
30 files may miss findings (this PR changed 43 files). That is a real review,
not proof of complete coverage. The host service remains observation-only.

Cursor approval scope already excludes Envy. Its personal Bugbot Autofix mode
is configured to commit to existing branches, despite the installation default
being Off; a concurrent Cursor writer advanced this PR during publication.
Exclusive writer ownership is therefore not yet demonstrated. Do not enable
the correction service or race that writer with repeated history rewrites.
