# Review scoreboard

**Last Updated:** 2026-10-18

The scoreboard measures how useful each AI review app has been on recent pull
requests and estimates whether it is available, then recommends which reviewer
to ask **by hand**. It never requests a review, posts on a pull request,
approves, or sets a status. The review-request rules still decide whether and
when to ask: one primary reviewer per HEAD, a second only for a named risk,
never automatically on every push.

## Use it

```bash
python3 .github/scripts/review-scoreboard.py --print
```

It needs a token from `GITHUB_TOKEN`, `GH_TOKEN`, or `gh auth token` with read
access to pull requests and GraphQL. The optional workflow
`.github/workflows/review-scoreboard.yml` runs the same script every six hours
(or on manual dispatch) with `--update-issue` and rewrites one
**Review bot scoreboard** issue. Pin that issue so agents and the maintainer
find it.

The output has three parts:

- **Recommendation**: the best available reviewer as primary and the next one
  as a second reviewer, each with the way to ask it. It is a hint: prefer it
  over the default primary when the numbers clearly favour it, and keep asking
  at most once per reviewer per HEAD, with `Head: <sha>` in the request.
- **Ranking**: every enabled reviewer with its score and, when held, why.
- **All review apps**: statistics for every review app seen on recent PRs,
  including apps that are not asked routinely (for example cubic or Cursor),
  for comparison.

## How it is computed

Statistics are recomputed from scratch over the last
`ENVY_SCOREBOARD_WINDOW_DAYS` days (up to 40 pull requests). A rerun never counts
anything twice, and the numbers follow each app's recent behaviour.

- **Outcome of a finding.** A review thread is *useful* when its treating reply
  starts with `Fixed in <sha>`, `Addressed in <sha>`, or `Partly fixed in <sha>`.
  It is *rejected* when that reply starts with `No change` or `Not reproduced`.
  Anything else is *unclassified*. Keep these reply forms when treating threads,
  or the score cannot learn from them.
- **Requests and answers.** A request is a comment that opens with the app's
  command (`@coderabbitai review`, `/q review`, `@sourcery-ai review`,
  `/gemini review`), or a reviewer request for Copilot. An answer is the app's
  next review or comment on that PR. The latency is the delay between the two.
- **Score.** Smoothed precision `(useful + 1) / (useful + rejected + 2)`,
  weighted by volume: an app needs about ten decided findings before its
  measured precision fully replaces the neutral 0.5 prior. The score drops in
  proportion to unanswered requests, and by 10 % when the median answer takes
  more than 12 hours. Ties keep the `ENVY_REVIEWERS` order.
- **Availability (a hint).** No app exposes its quota by API, so:
  - a limit or rate-limit message from the app holds it until its monthly reset
    day (`ENVY_REVIEWER_RESET_DAYS`), else for `ENVY_REVIEWER_COOLDOWN_HOURS`
    (default 24);
  - `ENVY_REVIEWER_MONTHLY_CAPS` holds an app once requests this calendar month
    reach the cap;
  - `ENVY_REVIEWER_HELD` holds an app until a date, for quotas that run out
    silently (Copilot);
  - a request left unanswered for `ENVY_REVIEW_TIMEOUT_HOURS` holds the app
    until it answers anywhere, or for 24 hours after that request.

## Settings

All are optional repository variables.

| Variable | Default | Example |
| --- | --- | --- |
| `ENVY_REVIEWERS` | `coderabbit,copilot,amazonq,sourcery,gemini` | reviewers to rank; the order breaks ties |
| `ENVY_REVIEWER_RESET_DAYS` | none | `sourcery=1` |
| `ENVY_REVIEWER_COOLDOWN_HOURS` | 24 for every app | `coderabbit=1` (hourly rate limit) |
| `ENVY_REVIEWER_MONTHLY_CAPS` | none | `gemini=900` |
| `ENVY_REVIEWER_HELD` | none | `copilot=2026-11-01` |
| `ENVY_REVIEW_TIMEOUT_HOURS` | `6` | `12` |
| `ENVY_SCOREBOARD_WINDOW_DAYS` | `90` | `30` |
| `ENVY_REVIEWER_LOGINS` | built in | `gemini=gemini-code-assist[bot]` to correct an app login |

## Limits

- Classification relies on the treating reply format. Older threads answered
  in free form stay unclassified and do not move the score.
- Availability is inferred, so an app can be held after its quota came back,
  or look available while it is silently exhausted; `ENVY_REVIEWER_HELD`
  covers the known case.
- The workflow uses the default `GITHUB_TOKEN` with `issues: write` only to
  rewrite its own issue. The issue is trusted only when written by
  `github-actions[bot]` or the repository owner.
