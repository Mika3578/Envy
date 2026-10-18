# Review digest

Status: active
Last updated: 2026-10-18
Scope: The comment that lists a pull request's unresolved review threads.
Source of truth: `.github/scripts/review-digest.py`, `.github/workflows/review-digest.yml`

## What it does

The **Review digest** workflow keeps one comment per pull request that lists
the unresolved review threads on the current head, grouped as *To treat*,
*Nits* and *Outdated*, with counts and links. Agents and the maintainer read
that comment, or print it locally, instead of paging through the whole
conversation. It refreshes on pushes, submitted or dismissed reviews, and new
review comments; `workflow_dispatch` refreshes one PR on demand.

```bash
python3 .github/scripts/review-digest.py --pr <N> --print
```

`--print` lists every thread and writes nothing; it needs a token from
`GITHUB_TOKEN`, `GH_TOKEN` or `gh auth token` with GraphQL access.

## Limits

- Advisory only: it never requests reviews, approves, resolves, merges or
  sets a status. Thread classification is a heuristic; agents still read each
  thread before treating it.
- Thread text is rendered as inert code spans, so links, mentions and
  reviewer commands in findings cannot act from the digest.
- Only comments by `github-actions[bot]` or the repository owner are treated
  as the digest; a pasted marker is ignored.
- The script runs from the default branch and never checks out PR code; fork
  PRs are skipped because their token is read-only.
