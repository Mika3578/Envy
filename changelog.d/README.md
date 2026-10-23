# Changelog fragments

PRs do not edit `CHANGELOG.md` (every PR touching it conflicts with every
other). Add one fragment per user-visible change instead:

    changelog.d/<PR-or-issue>.<category>.md

`category` is one of `added`, `changed`, `fixed`, `security`, `removed`.
The file holds a single entry in the existing style, without the leading
`- `:

    **Kad bootstrap rotation (#462)** - Rotate candidates with bounded retries.

At release time the maintainer runs
`python .github/scripts/compile-changelog.py`, which appends the fragments to
`## [Unreleased]` of `CHANGELOG.md` and deletes them. Use `--dry-run` to
preview. Entries already in `CHANGELOG.md` stay as they are.
