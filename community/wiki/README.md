# GitHub Wiki source

Markdown in this directory is the **reviewable source** for [Mika3578/Envy Wiki](https://github.com/Mika3578/Envy/wiki).

## Canonical vs Wiki

| Topic | Location |
| --- | --- |
| Implementation status, protocols, security, AGENTS rules | Main repo `docs/` (versioned) |
| History, FAQ, onboarding, curated archives | Wiki (this source) |

## Publish to live Wiki (maintainer)

After the community PR merges and content is approved:

```bash
git clone https://github.com/Mika3578/Envy.wiki.git /tmp/envy-wiki
find community/wiki -maxdepth 1 -name '*.md' ! -name README.md -exec cp {} /tmp/envy-wiki/ \;
cd /tmp/envy-wiki
git add -A
git status
git commit -m "docs(wiki): sync from community/wiki source"
git diff -- . ':!README.md'
git push origin HEAD
```

GitHub Wiki default branch may be `master` or `main`; use `git branch` in the clone.

Do not overwrite unexpected live-only edits without review.

## PR workflow

1. Edit files here on a feature branch.
2. Open/update the community website PR.
3. Publish to `.wiki.git` only after merge unless explicitly authorized earlier.
