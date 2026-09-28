# GitHub Discussions — Envy community space

Status: active
Scope: How Envy uses GitHub Discussions versus Issues, category intent, templates, and lightweight moderation.

**Canonical project state** remains in the repository (`docs/10_dev/status.md`, `docs/10_dev/roadmap.md`, `docs/DEVELOPMENT_PLAN.md`, Issues/PRs). Discussions are for conversation, not a second roadmap.

## Issues vs Discussions

| Use **Issues** for | Use **Discussions** for |
| --- | --- |
| Confirmed bugs and regressions | Questions and troubleshooting |
| Security/correctness work ([SECURITY.md](../../.github/SECURITY.md)) | Brainstorming and early feature exploration |
| Scoped features with acceptance criteria | Design exploration before scoping |
| Measurable engineering tasks | Preview-build and interoperability feedback |
| | Contributor introductions and onboarding chat |
| | Official announcements (maintainer-led) |

Do not move well-scoped P0/P1 engineering work into Discussions.

## Category map (live on GitHub)

| Category | Slug | Purpose |
| --- | --- | --- |
| Announcements | `announcements` | Releases, preview builds, milestones, maintainer news |
| General | `general` | Broad conversation; onboarding |
| Q&A | `q-a` | Help — GitHub **accepted answer** enabled |
| Ideas | `ideas` | Feature proposals before Issues |
| Polls | `polls` | Non-binding preference checks |
| Show and tell | `show-and-tell` | Showcases; not primary interop reporting |

### Recommended category additions (manual GitHub UI)

The public GraphQL API does **not** expose category create/rename/delete. When ready, add or adjust categories under **Settings → General → Discussions**:

| Recommended name | Format | Emoji | Description |
| --- | --- | --- | --- |
| Development & Architecture | Open discussion | `:hammer_and_wrench:` | EnvyCore, portability, headless/API design, implementation strategy |
| Testing & Interoperability | Open discussion | `:test_tube:` | Preview testing, ED2K/Kad/BT/G1/G2/NMDC interop reports (sanitized) |
| Contributors | Open discussion | `:handshake:` | “I want to help”, first issues, dev environment, introductions |

After creating a category, add a matching `.github/DISCUSSION_TEMPLATE/<slug>.yml` form (filename must equal the category slug).

Optional renames (UI only): align **Q&A** emoji to `:question:` and **Ideas** description with “exploration, not commitment to implement”.

## Category forms

Repository forms live in [`.github/DISCUSSION_TEMPLATE/`](../../.github/DISCUSSION_TEMPLATE/). They apply per category slug when merged to the default branch.

## Canonical pinned discussions

Maintainers should pin (UI — no public pin API):

1. **Welcome to Envy Discussions** — scope, doc links, Issues vs Discussions
2. **How to contribute, test, and help Envy** — CONTRIBUTING, AGENTS, roles
3. **Preview testing and protocol interoperability reports** — template below
4. **Envy modernization roadmap and project direction** — links to roadmap/status only

Draft bodies for (2)–(4) are available in [`canonical-discussions/`](canonical-discussions/), or can be recreated from this file’s interoperability section.

## Interoperability report template

Use for preview testing and protocol feedback (sanitize all private data):

```markdown
### Environment
- Envy version/commit:
- Windows version:
- Architecture:

### Network / protocol
- BitTorrent / ED2K / Kad / G1 / G2 / NMDC / other:

### Test
- What was tested:
- Peer/client used for interoperability:
- Expected:
- Actual:

### Evidence
- Sanitized log excerpt:
- Reproduction steps:

### Privacy
- [ ] Peer IPs removed
- [ ] Personal paths removed
- [ ] Credentials/tokens removed
```

Do not claim live interoperability where [status.md](../10_dev/status.md) marks behavior **unverified**.

## Moderation principles (lightweight)

- Be technical and respectful; search before duplicating topics.
- Sanitize logs — no credentials, tokens, or private peer IPs unless truly necessary and safe.
- No requests for pirated or infringing content; discuss protocol/client behavior, not sourcing illegal material.
- Security vulnerabilities → [private advisories](https://github.com/Mika3578/Envy/security/advisories/new), not public Discussions.
- Confirmed bugs → Issues. Accepted implementation work → Issues with criteria, then PRs.

## Issue template routing

[`.github/ISSUE_TEMPLATE/config.yml`](../../.github/ISSUE_TEMPLATE/config.yml) `contact_links` direct general questions and early ideas to the appropriate Discussion categories without blocking bug reports.
