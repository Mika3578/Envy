# Idea capture and periodic review

Status: active
Last updated: 2026-10-06
Scope: Capture observations during development without opening an Issue or PR per note.
Canonical durable register: [`ideas.md`](ideas.md)
Tracking-model hub: [#424 — Consolidate Envy work tracking, planning, and development records](https://github.com/Mika3578/Envy/issues/424)
Documentation-drift cleanup remains [#85 — Reconcile canonical project documentation and stale roadmap references](https://github.com/Mika3578/Envy/issues/85)

This process is optional for compiling, testing, or contributing code. A clone without `.local/inbox/` is valid.

## Why this exists

Two failure modes to avoid:

1. Useful observations die in ChatGPT, Codex, Cursor, or machine-local notes.
2. GitHub is flooded with an Issue or PR for every small idea.

GitHub Issues remain the durable unit of **actionable** work (bugs, scoped features, security, interop gaps). `ideas.md` is only the **pre-issue** register plus a short memory of rejected or deferred ideas so agents do not keep re-proposing them.

Do not treat this file as a second roadmap. Sequencing stays in `docs/DEVELOPMENT_PLAN.md`. Capability status stays in `docs/10_dev/status.md`. Itemization stays in `docs/10_dev/roadmap.md`. Decisions stay in `docs/DECISIONS.md`.

## Cycle

```
Observation
  → optional local inbox (.local/inbox/, gitignored)
  → periodic review (or immediate path if urgent)
  → durable register (docs/10_dev/ideas.md)
  → Discussion / existing plan doc (open architecture only)
  → GitHub Issue (when work is defined)
  → focused implementation PR
```

Never open one PR per inbox note. Never auto-convert observations into Issues. Never bundle unrelated product fixes into a documentation review PR.

## Local inbox (temporary, not a specification)

Create files only if you want them. Suggested names under `.local/inbox/`:

| File | Use |
|------|-----|
| `ideas.md` | Product, UX, docs, miscellaneous |
| `protocols.md` | G1/G2, ED2K, Kad, BitTorrent, NMDC/ADC |
| `architecture.md` | EnvyCore, portability, performance, core/UI |
| `security.md` | Security observations that are **not** confirmed P0/P1 |
| `ci.md` | CI, build, tooling |
| `technical-debt.md` | Localized debt that is not yet an Issue |

Do not invent extra categories unless review keeps tripping over mixed files.

Entry format: [`idea-entry.template.md`](idea-entry.template.md). Every entry needs a descriptive title. Never record only `IDEA-017` or only `#231`.

The inbox is **unapproved**. It is never a specification and never authorization to implement.

## Urgent work never waits for batch review

Handle immediately through the normal bug/security path (private advisory when required):

- Confirmed vulnerability
- Data corruption or loss
- Reproducible critical crash
- Confidentiality leak
- Serious protocol-violation / interop breakage in shipping code
- Important recent regression
- `develop` or required CI broken
- Any P0/P1 that needs action now

Do not park these in the inbox hoping a monthly review will notice them.

## Periodic review triggers

Configurable; start here and adjust after using the process:

- 10 PRs **merged** to `develop` since the last review, **or**
- 10 pending inbox entries (all categories combined), **or**
- 30 days since the last review, **or**
- Manual trigger

Merged PRs are the work unit, not commit count. `scripts/check-maintenance-review.py` prints an advisory signal only. It must not create Issues, accept ideas, open PRs, or change product code.

## What a review does

For **each** pending inbox entry:

1. Read current `develop`.
2. Search `docs/10_dev/ideas.md`.
3. Search open **and** closed Issues (title + number).
4. Search open and merged PRs.
5. Search Discussions and existing plan docs (`docs/20_arch/`, `docs/ipv6/`, `docs/DECISIONS.md`) when architecture is involved.
6. Check whether the problem still exists.
7. Consult primary technical sources when needed (spec → official docs → maintained implementation).

Classify:

| Class | Meaning |
|-------|---------|
| NEW | Not represented; immature → Candidate in `ideas.md` |
| NEEDS RESEARCH | Plausible; evidence missing |
| ACCEPTED | Direction agreed; still not an Issue until scoped |
| TRACKED | GitHub Issue (or tracking issue) exists |
| DUPLICATE | Already in ideas/Issue/PR — link `#N — title` |
| ALREADY IMPLEMENTED | Landed; close the inbox note |
| SUPERSEDED | Replaced by a later decision or Issue |
| DEFERRED | Not now; keep a short justification |
| REJECTED | Will not do; keep a short justification |
| URGENT | Leave the batch process immediately |

Keep short Rejected/Deferred rows. Deleting them causes agents to rediscover the same bad idea.

## Promotion

| After review | Destination |
|--------------|-------------|
| NEW but immature | `ideas.md` Candidate |
| Open architectural question | GitHub Discussion, or an existing plan doc — **not** a new RFC tree |
| Work defined enough to execute | GitHub Issue (feature/bug template) |
| Issue defined enough | Separate implementation PR |

Do not create `docs/proposals/` for ordinary improvements. Substantial architecture already uses `docs/DECISIONS.md` and dedicated plan docs (`PORTABILITY_PLAN.md`, `UI_MODERNIZATION.md`, `docs/ipv6/PLAN.md`, protocol plans).

An actionable Issue should include: problem, evidence, scope, non-goals when useful, intended approach, security/risk, acceptance, tests, dependencies. Always write `#123 — descriptive title`, never `#123` alone.

## Maintenance PR

A review may produce **one** documentation/maintenance PR, for example `docs: periodic backlog review 2026-10`.

That PR may update `ideas.md`, record decisions, link Issues, and refresh this process doc. It must **not** collect unrelated product-code fixes.

## Last review pointer

The versioned pointer lives at the top of [`ideas.md`](ideas.md): date, `develop` revision, and merged-PR baseline. After a review, update that block in the same maintenance PR.

## GitHub Discussions

Discussions are enabled for questions and open-ended direction ([contact link](https://github.com/Mika3578/Envy/discussions)). Convert to an Issue only when the work is scoped. Do not use Discussions as the durable backlog.

## Portability

No IDE, vendor AI, machine path, or token is required. Humans and any assistant should follow the same search order before proposing work.
