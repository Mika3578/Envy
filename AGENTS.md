# AGENTS.md

## Repository Rules for Coding Agents

### 1) Scope and Planning
- Keep tasks decomposed into small, reviewable changes.
- Prefer incremental updates over sweeping rewrites.
- Preserve existing behavior unless the task explicitly changes it.

### 2) Coding Standards
- Follow local style in touched files.
- Prioritize safe string/path handling in C/C++ code.
- Keep Windows/MFC assumptions explicit when adding abstractions.

### 3) Testing
- Run the most relevant checks for changed areas.
- If environment blocks execution, report exact limitation.
- Add or update tests for bug fixes and protocol parsing changes when feasible.

### 4) Documentation
- Update docs in `/docs` for architecture, setup, API, testing, deployment.
- Update `docs/DEVELOPMENT_PLAN.md` on meaningful scope/decision changes.
- Keep `CHANGELOG.md` current under `[Unreleased]`.

### 5) Commit and Review Hygiene
- Use clear commit messages with one intent per commit.
- Include risk notes for security, dependency, and performance impacts.
- Surface any human decisions required before implementation.
