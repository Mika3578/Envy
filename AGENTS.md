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


### 6) Security Patterns
- Always use `crypto.getRandomValues` for security tokens (no `Math.random` for secrets).
- Never assign user-controlled input directly to `innerHTML`; use `textContent` or approved sanitization.
- Redirects must pass through an internal allowlist validator (block absolute, protocol-relative, and dangerous schemes).

### 7) Operating Rules (Repository-Wide)
- Prefer small, reviewable PRs; keep one logical change area per PR.
- Never silently remove tests, coverage, artifacts, workflows, legacy files, or docs.
- Every meaningful PR must update:
  - `CHANGELOG.md` (`[Unreleased]`)
  - `docs/DEVELOPMENT_PLAN.md` for strategic scope/decision changes
  - `docs/DEV_TRACKER.md` for operational status changes
- Protocol changes must preserve wire compatibility unless explicitly documented.
- CI changes must preserve validation capability unless intentionally moved and documented.
- Always report testing performed, testing not performed, and environment limitations.
- Build authority and toolchain policy: `Visual Studio/Envy.sln` is authoritative, MSVC `v145` is required, CMake is partial only.
- Prefer audit-first development for risky protocol/security changes.
- Avoid broad refactors without explicit scope and rollback strategy.
