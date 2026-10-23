# Cursor rules (Envy)

Cursor reads root `AGENTS.md` (global rules) and discovers the skills in
`.agents/skills/`, loading a `SKILL.md` only when a task matches it. The files here are **file-scoped** rules attached by glob
only (`alwaysApply: false`, empty `description`, comma-separated `globs`):

- `01-cpp.mdc` - C/C++ sources: language level, ownership, MFC, errors,
  performance
- `02-mfc-resources.mdc` - `.rc` / `Resource.h`: resource de-duplication
- `06-p2p-protocols.mdc` - protocol and network sources: points to
  `envy-protocol-change`
- `07-documentation.mdc` - documentation paths

Other tools read the matching file before editing those paths (`AGENTS.md`,
*Code invariants*). Do not add always-on rules or copies of `AGENTS.md`
here; `.github/scripts/check-agent-config.py` enforces the format.
