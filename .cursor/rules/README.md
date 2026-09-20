# Cursor Rules (Envy)

Cursor reads the repository root `AGENTS.md` automatically. That file is the
single source of truth for repository-wide workflow, branching, quality,
documentation, toolchain, and safety rules.

The files in this folder are intentionally **conditional** project rules only.
They add file-scoped guidance that would be noisy or irrelevant as global
context:

- `01-cpp-standards.mdc` — C/C++ sources
- `02-mfc-patterns.mdc` — MFC/UI/resources
- `03-naming-conventions.mdc` — C++/resource naming
- `04-error-handling.mdc` — C++/Win32/MFC error handling
- `05-performance.mdc` — C++ performance-sensitive code
- `06-p2p-protocols.mdc` — protocol/network code
- `07-documentation.mdc` — documentation paths

Do not add another always-on project-context, workflow, or documentation-sync
rule here. Put global rules in `AGENTS.md`. The legacy root `.cursorrules`
file is intentionally removed and must not be reintroduced.
