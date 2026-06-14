# Cursor Rules (Envy)

Cursor rule files (`*.mdc`) provide scoped guidance. Canonical cross-tool rules
live in **`AGENTS.md`** at the repository root.

## Active rule set

| File | Scope |
| --- | --- |
| `00-core.mdc` | Project context, AGENTS.md pointer (always on) |
| `10-cpp-mfc.mdc` | C++, MFC, naming, errors, performance |
| `20-build-msbuild.mdc` | MSBuild, vcpkg, build authority |
| `30-protocols.mdc` | P2P protocol safety and compatibility |
| `40-git-pr-workflow.mdc` | Branching, PRs, GitHub tracking (always on) |
| `50-documentation.mdc` | Documentation policy |
| `60-security-review.mdc` | Security-sensitive change checklist |

Change canonical rules in `AGENTS.md`; update scoped rules here only when
Cursor-specific scoping adds value.
