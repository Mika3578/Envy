# AI coding guide

Status: active
Last updated: 2026-09-20
Scope: Entry point for AI-assisted development on Envy.
Source of truth: `AGENTS.md`, live GitHub state, and the canonical docs linked below.

## Canonical rules

Root [`AGENTS.md`](../../AGENTS.md) is the single source of truth for
repository-wide AI and contributor workflow rules. It defines the mandatory
preflight, branch/PR policy, toolchain, quality gates, protocol evidence,
documentation sync, and merge requirements.

Do not copy those rules into tool-specific guides. When policy changes, update
`AGENTS.md` first.

## Tool adapters

- Cursor automatically reads `AGENTS.md`; `.cursor/rules/*.mdc` contains
  conditional file-scoped guidance only.
- GitHub Copilot: `.github/copilot-instructions.md` is a thin adapter.
- Claude Code: `CLAUDE.md` is a thin adapter.
- Cline/Windsurf/Continue adapters point back to `AGENTS.md`.
- Aider explicitly loads `AGENTS.md` from `.aider.conf.yml`.

The legacy root `.cursorrules` and the duplicate
`.github/agents/my-agent.md` are intentionally removed.

## Working sequence

Before editing, use the preflight in `AGENTS.md`: inspect current `develop`,
open PRs/issues, recent commits, CI/rulesets, relevant code/tests, and primary
protocol/spec sources. Classify overlapping work before starting anything new.

Prefer the smallest compatible change with explicit validation. Network/file
input is untrusted. Protocol changes require evidence appropriate to their
risk: regression tests, boundary/malformed cases, primary-spec comparison, and
reference-client comparison where relevant.

## Canonical context

- [Development plan](../DEVELOPMENT_PLAN.md)
- [Current implementation status](status.md)
- [Architecture](../20_arch/architecture.md)
- [Protocol references](../30_protocols/REFERENCE_IMPLEMENTATIONS.md)
- [Agents and automation](agents-and-automation.md)
- [DevSecOps map](devsecops-envy.md)
