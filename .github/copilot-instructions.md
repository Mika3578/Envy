# GitHub Copilot instructions for Envy

Root `AGENTS.md` is the canonical rule set; Copilot agents read it. Copilot
code review reads only the first 4,000 characters of this file, so the review
essentials below are self-contained. Full reviewer procedure:
`.agents/skills/envy-code-review/SKILL.md`.

## Reviewing

- Envy is a Windows C++/MFC P2P client (ED2K/Kad, G1/G2, BitTorrent, DC).
  Report correctness, security and interoperability defects first; mark
  style nits optional. Do not repeat findings already answered on the PR.
- Network, peer, file and Remote input is hostile: flag missing length or
  bounds checks, unchecked size arithmetic, uncapped allocations or queues,
  path traversal, and crashes on malformed input.
- Wire-format or protocol behaviour changes need a regression test or a
  spec/reference comparison. Crypto, auth, threading, locking and memory
  lifetime changes need targeted tests; `Wire-format impact: none` does not
  cover them.
- Flag: re-encoded files, EOL churn, removed copyright or provenance notices,
  edits to read-only third-party trees (`Services/*`, `HashLib/HashLib/*`,
  `Plugins/{RatDVDPlugin,SWFPlugin}`), XP-targeting macros, GPL-2.0/3.0
  dependencies, personal emails, AI `Co-authored-by` trailers.
- Flag any change that skips, disables or weakens a required check, test or
  quality gate.

## Review state

- Governance paths (`AGENTS.md`, `CLAUDE.md`, `.agents/**`, `.claude/**`,
  `.cursor/**`, `.continue/**`, `.gemini/**`, `.clinerules`, `.windsurfrules`,
  `.aider.conf.yml`, `.coderabbit.yaml`, this file, `.github/workflows/**`,
  `.github/scripts/**`, `.github/rulesets/**`, `.github/settings.yml`): never
  `APPROVED`. Leave
  `COMMENTED` or `CHANGES_REQUESTED`; a human approves.
- Never approve a Draft or a PR authored by Copilot cloud agent.
- Blocking defect or missing evidence: `CHANGES_REQUESTED`. Otherwise
  `COMMENTED`, or `APPROVED` only when checks are green, the branch is up to
  date, no thread or `CHANGES_REQUESTED` is open, the branch name has no
  tool prefix and the Squash Commit Summary matches the final head.
- A Copilot review is advisory. The maintainer merges; CI stays independent.
