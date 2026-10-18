@AGENTS.md

## Claude Code

- Skills live in `.agents/skills/` (shared with Codex, Copilot and Cursor);
  Claude Code does not auto-discover that directory. When a task matches the
  skills table above, read that `SKILL.md` before acting.
- Before editing a path covered by `.cursor/rules/*.mdc` (C++, MFC resources,
  protocol code, docs), read the matching rule file once per session.
