Paste this as the body when creating the pinned Discussion **How to contribute, test, and help Envy** (category: **General** or future **Contributors**).

---

## How to contribute, test, and help Envy

Thank you for wanting to help. Envy is AGPL-3.0-or-later; see [CONTRIBUTING.md](https://github.com/Mika3578/Envy/blob/develop/.github/CONTRIBUTING.md) and [AGENTS.md](https://github.com/Mika3578/Envy/blob/develop/AGENTS.md) for workflow, branch naming, and review expectations.

### Ways to help

| Area | What helps |
| --- | --- |
| **C++ / MFC developers** | Fix bugs and scoped features via PRs to `develop`; start from [open issues](https://github.com/Mika3578/Envy/issues) with clear scope. |
| **Protocol specialists** | ED2K/Kad, BitTorrent, G1/G2, NMDC interoperability reports with sanitized evidence; compare with [reference implementations](https://github.com/Mika3578/Envy/blob/develop/docs/30_protocols/REFERENCE_IMPLEMENTATIONS.md). |
| **Testers** | Preview builds from [Releases](https://github.com/Mika3578/Envy/releases); post structured feedback in the preview/interoperability pinned thread. |
| **Documentation** | Improve `docs/` and contributor guides; keep status vocabulary aligned with [status.md](https://github.com/Mika3578/Envy/blob/develop/docs/10_dev/status.md). |
| **Translations** | `Languages/` XML — only if you are fluent in the target language (see CONTRIBUTING). |
| **Security researchers** | **Private** reports only — [SECURITY.md](https://github.com/Mika3578/Envy/blob/develop/.github/SECURITY.md). |
| **UI/UX** | Feedback and design ideas welcome in Discussions; implementation goes through scoped issues/PRs. |

### First-time code contributors

1. Read [CONTRIBUTING.md](https://github.com/Mika3578/Envy/blob/develop/.github/CONTRIBUTING.md).
2. Pick an issue or ask here what subsystem matches your skills.
3. Branch from `develop` using `type/short-kebab-summary` (no tool/agent prefixes).
4. Open a **draft PR** early; CI and review gates apply before merge.

### Protocol / interoperability reports

Include: Envy version/commit, network/protocol, expected vs actual, sanitized logs, reproduction steps. Live eMule/aMule/Kad interop is often **unverified** in docs — evidence helps prioritize work.

Questions: [**Q&A**](https://github.com/Mika3578/Envy/discussions/categories/q-a). Confirmed defects: **Issues**.
