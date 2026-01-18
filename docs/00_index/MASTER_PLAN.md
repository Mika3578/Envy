# Envy Modernisation — Master Plan

This is the single-page plan to drive modernisation in the right order: foundations first, then protocol compatibility, then performance/security, then release discipline.

## Order of operations
1. Build reproducibility + CI gates
2. Unified packet parsing/serialization (bounded)
3. Observability (logs/metrics)
4. Tests harness + protocol fixtures
5. ED2K: tags/vendor -> search -> sources/uploads
6. Kad: nodes.dat -> lookup correctness
7. Performance (anti-freeze)
8. Security hardening + fuzzing
9. Releases

## Non-negotiables
- Any protocol bugfix must add a fixture + test.
- No raw network parsing outside the unified reader.
- Small PRs, linear history.
