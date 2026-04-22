# Code Quality Audit

- **Date:** 2026-04-22
- **Scope:** Repository-wide structure, coding patterns, tests, linting, maintainability
- **Method:** Static file inspection and targeted pattern scan

## Executive Summary
The codebase is substantial and mature, but quality signals are mixed: strong test intent and CI workflows exist, while architecture sprawl, legacy patterns, and partial toolchain migration create maintenance friction.

## Severity-Ranked Findings

### High
1. **Module scale and coupling in `Envy/` are high.**
   - Hundreds of translation units with UI, protocol, and state management tightly interwoven.
2. **Build-system duplication causes quality drift.**
   - Visual Studio projects are authoritative; CMake is intentionally incomplete.
3. **Test coverage is narrow relative to surface area.**
   - Existing tests focus heavily on hashing/crypto primitives; limited coverage of protocol stacks, UI glue, plugin loading, and persistence paths.

### Medium
1. **Mixed coding eras and conventions** across C, legacy C++, and modern C++17 patterns.
2. **Technical-debt markers present (`TODO`, `FIXME`) in runtime-relevant code paths.**
3. **Large class files and many responsibilities per subsystem** increase regression risk.

### Low
1. **Legacy project artifacts (`.vcproj`) remain alongside `.vcxproj`.**
2. **Docs duplication (`docs/*`, `.github/*`, root markdown files) can desynchronize over time.**

## Complexity and Duplication Hotspots
- `Envy/` UI + networking classes (`Wnd*`, `Dlg*`, protocol handlers).
- Repeated platform-specific logic for process launching and path handling.
- Duplicate workflow logic across existing GitHub actions files.

## Test and Linting Gaps
- Unit tests do not yet reflect critical runtime behavior (transfer lifecycle, network protocol interoperability, settings migration).
- Formatting checks run in CI, but there is no strict repository-wide “must pass” gate for static analysis failures.

## Recommendations
1. Prioritize subsystem-level test harnesses for protocol handlers and persistence components.
2. Define a modernization track for high-complexity files (extract interfaces, reduce cross-layer coupling).
3. Promote static analysis results from advisory to blocking on selected paths.
4. Introduce coverage thresholds per subsystem and track trends in CI artifacts.
