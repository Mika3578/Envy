# Legacy Refactor Plan — Clean Restart Strategy

- **Status:** Proposed
- **Owner:** Maintainers
- **Last Updated:** 2026-05-04
- **Scope:** Repository-wide, with hard caps on per-PR blast radius
- **Inputs:** `docs/audit/{ARCHITECTURE,SECURITY,CODE_QUALITY,DEPENDENCY,PERFORMANCE}_AUDIT.md`, `docs/10_dev/roadmap.md`, `docs/DEVELOPMENT_PLAN.md`, `AGENTS.md`, `CLAUDE.md`

## Intent
Provide a deterministic, low-risk path out of legacy without sweeping rewrites. Each step is a single PR sized for human review (≤ ~600 changed LOC, single intent). Behavior is preserved unless the PR is explicitly behavioral. The Visual Studio solution remains authoritative until CMake parity is reached (Phase 4).

## Operating Rules (apply to every PR)
1. **One intent per PR.** No drive-by edits. If you find unrelated rot, file an issue.
2. **Behavior-preserving by default.** Behavioral PRs must say so in the title and list the observable change.
3. **Tests land before refactors that touch the same code.** No "I'll add tests later".
4. **Windows-first assumptions stay explicit.** No silent cross-platform abstractions.
5. **Security/perf/dependency notes** required in PR description when relevant.
6. **Update `CHANGELOG.md` (`[Unreleased]`) and `docs/DEVELOPMENT_PLAN.md`** in the same PR when behavior, build, or process changes.
7. **No new dependencies** without an entry in the dependency register (PR-02) and an owner.

## Sequencing Overview

```
Phase 0 — Foundations (PR-01 → PR-04)
   └─► Phase 1 — Test scaffolding (PR-05 → PR-08)
          └─► Phase 2 — Safe fences (PR-09 → PR-12)
                 └─► Phase 3 — Modernization slices (PR-13 → PR-19)  [parallelizable across modules]
                        └─► Phase 4 — Build convergence (PR-20 → PR-22)
                               └─► Phase 5 — Cleanup & release hygiene (PR-23 → PR-26)
```

PRs in Phase 3 are independent across modules and may be parallelized once their respective fences (Phase 2) are merged.

---

## Phase 0 — Foundations

### PR-01 — Promote green static-analysis checks to required CI gates
- **Why:** Lock the current quality floor before refactor pressure pushes it down.
- **Files:** `.github/workflows/code-quality.yml`, `.clang-tidy`, `.cppcheck-suppressions`, `docs/10_dev/standards.md`.
- **Scope:** For each check that is already green on `develop`, mark the job `required` (branch-protection-ready). Do not add new lints. Document the floor.
- **Acceptance:** CI on `develop` unchanged green; protected-branch config doc updated; no source code touched.
- **Risk:** Low. Pure CI/policy.
- **Prompt:**
  > Read `.github/workflows/code-quality.yml`, `.clang-tidy`, `.cppcheck-suppressions`. Identify which jobs are currently passing on `develop`. Mark those jobs as `required` via job-level `continue-on-error: false` and document the gate set in `docs/10_dev/standards.md` under a new "CI Quality Floor" section. Do not enable any new checks. Do not modify source code. Update `CHANGELOG.md [Unreleased]` with a one-line entry.

### PR-02 — Dependency register + SBOM scaffold
- **Why:** Address audit finding (no machine-readable manifest for vendored C/C++).
- **Files:** new `docs/40_quality/dependencies/REGISTER.md`, new `docs/40_quality/dependencies/SBOM.cdx.json` (skeleton), `.github/workflows/security.yml`.
- **Scope:** Inventory in tabular form: name, vendored path, observed version, upstream URL, license, owner, last-reviewed date. Generate a CycloneDX skeleton (manual entries OK). Add a CI step that uploads the SBOM as a build artifact on release-tag runs only.
- **Acceptance:** Register lists every entry from `docs/audit/DEPENDENCY_AUDIT.md`. SBOM artifact published on a tagged dry-run.
- **Risk:** Low.
- **Prompt:**
  > From `docs/audit/DEPENDENCY_AUDIT.md` and direct inspection of `Services/`, `HashLib/`, and `Plugins/`, produce `docs/40_quality/dependencies/REGISTER.md` (table: name, path, version, upstream URL, license, owner, last-reviewed). Then create `docs/40_quality/dependencies/SBOM.cdx.json` as a minimal CycloneDX 1.5 document referencing each entry. Add a job to `.github/workflows/security.yml` that uploads the SBOM as an artifact on `push` to tags matching `v*`. No source code changes.

### PR-03 — Threat model + secure-coding checklist
- **Why:** Audit calls out missing threat model; refactor decisions need a security baseline.
- **Files:** new `docs/40_quality/security/THREAT_MODEL.md`, new `docs/40_quality/security/SECURE_CODING_CHECKLIST.md`.
- **Scope:** STRIDE-style table per trust boundary (P2P peers, DHT, Remote HTTP UI, plugin host, local FS, update channel). Checklist references concrete files (e.g., `URLValidator.cpp`, `Remote/security-config.js`).
- **Acceptance:** Each "Critical" / "High" finding from `SECURITY_AUDIT.md` mapped to a checklist item.
- **Risk:** Documentation-only.
- **Prompt:**
  > Using `SECURITY_AUDIT.md` and `docs/audit/SECURITY_AUDIT.md`, produce `docs/40_quality/security/THREAT_MODEL.md` with one STRIDE row per trust boundary (P2P peers, DHT, Remote HTTP UI, plugin host, local FS, update channel) and a controls column referencing existing code paths. Then write `docs/40_quality/security/SECURE_CODING_CHECKLIST.md` with one bullet per "Critical"/"High" finding from the audit, citing the file path that addresses (or should address) it. No source code changes.

### PR-04 — Baseline performance harness
- **Why:** Without numbers, modernization claims are not falsifiable.
- **Files:** new `tests/perf/`, `tests/CMakeLists.txt`, `docs/40_quality/performance/BASELINE.md`.
- **Scope:** Three measurable scenarios on Windows: cold-start time, peak RSS during 1k-source library scan, throughput on a 1 GiB BT seed against a localhost peer. Capture as fixtures, not pass/fail gates yet.
- **Acceptance:** `ctest -L perf` runs the harness; baseline numbers stored in `BASELINE.md` with environment notes.
- **Risk:** Low (tests-only).
- **Prompt:**
  > Add `tests/perf/` with three Google-Test-driven scenarios: (1) measure `CEnvyApp` cold-start to message-pump-ready, (2) RSS after a synthetic 1k-file library scan against a temp dir fixture, (3) BitTorrent throughput against a localhost peer using the existing test harness. Wire it under `BUILD_TESTS=ON` with the CTest label `perf`. Record the captured numbers in `docs/40_quality/performance/BASELINE.md` with hardware, toolset, and date columns. Do not gate CI on these numbers yet.

---

## Phase 1 — Test scaffolding

### PR-05 — Expand HashLib + BENode parser tests
- **Why:** BENode is a parser at a trust boundary (BitTorrent). It must be the first to gain coverage.
- **Files:** `tests/test_hashlib.cpp`, new `tests/test_benode.cpp`, `tests/CMakeLists.txt`.
- **Scope:** Add malformed-input fuzz-style cases (truncated, oversized length prefix, recursion depth, integer overflow on string length).
- **Acceptance:** Coverage report shows BENode lines hit ≥ 85%; harness runs in < 5 s.
- **Prompt:**
  > Read `Envy/BENode.cpp` and `Envy/BENode.h`. Add `tests/test_benode.cpp` with cases for: truncated dictionaries, oversized length prefix, deep recursion, negative/oversized integer fields, duplicate keys, non-sorted dict keys (per BEP-3). Use the existing `test_framework.h`. Register in `tests/CMakeLists.txt`. Do not modify `BENode.cpp` itself even if a bug appears — file an issue and document it in the test as `DISABLED_*`.

### PR-06 — Protocol packet parser tests (read-only)
- **Files:** new `tests/test_btpacket.cpp`, `tests/test_edpacket.cpp`, `tests/test_g2packet.cpp`.
- **Scope:** Parser/serializer round-trips on captured fixtures. Pure data, no socket. Add `tests/fixtures/packets/` with hex dumps.
- **Acceptance:** Each parser hit on representative real-world payloads; failing fixtures documented as `DISABLED_*`.
- **Prompt:**
  > For each of `BTPacket`, `EDPacket`, `G2Packet`: add a parser/serializer round-trip test in `tests/`, fed by hex fixture files under `tests/fixtures/packets/`. The fixtures must be pure data. The test must not open sockets, threads, or files outside `tests/fixtures/`. If a round-trip fails, encode the case as `DISABLED_*` with a comment pointing at the suspected file/line — do not patch the parser in this PR.

### PR-07 — Remote API contract tests
- **Files:** new `tests/remote/test_contract.py` (pytest), `Remote/api-specification.md` reconciled.
- **Scope:** Spec-driven tests against a stub server fixture or recorded responses. Lock observable response shape; do not change server code.
- **Acceptance:** Every endpoint listed in `Remote/api-specification.md` has at least one shape assertion.
- **Prompt:**
  > Read `Remote/api-specification.md` end-to-end. For each endpoint, add a pytest case in `tests/remote/test_contract.py` that asserts response shape (keys, types) against a fixture. Use `responses` or `httpx.MockTransport`; do not start the C++ server. Reconcile `api-specification.md` with the fixtures so they agree. Add a CI job that runs `pytest tests/remote` on Linux.

### PR-08 — Remote JS unit tests
- **Files:** new `tests/remote-js/security-config.test.js`, `package.json`, `.github/workflows/code-quality.yml`.
- **Scope:** Jest tests for `generateCSRFToken`, `validateRedirect`, rate limiter, and session timeout in `Remote/security-config.js`. Audit (`CODE_QUALITY_AUDIT.md` §3.1) provides the test matrix.
- **Acceptance:** `npm test` passes; CI runs it.
- **Prompt:**
  > Implement the test plan from `CODE_QUALITY_AUDIT.md` section 3.1 in `tests/remote-js/security-config.test.js` using Jest. Add a minimal `package.json` (jest only, no production deps). Add a `js-tests` job to `.github/workflows/code-quality.yml` running on `ubuntu-latest`. Do not refactor `Remote/security-config.js` in this PR — if a test fails, mark it `it.skip` with a TODO referencing the line.

---

## Phase 2 — Safe fences (legacy isolation)

> **Goal of this phase:** make subsequent rewrites possible without touching MFC/UI code on every PR. Each fence PR adds *interfaces and seams*, not implementation changes.

### PR-09 — Header-only seams for protocol parsers
- **Files:** new `Envy/include/protocol/{btpacket,edpacket,g2packet}_view.h` (proposed).
- **Scope:** Pure-`std` views over packet buffers exposing the parsing API used elsewhere. Existing `.cpp` files include the new headers and continue to compile. No removal of existing public methods.
- **Acceptance:** VS solution builds. No call sites changed except `#include`.
- **Prompt:**
  > Without changing behavior, extract the parser-only interface of `BTPacket`, `EDPacket`, `G2Packet` into header-only `*_view.h` files under `Envy/include/protocol/`. The originals continue to be the implementation; the new headers expose the read-side API for testability. Update the `.vcxproj` filters to add the new headers. Do not modify any `.cpp` file logic. Confirm the VS solution still builds with msbuild on Windows (note in PR if you cannot run it locally).

### PR-10 — Plugin ABI version + compatibility policy
- **Files:** `Plugins/Common/`, new `docs/20_arch/plugin-abi.md`.
- **Scope:** Define a `PLUGIN_ABI_VERSION` macro (start at 1), publish the policy: when the host bumps it, what guarantees break, deprecation window.
- **Acceptance:** Policy doc merged; macro defined; no plugin behavior changed.
- **Prompt:**
  > Read `Plugins/Common/` to identify the plugin entry-point ABI. Add a `PLUGIN_ABI_VERSION` macro (value `1`) in the shared header. Write `docs/20_arch/plugin-abi.md` covering: how a host bumps the version, what binary guarantees a plugin gets within a major version, deprecation window in days, how to mark deprecated entry points. Do not edit any concrete plugin.

### PR-11 — Core/UI seam for transfer engine (interfaces only)
- **Files:** new `Envy/include/core/{transfer,download,upload}_iface.h`.
- **Scope:** Declare abstract interfaces matching the public methods that UI code currently calls on `CDownload`, `CUpload`, etc. Existing classes get `: public ITransfer` etc. — no method bodies move.
- **Acceptance:** Solution builds. UI code unchanged. No virtual dispatch added in hot paths.
- **Prompt:**
  > Identify the public methods on `CDownload` and `CUpload` (Envy/Download*.h, Envy/Upload*.h) that are called from `Wnd*` / `Dlg*` / `Ctrl*` files. Declare matching abstract interfaces `ITransfer`, `IDownloadInfo`, `IUploadInfo` in `Envy/include/core/`. Make existing classes inherit them with no behavior change. Do not migrate any call site to the interface yet — that's a later PR. Document the hot-path methods you deliberately did NOT make virtual.

### PR-12 — Security/filtering namespace isolation
- **Files:** `Envy/Security*.{cpp,h}`, new `Envy/include/security/`.
- **Scope:** Wrap security/filtering classes in `namespace envy::security` (file-by-file) and list explicit external dependencies in a header comment block.
- **Acceptance:** Build green; symbol surface unchanged externally via `using` aliases.
- **Prompt:**
  > For files matching `Envy/Security*.{cpp,h}`, place public types under `namespace envy::security`. Preserve existing global-scope identifiers via `using` aliases in the headers so call sites compile unchanged. At the top of each header, list "External dependencies:" with file paths. No logic changes. Solution must still build.

---

## Phase 3 — Modernization slices

> Independent across modules. Each slice is its own PR, can run in parallel once Phase 2 is merged.

### PR-13 — Replace unsafe string ops in core
- **Files:** Audit-driven hit list (drop from `SECURITY_AUDIT.md` section 1).
- **Scope:** Replace `sprintf`/`strcpy`/`sscanf` with bounded variants or `CString` formatters. One file per commit if possible.
- **Acceptance:** Static-analysis warnings on touched files drop to zero.
- **Prompt:**
  > Take the file list from `SECURITY_AUDIT.md` section 1 (sprintf/sscanf safety). For each file, replace unsafe calls with the bounded equivalent (`StringCchPrintfW`, `_snwprintf_s`, etc.) preserving exact width/precision/encoding. Add a unit test in `tests/` exercising a representative input per file. One file per commit. Do not introduce new helpers or wrappers — use the platform-provided bounded calls.

### PR-14 — MiniUPnP refresh + NAT regression matrix
- **Files:** `Services/MiniUPnP/`, `tests/perf/`.
- **Scope:** Vendor newer release; rebuild; run NAT-traversal regression matrix (with-/without-UPnP, IPv4/IPv6 if available).
- **Acceptance:** Functional parity on documented scenarios; perf delta in `BASELINE.md`.
- **Prompt:**
  > Read the dependency register entry for MiniUPnP (PR-02). Vendor the latest stable upstream release into `Services/MiniUPnP/`, preserving the build-tree integration (preserve `.vcxproj` and any local patches — list patches at the top of a `LOCAL_CHANGES.md`). Rebuild and run a regression matrix of: UPnP on/off, IPv4 only, IPv6 if available. Update `docs/40_quality/performance/BASELINE.md` with delta. Do NOT change any caller; the goal is drop-in upgrade.

### PR-15 — UnRAR refresh
- Same shape as PR-14, scoped to `Services/UnRAR/`. Regression matrix: encrypted, multi-volume, recovery-record archives.
- **Prompt:** Same template as PR-14 with `Services/UnRAR/` substituted, and an archive-format matrix in the regression run.

### PR-16 — Python 2 → Python 3 migration
- **Files:** `Services/LibUTP/parse_log.py`.
- **Scope:** Run `2to3`, manual review, replace `iteritems`, `print >>sys.stderr`, raw-string SVN paths. Add a smoke test.
- **Acceptance:** Script runs under Python 3.11+; smoke test in CI.
- **Prompt:**
  > Migrate `Services/LibUTP/parse_log.py` from Python 2 to Python 3 (target 3.11+). Apply the migration described in `CODE_QUALITY_AUDIT.md` section 5.1: `print()`, `dict.items()`, `pathlib.Path`, file-redirect via `print(..., file=sys.stderr)`. Update the shebang. Add a one-line CI step under `.github/workflows/code-quality.yml` that runs `python3 -c "import ast; ast.parse(open('Services/LibUTP/parse_log.py').read())"` plus the script against a small fixture log under `tests/fixtures/utp/`.

### PR-17 — `Remote/envy-modern.js` → ES modules + DI for security
- **Files:** `Remote/envy-modern.js`, `Remote/security-config.js`, the HTML templates that load them.
- **Scope:** Apply the dependency-injection sketch in `CODE_QUALITY_AUDIT.md` §1.3. No new behavior.
- **Acceptance:** PR-08 tests still green; CSRF behavior unchanged on the live page.
- **Prompt:**
  > Apply the refactor described in `CODE_QUALITY_AUDIT.md` sections 1.1–1.3: convert `Remote/envy-modern.js` and `Remote/security-config.js` to ES modules; introduce a `SecurityService` class injected into `EnvyAPI`. Update the `<script type="module">` tags in the HTML templates that load them. Existing tests from PR-08 must still pass — if they break, the refactor is wrong, not the tests. Don't add fallbacks for the old global-scope API; remove `window.EnvyRemote` if and only if no template still calls it (grep first).

### PR-18 — Debounce activity tracking + DOM cache discipline
- **Files:** `Remote/security-config.js`, `Remote/envy-modern.js`.
- **Scope:** Implement the rAF-debounced activity tracker and a single `cache` lookup pattern (audit §2.1, §2.2).
- **Acceptance:** PR-08 tests still green; manual smoke test on Chromium DevTools shows no per-frame `mousemove` work.
- **Prompt:**
  > Apply `CODE_QUALITY_AUDIT.md` §2.1 (DOM-cache discipline) and §2.2 (rAF-debounced activity tracking) verbatim. Run the PR-08 Jest suite; it must remain green. Add a new test asserting that `lastActivity` is updated at most once per animation frame even with 100 synthetic mousemove events.

### PR-19 — Logging façade
- **Files:** new `Envy/include/diag/log.h`, `Remote/log.js`.
- **Scope:** Single API for native and Remote: levels, structured fields, opt-in file sink. Existing call sites can be migrated incrementally; this PR only ships the API + one converted module as proof.
- **Acceptance:** One module migrated; rest unchanged.
- **Prompt:**
  > Define a logging façade in `Envy/include/diag/log.h` with levels (trace/debug/info/warn/error), structured key=value fields, and a default sink that matches Envy's current logging output byte-for-byte. Pick one mid-size source file (~300 LOC, no UI) and migrate its log calls to the new façade as a proof. Do not migrate other files. Add a unit test that captures structured output and asserts field ordering.

---

## Phase 4 — Build convergence (CMake parity)

> Only start once Phases 1–3 critical PRs are merged. Visual Studio remains authoritative until PR-22 is verified on CI.

### PR-20 — CMake covers `Services/` vendored libs
- **Scope:** Each vendored lib gets a `CMakeLists.txt` mirroring the `.vcxproj` minus Windows-only resource compilation.
- **Acceptance:** `cmake --build build --target <lib>` succeeds on Windows; produces matching object files (smoke comparison of exported symbols).
- **Prompt:**
  > For each subdirectory under `Services/`, write a `CMakeLists.txt` that compiles the same source set as the corresponding `.vcxproj` for x64 Release. Skip resource compilation. Add a top-level option `ENVY_BUILD_SERVICES` (default `OFF`). Add a CI job (Windows runner) that builds with `-DENVY_BUILD_SERVICES=ON` and dumps exported symbols via `dumpbin /exports` for diff against the MSBuild artifact. Do not touch the VS solution.

### PR-21 — CMake covers Envy core (no UI)
- **Scope:** Core protocol/library/security `.cpp` files only. UI files (`Wnd*`, `Dlg*`, `Ctrl*`, `Page*`) explicitly excluded.
- **Acceptance:** Static lib produced; existing tests link against it.
- **Prompt:**
  > Add a CMake target `envy_core` that compiles Envy's core sources, excluding `Envy/Wnd*.cpp`, `Envy/Dlg*.cpp`, `Envy/Ctrl*.cpp`, `Envy/Page*.cpp`. Use the interfaces from PR-11 to break UI-leaking includes — if a core file `#include`s an MFC UI header, fix the include first (preferably forward-declare). Re-link the existing tests against `envy_core` to validate. The VS solution must still build unchanged.

### PR-22 — CMake covers UI + final solution parity
- **Scope:** UI files added behind `WIN32 AND MFC_FOUND` guard. Final compare: a release build through CMake produces a working `Envy.exe` byte-for-byte close to the MSBuild artifact (sizes within 5%).
- **Acceptance:** Either parity reached, or remaining gaps documented and a follow-up issue created. Do not declare CMake authoritative yet.
- **Prompt:**
  > Add UI sources to a CMake target `envy_app` guarded by `WIN32 AND MFC_FOUND` (require `find_package(MFC)`-style detection or VS-generator-only). Build `Envy.exe`. Compare its size and exported imports against the MSBuild artifact. Document gaps in `docs/10_dev/build.md`. Do NOT change `CLAUDE.md` to remove the "VS authoritative" note in this PR — that's PR-26's call.

---

## Phase 5 — Cleanup & release hygiene

### PR-23 — Archive legacy `.vcproj`
- **Prompt:**
  > Find every `*.vcproj` (legacy VS2008 format) in the repo and move them to `archive/legacy-projects/` preserving relative paths. Update any documentation that references them. Do NOT delete `.vcxproj` files. Do NOT touch the active `Visual Studio/Envy.sln`.

### PR-24 — Consolidate duplicate roadmap/status docs
- **Prompt:**
  > List every file under `docs/` that contains "roadmap" or "status" content. Identify duplicates with `diff -u` summaries. Keep `docs/10_dev/roadmap.md` and `docs/10_dev/status.md` as canonical. Replace each duplicate with a one-line "moved to …" stub (matching the existing style in `docs/ROADMAP.md`). Update any cross-links. Do NOT change content of the canonical docs.

### PR-25 — `THIRD_PARTY_LICENSES.md` + attribution table
- **Prompt:**
  > Build `THIRD_PARTY_LICENSES.md` at the repo root listing every entry from the dependency register (PR-02), with: component, version, SPDX identifier, license file path inside the vendored tree, attribution text required by the license. Cross-link from `README.md`.

### PR-26 — Tag plugin ABI v1, ship SBOM in release artifacts
- **Prompt:**
  > Bump `PLUGIN_ABI_VERSION` to `1` (already 1; assert it in the release notes). Update `.github/workflows/release.yml` so the release pipeline attaches `THIRD_PARTY_LICENSES.md`, the dependency register, and the CycloneDX SBOM as release assets. Add an entry to `CHANGELOG.md` under the next version heading documenting the new release contents.

---

## Tracking

- One GitHub issue per PR, all labeled `legacy-refactor`, milestone `Legacy Refactor v1`.
- Update `docs/DEVELOPMENT_PLAN.md` "Decisions Log" when a phase completes.
- If a PR's scope grows beyond ~600 LOC, split it before requesting review.

## Stop Conditions
- A PR-13 file rewrite uncovers a behavioral bug → freeze PR-13, file an incident, fix in a dedicated PR before resuming.
- PR-20/21/22 reveals undocumented MFC linkage that requires touching > 30 files → freeze Phase 4, schedule an architecture spike.
- Any audit finding marked "Critical" surfaces during refactor → bubble to top of queue, suspend non-blocking PRs.
