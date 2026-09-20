# Developer Guide

Status: active
Last updated: 2026-09-20
Scope: Supported setup, build, development workflow, and pull-request process.
Source of truth: `AGENTS.md`, `Visual Studio/Envy.sln`, and live GitHub rulesets/workflows.

## Prerequisites

- **Visual Studio 2026** (18.x) with MSVC **v145 / 14.50**
- Desktop development with C++, MFC, ATL, Spectre-mitigated libraries
- Windows 10/11 SDK
- Git 2.30+
- vcpkg restored through the repository scripts

Language/platform policy:

- First-party targets: **C++20**
- Legacy plugins explicitly configured that way: **C++17**
- Windows x64: primary supported build
- Win32: legacy Stage A
- Windows ARM64: **planned / unsupported**
- Linux/macOS: planned for portable-core/headless work only; not supported
  product targets today

The full MFC application is authoritative through
`Visual Studio\Envy.sln`. CMake is for the portable slice where documented;
do not treat it as a replacement full-app build.

## Initial setup

```text
git clone https://github.com/Mika3578/Envy.git
cd Envy
scripts\bootstrap-vcpkg.cmd
rem Restore Win32 too when needed:
scripts\bootstrap-vcpkg.cmd -Triplet x86-windows-static
```

Open `Visual Studio\Envy.sln` and select the required configuration/platform.

## Development workflow

### 1. Preflight before editing

Read root `AGENTS.md` and perform its mandatory preflight:

- inspect current `develop`, open PRs/issues, recent commits and CI/rulesets;
- verify that the work is not already fixed, in progress, obsolete, or duplicate;
- inspect nearby code/tests and relevant canonical docs;
- for protocol/security work, consult primary specifications before reference
  implementations;
- define the smallest change and its verification plan.

### 2. Synchronize `develop`

```bash
git fetch origin
git checkout develop
git pull --ff-only origin develop
```

Never commit directly to `develop`, `main`, or `legacy`.

### 3. Create a functional branch

```bash
git checkout -b feat/short-kebab-summary
```

Use the prefixes allowed by `AGENTS.md` such as `feat/`, `fix/`,
`docs/`, `refactor/`, `perf/`, `test/`, `build/`, `ci/`,
`chore/`, `hotfix/`, or `security/`. Never use tool/agent prefixes such
as `cursor/`, `claude/`, or `copilot/`.

### 4. Implement and verify

Match the surrounding MFC style and preserve legacy file encoding. Do not
bulk-format unrelated code.

Useful local gates:

```powershell
.\scripts\ci-fast.ps1
.\scripts\ci-verify.ps1
# broader Windows verification when required:
.\scripts\ci-verify.ps1 -Full
```

For protocol/parser changes, add focused regression coverage including
relevant nominal, boundary, zero, truncated, malformed, overflow, and unknown
opcode/extension cases.

### 5. Pull request

Push only the work branch and open a **draft PR to `develop`** using
`.github/pull_request_template.md`. Include exact validation performed,
validation not performed, environment limitations, compatibility/wire impact,
risk, rollback, and relevant source/spec evidence.

After pushes, follow `AGENTS.md` for CI monitoring. Do not use arbitrary
sleep/poll loops.

The target merge policy is at least one GitHub `APPROVED` review. In this
solo-maintainer repository, GitHub Copilot Code Review may satisfy the review
gate only when repository settings explicitly allow its approvals to count and
GitHub records an actual `APPROVED` review. All required checks and review
threads must still be satisfied.

## Build

Authoritative full-app Release x64 example:

```cmd
msbuild "Visual Studio\Envy.sln" /m /p:Configuration=Release /p:Platform=x64 ^
  /p:PlatformToolset=v145 /p:WindowsTargetPlatformVersion=10.0 ^
  /p:VcpkgEnableManifest=true /p:VcpkgTriplet=x64-windows-static
```

CI also verifies Win32 where required. See [build.md](build.md) for bootstrap,
runner, and troubleshooting details.

## Testing and analysis

Use the closest relevant tests for the files touched. CI supplies the
authoritative Windows builds plus required quality/security checks. Local Linux
or Cursor Cloud checks are useful for portable tooling, clang-format/tidy,
cppcheck and Remote JS tests, but they do **not** validate the MFC application.

See:

- [Testing](../TESTING.md)
- [CI audit](CI_AUDIT_2026-09.md)
- [DevSecOps map](devsecops-envy.md)
- [Standards](standards.md)

## Documentation

Update documentation in the same PR when behavior, setup, API, protocol,
security, build/CI, or troubleshooting changes. Keep one canonical location per
topic and do not claim support without code/tests/runtime evidence.

## Related

- [AGENTS.md](../../AGENTS.md)
- [Contributing](contributing.md)
- [Status](status.md)
- [Architecture](../20_arch/architecture.md)
- [Cursor index](../00_index/CURSOR_INDEX.md)
