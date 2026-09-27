# Runtime benchmarks (Issue #111)

EnvyBenchmarks is a **separate** Release x64 console executable for reproducible
performance baselines. It is not part of `EnvyTests` and does not assert timing
thresholds.

## Purpose

- Measure current hot-path behavior **without changing production code**.
- Emit human-readable summaries and machine-readable JSON for local or CI comparison.
- Provide evidence infrastructure for follow-ups (#112–#114, #343–#345).

Google Benchmark was **not** adopted: vcpkg/maintenance and MSVC/MFC linkage for
production `CBuffer` outweigh the benefit for this first slice. The harness is
first-party C++17 with `std::chrono::steady_clock`.

## Build (authoritative: Visual Studio)

```cmd
msbuild "Visual Studio\Envy.sln" /m /p:Configuration=Release /p:Platform=x64 ^
  /p:PlatformToolset=v145 /p:WindowsTargetPlatformVersion=10.0 ^
  /t:EnvyBenchmarks
```

Or build the project directly:

```cmd
msbuild "benchmarks\EnvyBenchmarks.vcxproj" /p:Configuration=Release /p:Platform=x64
```

Output: `benchmarks\Release x64\EnvyBenchmarks.exe` (requires `HashLib.dll` copied
next to the exe by the project post-build step).

**CMake:** HashLib remains buildable via the portable CMake slice; EnvyBenchmarks is
**MSBuild-only** today (links production `Envy/Buffer.cpp` with a minimal MFC static
PCH). Do not claim cross-platform benchmark support until a dedicated CMake target
exists.

## Run

```cmd
benchmarks\Release x64\EnvyBenchmarks.exe
benchmarks\Release x64\EnvyBenchmarks.exe --list
benchmarks\Release x64\EnvyBenchmarks.exe --filter buffer
benchmarks\Release x64\EnvyBenchmarks.exe --json results.json
benchmarks\Release x64\EnvyBenchmarks.exe --ci --json ci-results.json
benchmarks\Release x64\EnvyBenchmarks.exe --self-test
```

Invalid arguments print an error and exit non-zero.

## Methodology

1. Fixed deterministic payloads (documented LCG seed `0xC0FFEE` for buffer workloads).
2. Warmup samples (discarded) then multiple timed samples per case.
3. Each timed sample runs a fixed **batch** (`iterations_per_sample`) of operations.
4. Report **median** nanoseconds per sample batch; optional min/max retained in JSON.
5. Throughput (`throughput_bytes_per_sec`) is derived from median duration and bytes
   touched per sample — not a separate measurement.
6. A `checksum_sink` records workload side effects so the compiler cannot delete the
   timed work.

Hosted GitHub Actions runners are noisy. Treat small percentage swings as
informational only. Do not use hosted CI as a blocking regression gate.

## Compare base vs head (offline)

After producing two JSON files (e.g. from `develop` and a feature branch on the
**same machine** when possible):

```bash
python3 scripts/compare-benchmark-results.py base.json head.json
```

The script validates JSON shape, rejects non-finite numerics, caps input size, and
does not execute shell commands or enforce thresholds.

## JSON schema (version 1)

Top-level fields:

| Field | Meaning |
| --- | --- |
| `schema_version` | `"1"` |
| `environment.architecture` | `x64`, `x86`, … |
| `environment.configuration` | `Release` or `Debug` |
| `environment.platform` | `windows` |
| `environment.toolset` | MSVC `_MSC_VER` string |
| `environment.compiler` | `msvc` |
| `benchmarks[]` | Per-case measurements |

Each benchmark entry includes: `group`, `name`, `iterations_per_sample`, `sample_count`,
`median_ns`, `min_ns`, `max_ns`, `bytes_per_sample`, `ops_per_sample`,
`throughput_bytes_per_sec`, `checksum_sink`.

No hostnames, personal paths, or secrets are written.

## Benchmark families in this foundation slice

| Group | Production seam | Notes |
| --- | --- | --- |
| `buffer/*` | `Envy/Buffer.cpp` via `benchmarks/buffer_production_tu.cpp` | append, remove, alternating, packet-like, retained 2 MiB |
| `protocol/*` | `Envy/PacketLengthValidate.h` | BT/ED2K/G1/G2 framing predicates |
| `hash/*` | `HashLib` | SHA-1, MD5, MD4, ED2K, Tiger/TTH file hashing |
| `fileio/*` | Scratch under `%LOCALAPPDATA%\\Envy\\BenchmarkScratch` | sequential read/write, multi-file |

**Not yet measured:** transfer concurrency, lock hold/wait, socket churn, `CTransferFile`
contention (#114), or synthetic scheduler metrics (#343–#345). The JSON schema leaves
room for future fields; this PR only emits metrics actually collected.

## CI

Workflow: `.github/workflows/benchmarks.yml` (informational). It builds Release x64,
runs `--self-test`, then a `--ci` bounded slice, and uploads JSON + summary artifacts.
It is **not** a required branch protection check.

## Future performance PRs

1. Run Release x64 benchmarks locally before/after changes.
2. Attach JSON or summary tables to the PR.
3. Compare with `compare-benchmark-results.py` when you have a trusted baseline file.
4. Keep correctness tests in `EnvyTests`; do not add timing assertions there.
