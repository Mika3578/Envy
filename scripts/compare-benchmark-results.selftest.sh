#!/usr/bin/env bash
# Self-test for scripts/compare-benchmark-results.py
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

BASE="$TMP/base.json"
HEAD="$TMP/head.json"

cat >"$BASE" <<'EOF'
{
  "schema_version": "1",
  "environment": {"architecture": "x64", "configuration": "Release", "platform": "windows", "toolset": "1950", "compiler": "msvc"},
  "benchmarks": [
    {"group": "buffer", "name": "append/1KiB", "iterations_per_sample": 1, "sample_count": 3, "median_ns": 1000, "min_ns": 900, "max_ns": 1100, "bytes_per_sample": 1024, "ops_per_sample": 1, "throughput_bytes_per_sec": 0, "checksum_sink": 1},
    {"group": "fileio", "name": "write/256KiB", "iterations_per_sample": 1, "sample_count": 3, "median_ns": 3000, "min_ns": 2800, "max_ns": 3200, "bytes_per_sample": 262144, "ops_per_sample": 1, "throughput_bytes_per_sec": 0, "checksum_sink": 4}
  ]
}
EOF

cat >"$HEAD" <<'EOF'
{
  "schema_version": "1",
  "environment": {"architecture": "x64", "configuration": "Release", "platform": "windows", "toolset": "1950", "compiler": "msvc"},
  "benchmarks": [
    {"group": "buffer", "name": "append/1KiB", "iterations_per_sample": 1, "sample_count": 3, "median_ns": 2000, "min_ns": 1800, "max_ns": 2200, "bytes_per_sample": 1024, "ops_per_sample": 1, "throughput_bytes_per_sec": 0, "checksum_sink": 2},
    {"group": "hash", "name": "sha1/256B", "iterations_per_sample": 1, "sample_count": 3, "median_ns": 500, "min_ns": 400, "max_ns": 600, "bytes_per_sample": 256, "ops_per_sample": 1, "throughput_bytes_per_sec": 0, "checksum_sink": 3}
  ]
}
EOF

python3 "$ROOT/scripts/compare-benchmark-results.py" "$BASE" "$HEAD" | grep -q "buffer/append/1KiB"
python3 "$ROOT/scripts/compare-benchmark-results.py" "$BASE" "$HEAD" | grep -q "missing base"
python3 "$ROOT/scripts/compare-benchmark-results.py" "$BASE" "$HEAD" | grep -q "missing head"

if OUTPUT="$(python3 "$ROOT/scripts/compare-benchmark-results.py" "$BASE" "$TMP/missing.json" 2>&1)"; then
	echo "expected failure for missing file" >&2
	exit 1
elif [[ "$OUTPUT" != *"results file not found"* ]]; then
	echo "expected 'results file not found', got: $OUTPUT" >&2
	exit 1
fi

echo "compare-benchmark-results self-test passed"
