#!/usr/bin/env python3
"""Compare two Envy benchmark JSON result files (base vs head).

Safe, offline comparison only — does not execute benchmark binaries or shell out.
"""

from __future__ import annotations

import argparse
import json
import math
import os
import sys
from typing import Any, Dict, List, Tuple


MAX_FILE_BYTES = 8 * 1024 * 1024


def validate_results_path(path: str) -> None:
    if not path or len(path) > 4096:
        raise ValueError("invalid path length")
    if ".." in path:
        raise ValueError("path traversal in results path")
    if os.path.basename(path) in ("", ".", ".."):
        raise ValueError("invalid results filename")


def load_document(path: str) -> Dict[str, Any]:
    validate_results_path(path)
    with open(path, "rb") as f:
        data = f.read(MAX_FILE_BYTES + 1)
    if len(data) > MAX_FILE_BYTES:
        raise ValueError(f"file too large: {path}")
    text = data.decode("utf-8")
    doc = json.loads(text)
    if not isinstance(doc, dict):
        raise ValueError("root must be an object")
    return doc


def bench_key(entry: Dict[str, Any]) -> str:
    group = entry.get("group")
    name = entry.get("name")
    if not isinstance(group, str) or not isinstance(name, str):
        raise ValueError("benchmark group/name must be strings")
    return f"{group}/{name}"


def parse_benchmarks(doc: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    items = doc.get("benchmarks")
    if not isinstance(items, list):
        raise ValueError("benchmarks must be an array")
    out: Dict[str, Dict[str, Any]] = {}
    for item in items:
        if not isinstance(item, dict):
            raise ValueError("benchmark entry must be an object")
        key = bench_key(item)
        median = item.get("median_ns")
        if not isinstance(median, (int, float)) or not math.isfinite(float(median)):
            raise ValueError(f"invalid median_ns for {key}")
        out[key] = item
    return out


def format_ns(value: float) -> str:
    return f"{value / 1e6:.4f} ms"


def compare(base_path: str, head_path: str) -> int:
    base_doc = load_document(base_path)
    head_doc = load_document(head_path)
    base = parse_benchmarks(base_doc)
    head = parse_benchmarks(head_doc)

    keys = sorted(set(base.keys()) | set(head.keys()))
    print(f"{'Benchmark':<40} {'Base':>14} {'Head':>14} {'Delta':>14}")
    print("-" * 86)

    missing = 0
    for key in keys:
        if key not in base:
            print(f"{key:<40} {'—':>14} {'present':>14} {'missing base':>14}")
            missing += 1
            continue
        if key not in head:
            print(f"{key:<40} {'present':>14} {'—':>14} {'missing head':>14}")
            missing += 1
            continue
        b = float(base[key]["median_ns"])
        h = float(head[key]["median_ns"])
        delta = h - b
        print(f"{key:<40} {format_ns(b):>14} {format_ns(h):>14} {format_ns(delta):>14}")

    if missing:
        print(f"\nNote: {missing} benchmark name(s) present in only one file.")
    return 0


def main(argv: List[str]) -> int:
    parser = argparse.ArgumentParser(description="Compare Envy benchmark JSON results")
    parser.add_argument("base", help="Baseline JSON results")
    parser.add_argument("head", help="Head JSON results")
    args = parser.parse_args(argv)
    try:
        return compare(args.base, args.head)
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
