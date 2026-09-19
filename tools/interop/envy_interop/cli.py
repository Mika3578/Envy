"""CLI entry used by tools/interop/run.py and python -m envy_interop."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path
from typing import Optional, Sequence

from .config import build_arg_parser, config_from_args
from .golden import ingest_hello
from .runner import run_harness


def repo_root_from_here() -> Path:
    return Path(__file__).resolve().parents[3]


def run_self_tests() -> int:
    interop_root = Path(__file__).resolve().parents[1]
    if str(interop_root) not in sys.path:
        sys.path.insert(0, str(interop_root))
    tests_dir = interop_root / "tests"
    suite = unittest.defaultTestLoader.discover(
        str(tests_dir), pattern="test_*.py", top_level_dir=str(interop_root)
    )
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    return 0 if result.wasSuccessful() else 1


def main(argv: Optional[Sequence[str]] = None) -> int:
    argv_list = list(argv) if argv is not None else sys.argv[1:]
    parser = build_arg_parser()
    ns, _unknown = parser.parse_known_args(argv_list)
    if ns.self_test:
        return run_self_tests()

    repo_root = repo_root_from_here()
    cfg = config_from_args(argv_list, repo_root)

    if ns.ingest_hello:
        run_dir = cfg.artifact_dir or (repo_root / "tools" / "interop" / "artifacts" / "ingest")
        dest = Path(run_dir) / "hello-ingest"
        ingest_hello(
            Path(ns.ingest_hello),
            dest,
            reference_client=cfg.resolved_reference_client() or "unspecified",
            reference_version=cfg.reference_version or "unspecified",
            direction=ns.ingest_direction or "recv",
        )
        print(f"Wrote sanitized Hello candidate under {dest}")
        return 0

    payload = run_harness(cfg)
    summary = payload.get("artifact_dir", "")
    print(f"Wrote {summary}/run-summary.json")
    failed = [item for item in payload["scenarios"] if item["result"] == "FAIL"]
    return 1 if failed else 0
