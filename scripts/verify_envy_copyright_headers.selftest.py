#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Regression checks for normalize/verify copyright header tooling."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _load_module(name: str, path: Path):
	spec = importlib.util.spec_from_file_location(name, path)
	mod = importlib.util.module_from_spec(spec)
	assert spec.loader is not None
	spec.loader.exec_module(mod)
	return mod


def main() -> int:
	normalize = _load_module(
		"normalize_envy_copyright_headers",
		ROOT / "scripts" / "normalize_envy_copyright_headers.py",
	)
	verify = _load_module(
		"verify_envy_copyright_headers",
		ROOT / "scripts" / "verify_envy_copyright_headers.py",
	)

	tmp_path = ROOT / "scripts" / ".copyright_selftest_tmp"
	tmp_path.mkdir(exist_ok=True)
	try:
		utf8_good = tmp_path / "Good.cpp"
		utf8_good.write_bytes(
			b"// (getenvy.com) \xc2\xa9 2020-2026 Envy Development Team\r\n"
			b"void f() {}\r\n"
		)
		if verify.verify_file(utf8_good):
			print("FAIL: valid UTF-8 banner should pass verify", file=sys.stderr)
			return 1

		utf8_bad = tmp_path / "Bad.cpp"
		utf8_bad.write_bytes(
			b"// (getenvy.com) \x9d 2020-2026 Envy Development Team\r\n"
			b"void f() {}\r\n"
		)
		if not verify.verify_file(utf8_bad):
			print("FAIL: legacy 0x9d banner should fail verify", file=sys.stderr)
			return 1

		if not normalize.normalize_file(utf8_bad, dry_run=False):
			print("FAIL: normalizer should fix legacy banner bytes", file=sys.stderr)
			return 1
		if verify.verify_file(utf8_bad):
			print("FAIL: normalized file should pass verify", file=sys.stderr)
			return 1
		if normalize.normalize_file(utf8_bad, dry_run=False):
			print("FAIL: second normalize pass should be idempotent", file=sys.stderr)
			return 1

		legacy = tmp_path / "Legacy.cpp"
		legacy.write_bytes(
			b"// (getenvy.com) \xa9 2020-2026 Envy Development Team\r\n"
			b"void g() {}\r\n"
		)
		if not normalize.normalize_file(legacy, dry_run=False):
			print("FAIL: legacy-encoded banner should be normalized", file=sys.stderr)
			return 1
		data = legacy.read_bytes()
		if b"getenvy.com) (C)" not in data:
			print("FAIL: non-UTF-8 source should keep ASCII (C) banner", file=sys.stderr)
			return 1
		if b"getenvy.com) \xc2\xa9" in data:
			print("FAIL: non-UTF-8 source must not get UTF-8 copyright bytes", file=sys.stderr)
			return 1

		print("OK: verify_envy_copyright_headers selftest passed.", file=sys.stderr)
		return 0
	finally:
		for child in tmp_path.iterdir():
			child.unlink()
		tmp_path.rmdir()


if __name__ == "__main__":
	raise SystemExit(main())
