#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Verify Envy getenvy.com banner lines use UTF-8 copyright (C2 A9)."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

BAD_COPYRIGHT_MARKERS = (
	b"getenvy.com) \x9d ",
	b"getenvy.com) \xa9 ",
	b"getenvy.com) \xef\xbf\xbd ",
	b"getenvy.com) \xc2\x9d ",
)

GOOD_COPYRIGHT_MARKER = b"getenvy.com) \xc2\xa9 "


def git_ls_envy_sources() -> list[Path]:
	out = subprocess.check_output(["git", "ls-files", "Envy"], cwd=ROOT, text=True)
	return [ROOT / line for line in out.splitlines() if line.endswith((".cpp", ".h", ".inl", ".c"))]


def verify_file(path: Path) -> list[str]:
	data = path.read_bytes()
	issues: list[str] = []
	rel = path.relative_to(ROOT).as_posix()
	has_banner = b"getenvy.com)" in data
	if not has_banner:
		return []
	if b"getenvy.com) (C)" in data or b"getenvy.com) - " in data:
		return []
	if GOOD_COPYRIGHT_MARKER in data:
		return []
	for marker in BAD_COPYRIGHT_MARKERS:
		if marker in data:
			issues.append("legacy copyright marker byte sequence")
	if issues:
		return [f"{rel}: {msg}" for msg in issues]
	# Banner without ©/(C)/- (e.g. URL-only line) is allowed.
	for line in data.splitlines():
		if b"getenvy.com)" in line and b"20" in line:
			if GOOD_COPYRIGHT_MARKER not in line and b"(C)" not in line and b") - " not in line:
				issues.append("getenvy.com banner with year but no UTF-8 © marker")
			break
	return [f"{rel}: {msg}" for msg in issues]


def main() -> int:
	failures: list[str] = []
	for path in git_ls_envy_sources():
		if path.is_file():
			failures.extend(verify_file(path))
	if failures:
		for msg in failures[:200]:
			print(msg, file=sys.stderr)
		if len(failures) > 200:
			print(f"... and {len(failures) - 200} more", file=sys.stderr)
		print(f"FAILED: {len(failures)} issue(s).", file=sys.stderr)
		return 1
	print("OK: Envy copyright / comment encoding checks passed.", file=sys.stderr)
	return 0


if __name__ == "__main__":
	raise SystemExit(main())
