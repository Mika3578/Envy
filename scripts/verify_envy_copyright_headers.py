#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Verify Envy getenvy.com banner lines use UTF-8 copyright (C2 A9).

Also flags obvious comment-line mojibake (U+FFFD, doubled UTF-8 punctuation).
"""

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
	return [
		ROOT / line
		for line in out.splitlines()
		if line.endswith((".cpp", ".h", ".hpp", ".inl", ".c"))
	]


def comment_line_mojibake_issues(data: bytes) -> list[str]:
	issues: list[str] = []
	for line_number, line in enumerate(data.splitlines(), start=1):
		if not line.lstrip().startswith(b"//"):
			continue
		if b"\xef\xbf\xbd" in line:
			issues.append(
				f"line {line_number}: U+FFFD replacement character in // comment"
			)
		if b"\xe2\x80\xe2\x80" in line:
			issues.append(
				f"line {line_number}: doubled UTF-8 punctuation in // comment (mojibake)"
			)
	return issues


def verify_file(path: Path) -> list[str]:
	data = path.read_bytes()
	issues: list[str] = []
	rel = path.relative_to(ROOT).as_posix()
	if data.startswith((b"\xff\xfe", b"\xfe\xff")):
		return []
	issues.extend(comment_line_mojibake_issues(data))
	for line_number, line in enumerate(data.splitlines(), start=1):
		if b"getenvy.com)" not in line or b"20" not in line:
			continue
		if (
			GOOD_COPYRIGHT_MARKER in line
			or b"getenvy.com) (C)" in line
			or b"getenvy.com) - " in line
		):
			continue
		if any(marker in line for marker in BAD_COPYRIGHT_MARKERS):
			issues.append(f"line {line_number}: legacy copyright marker byte sequence")
		else:
			issues.append(
				f"line {line_number}: getenvy.com banner with year "
				"but no UTF-8 © marker"
			)
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
	print("OK: Envy getenvy.com copyright banner and comment mojibake checks passed.", file=sys.stderr)
	return 0


if __name__ == "__main__":
	raise SystemExit(main())
