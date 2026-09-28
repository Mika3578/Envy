#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Normalize Envy source headers to UTF-8 (copyright and common comment punctuation).

Replaces legacy Windows-1252 / invalid UTF-8 bytes on getenvy.com banner lines and
in // comment lines with proper UTF-8 sequences. Intentional ASCII forms are kept:
(getenvy.com) (C) ... and (getenvy.com) - ...
"""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ENVY = ROOT / "Envy"

COPYRIGHT_CANONICAL = b"getenvy.com) \xc2\xa9 "

COPYRIGHT_REPLACEMENTS: tuple[tuple[bytes, bytes], ...] = (
	(b"getenvy.com) \x9d ", COPYRIGHT_CANONICAL),
	(b"getenvy.com) \xa9 ", COPYRIGHT_CANONICAL),
	(b"getenvy.com) \xef\xbf\xbd ", COPYRIGHT_CANONICAL),
	(b"getenvy.com) \xc2\x9d ", COPYRIGHT_CANONICAL),
)

# CP1252 punctuation often found in legacy // comments (not valid UTF-8 as raw bytes).
COMMENT_CP1252_TO_UTF8: tuple[tuple[bytes, bytes], ...] = (
	(b"\x96", b"\xe2\x80\x93"),  # en dash
	(b"\x97", b"\xe2\x80\x94"),  # em dash
	(b"\x91", b"\xe2\x80\x98"),  # left single quote
	(b"\x92", b"\xe2\x80\x99"),  # right single quote
	(b"\x93", b"\xe2\x80\x9c"),  # left double quote
	(b"\x94", b"\xe2\x80\x9d"),  # right double quote
	(b"\x85", b"\xe2\x80\xa6"),  # ellipsis
)


def git_ls_envy_sources() -> list[Path]:
	out = subprocess.check_output(
		["git", "ls-files", "Envy"],
		cwd=ROOT,
		text=True,
	)
	paths: list[Path] = []
	for line in out.splitlines():
		if line.endswith((".cpp", ".h", ".hpp", ".inl", ".c")):
			paths.append(ROOT / line)
	return paths


def is_comment_line(line: bytes) -> bool:
	stripped = line.lstrip()
	return stripped.startswith(b"//")


def normalize_line(line: bytes, fix_comments: bool) -> bytes:
	new_line = line
	if b"getenvy.com)" in new_line and b"20" in new_line:
		if b"getenvy.com) (C)" in new_line:
			pass
		elif b"getenvy.com) - " in new_line or b"getenvy.com) -" in new_line:
			pass
		elif COPYRIGHT_CANONICAL in new_line:
			pass
		else:
			for old, new in COPYRIGHT_REPLACEMENTS:
				if old in new_line:
					new_line = new_line.replace(old, new)
	if fix_comments and is_comment_line(new_line):
		# CP1252 byte replacements must not run on valid UTF-8 (e.g. em dash ends in 0x94).
		try:
			new_line.decode("utf-8")
		except UnicodeDecodeError:
			for old, new in COMMENT_CP1252_TO_UTF8:
				if old in new_line:
					new_line = new_line.replace(old, new)
	return new_line


def normalize_file(path: Path, fix_comments: bool, dry_run: bool) -> bool:
	data = path.read_bytes()
	if data.startswith(b"\xff\xfe") or data.startswith(b"\xfe\xff"):
		return False
	ends_with_nl = data.endswith(b"\n") or data.endswith(b"\r\n")
	# Preserve original newline style per line.
	parts = data.splitlines(keepends=True)
	if not parts and not data:
		return False
	if not parts:
		parts = [data]
	changed = False
	out_parts: list[bytes] = []
	for part in parts:
		fixed = normalize_line(part, fix_comments)
		if fixed != part:
			changed = True
		out_parts.append(fixed)
	if not changed:
		return False
	new_data = b"".join(out_parts)
	if not ends_with_nl and new_data.endswith(b"\n"):
		# splitlines(keepends=True) can drop trailing empty; avoid altering EOF policy.
		pass
	if dry_run:
		return True
	path.write_bytes(new_data)
	return True


def main() -> int:
	parser = argparse.ArgumentParser(description=__doc__)
	parser.add_argument(
		"--no-comment-cp1252",
		action="store_true",
		help="Deprecated compatibility option; comment conversion is opt-in.",
	)
	parser.add_argument(
		"--fix-comment-cp1252",
		action="store_true",
		help="Also convert CP1252 punctuation in // comment lines.",
	)
	parser.add_argument(
		"--dry-run",
		action="store_true",
		help="Report files that would change without writing.",
	)
	args = parser.parse_args()
	fix_comments = args.fix_comment_cp1252 and not args.no_comment_cp1252

	changed: list[str] = []
	for path in git_ls_envy_sources():
		if not path.is_file():
			continue
		if normalize_file(path, fix_comments, args.dry_run):
			changed.append(str(path.relative_to(ROOT)).replace("\\", "/"))

	for rel in sorted(changed):
		print(rel)
	print(f"{'Would change' if args.dry_run else 'Changed'} {len(changed)} file(s).", file=sys.stderr)
	return 0


if __name__ == "__main__":
	raise SystemExit(main())
