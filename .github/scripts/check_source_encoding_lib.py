#!/usr/bin/env python3
"""Diff-aware encoding guard for first-party sources (base -> head).

Historical debt on the merge base is tolerated; new corruption in HEAD fails.
See docs/10_dev/development-environment.md and issue #350.
"""
from __future__ import annotations

import os
import subprocess
import sys
from dataclasses import dataclass
from typing import Iterable

FFFD = b"\xef\xbf\xbd"
UTF8_C29D = b"\xc2\x9d"

FIRST_PARTY_PREFIXES = (
    "Envy/",
    "HashLib/",
    "TorrentEnvy/",
    "Unpacker/",
    "SkinBuilder/",
    "Installer/",
)

SOURCE_SUFFIXES = (
    ".cpp",
    ".cxx",
    ".cc",
    ".c",
    ".h",
    ".hpp",
    ".hxx",
    ".inl",
)

ISS_SUFFIX = ".iss"

MOJIBAKE_SEQUENCES = (
    b"\xc3\x82\xc2\xa9",  # Â©
    b"\xc3\x83\xc2\xa9",  # Ã©
    b"\xe2\x80\x99",  # â€™
    b"\xe2\x80\x93",  # â€“
    b"\xe2\x80\x94",  # â€”
)

ENVY_HEADER_PREFIXES = (
    b"// This file is part of Envy (getenvy.com)",
    b"// Portions copyright Shareaza",
)

ISS_COPYRIGHT_MARKERS = (
    b"AppCopyright=",
    b"#define copyright",
)


@dataclass
class FileMetrics:
    fffd: int
    utf8_c29d: int
    c1_controls_utf8: int
    mojibake: dict[bytes, int]
    sensitive_lines: list[bytes]
    iss_copyright_lines: list[bytes]


def git_show(repo_root: str, rev: str, path: str) -> bytes | None:
    r = subprocess.run(
        ["git", "-C", repo_root, "show", f"{rev}:{path}"],
        capture_output=True,
        check=False,
    )
    if r.returncode != 0:
        return None
    return r.stdout


def git_changed_paths(repo_root: str, base: str, head: str) -> list[str]:
    r = subprocess.run(
        [
            "git",
            "-C",
            repo_root,
            "diff",
            "--name-only",
            "--diff-filter=ACMR",
            f"{base}...{head}",
        ],
        capture_output=True,
        check=True,
        text=True,
    )
    return [p for p in r.stdout.splitlines() if p]


def is_scanned_path(path: str) -> bool:
    if not any(path.startswith(p) for p in FIRST_PARTY_PREFIXES):
        return False
    if path.endswith(SOURCE_SUFFIXES):
        return True
    if path.endswith(ISS_SUFFIX):
        return True
    return False


def count_c1_controls_if_valid_utf8(data: bytes) -> int:
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return 0
    return sum(1 for ch in text if 0x80 <= ord(ch) <= 0x9F)


def sensitive_header_lines(data: bytes) -> list[bytes]:
    out: list[bytes] = []
    for line in data.split(b"\n"):
        for prefix in ENVY_HEADER_PREFIXES:
            if line.startswith(prefix):
                out.append(line)
                break
    return out


def iss_copyright_lines(data: bytes) -> list[bytes]:
    out: list[bytes] = []
    for line in data.split(b"\n"):
        for marker in ISS_COPYRIGHT_MARKERS:
            if marker in line:
                out.append(line)
                break
    return out


def analyze_blob(data: bytes) -> FileMetrics:
    return FileMetrics(
        fffd=data.count(FFFD),
        utf8_c29d=data.count(UTF8_C29D),
        c1_controls_utf8=count_c1_controls_if_valid_utf8(data),
        mojibake={seq: data.count(seq) for seq in MOJIBAKE_SEQUENCES},
        sensitive_lines=sensitive_header_lines(data),
        iss_copyright_lines=iss_copyright_lines(data),
    )


def is_corrupt_copyright_line(line: bytes) -> bool:
    if FFFD in line:
        return True
    if UTF8_C29D in line:
        return True
    if b"\x9d" in line and b"\xa9" not in line and b"\xc2\xa9" not in line:
        return True
    for seq in MOJIBAKE_SEQUENCES:
        if seq in line:
            return True
    if b"?" in line and (b"copyright" in line.lower() or b"getenvy" in line.lower()):
        return True
    return False


def line_introduces_copyright_corruption(base_line: bytes, head_line: bytes) -> bool:
    if base_line == head_line:
        return False
    # Explicit corruption patterns vs known-good legacy © (0xA9 or UTF-8 C2 A9).
    if b"\xa9" in base_line or b"\xc2\xa9" in base_line:
        if b"\x9d" in head_line and b"\xa9" not in head_line and b"\xc2\xa9" not in head_line:
            return True
        if FFFD in head_line and FFFD not in base_line:
            return True
        for seq in MOJIBAKE_SEQUENCES:
            if head_line.count(seq) > base_line.count(seq):
                return True
        if b"?" in head_line and b"?" not in base_line and (
            b"\xa9" in base_line or b"\xc2\xa9" in base_line
        ):
            return True
    return False


def compare_sensitive_lines(base_lines: list[bytes], head_lines: list[bytes]) -> str | None:
    if base_lines == head_lines:
        return None
    if len(base_lines) != len(head_lines):
        return "copyright/license header line count changed"
    for base_line, head_line in zip(base_lines, head_lines):
        if base_line == head_line:
            continue
        if is_corrupt_copyright_line(head_line) and not is_corrupt_copyright_line(base_line):
            return "copyright/license header corruption"
        if is_corrupt_copyright_line(base_line) and not is_corrupt_copyright_line(head_line):
            continue
        if line_introduces_copyright_corruption(base_line, head_line):
            return "copyright/license header corruption"
        return "copyright/license header bytes changed (preserve legacy bytes byte-for-byte)"
    return None


def compare_metrics(path: str, base: FileMetrics, head: FileMetrics) -> list[str]:
    errors: list[str] = []

    if head.fffd > base.fffd:
        errors.append(
            f"new U+FFFD (EF BF BD): base={base.fffd} head={head.fffd}"
        )

    if head.utf8_c29d > base.utf8_c29d:
        errors.append(
            f"new UTF-8 U+009D bytes (C2 9D): base={base.utf8_c29d} head={head.utf8_c29d}"
        )

    if head.c1_controls_utf8 > base.c1_controls_utf8:
        errors.append(
            "new Unicode C1 controls (U+0080-U+009F) in valid UTF-8 text: "
            f"base={base.c1_controls_utf8} head={head.c1_controls_utf8}"
        )

    for seq, base_count in base.mojibake.items():
        head_count = head.mojibake[seq]
        if head_count > base_count:
            errors.append(
                f"new mojibake sequence {seq!r}: base={base_count} head={head_count}"
            )

    header_err = compare_sensitive_lines(base.sensitive_lines, head.sensitive_lines)
    if header_err:
        errors.append(header_err)

    iss_err = compare_sensitive_lines(base.iss_copyright_lines, head.iss_copyright_lines)
    if iss_err:
        errors.append(f"installer metadata: {iss_err}")

    return errors


def run_check(repo_root: str, base_sha: str, head_sha: str) -> int:
    migration_ok = os.environ.get("ENVY_ENCODING_MIGRATION_PR", "").strip() in (
        "1",
        "true",
        "yes",
    )
    failed = 0
    paths = [p for p in git_changed_paths(repo_root, base_sha, head_sha) if is_scanned_path(p)]

    for path in paths:
        base_blob = git_show(repo_root, base_sha, path)
        head_blob = git_show(repo_root, head_sha, path)
        if head_blob is None:
            print(f"::error file={path}::Missing file at HEAD", file=sys.stderr)
            failed += 1
            continue
        base_metrics = analyze_blob(base_blob or b"")
        head_metrics = analyze_blob(head_blob)
        errors = compare_metrics(path, base_metrics, head_metrics)
        if migration_ok and errors:
            print(
                f"::warning file={path}::Encoding findings (ENVY_ENCODING_MIGRATION_PR set): "
                + "; ".join(errors)
            )
            continue
        for msg in errors:
            print(f"::error file={path}::{msg}", file=sys.stderr)
            failed += 1

    if failed:
        return 1
    print(
        "check-source-encoding: no new encoding corruption in changed first-party sources."
    )
    return 0


def main(argv: Iterable[str] | None = None) -> int:
    args = list(argv or sys.argv[1:])
    if len(args) != 2:
        print(
            "usage: check_source_encoding_lib.py BASE_SHA HEAD_SHA",
            file=sys.stderr,
        )
        return 2
    base_sha, head_sha = args
    repo_root = os.environ.get("CHECK_ENCODING_ROOT", os.getcwd())
    try:
        return run_check(repo_root, base_sha, head_sha)
    except Exception as exc:  # fail closed
        print(f"::error::check-source-encoding internal error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
