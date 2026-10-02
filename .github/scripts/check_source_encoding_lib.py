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
UTF8_BOM = b"\xef\xbb\xbf"
UTF8_C29D = b"\xc2\x9d"

FIRST_PARTY_PREFIXES = (
    "Envy/",
    "HashLib/",
    "TorrentEnvy/",
    "Unpacker/",
    "SkinBuilder/",
    "Installer/",
    "tests/",
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

# Double-encoded / legacy corruption byte runs only (not valid UTF-8 punctuation).
MOJIBAKE_SEQUENCES = (
    b"\xc3\x82\xc2\xa9",  # Â©
    b"\xc3\x83\xc2\xa9",  # Ã©
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


def git_merge_base(repo_root: str, base: str, head: str) -> str:
    r = subprocess.run(
        ["git", "-C", repo_root, "merge-base", base, head],
        capture_output=True,
        check=True,
        text=True,
    )
    return r.stdout.strip()


def git_file_diff(
    repo_root: str, base: str, head: str, base_path: str, head_path: str
) -> bytes:
    path_args = [head_path]
    if base_path != head_path:
        path_args = [base_path, head_path]
    r = subprocess.run(
        [
            "git",
            "-C",
            repo_root,
            "diff",
            "-U0",
            base,
            head,
            "--",
            *path_args,
        ],
        capture_output=True,
        check=True,
    )
    return r.stdout


def iter_changed_line_pairs(patch: bytes) -> Iterable[tuple[bytes, bytes]]:
    pending_minus: list[bytes] = []
    in_hunk = False
    for raw_line in patch.splitlines():
        if raw_line.startswith(b"@@"):
            in_hunk = True
            pending_minus.clear()
            continue
        if not in_hunk and raw_line.startswith(
            (b"---", b"+++", b"diff ", b"index ", b"old mode", b"new mode")
        ):
            continue
        if raw_line.startswith(b"-") and (in_hunk or not raw_line.startswith(b"---")):
            pending_minus.append(raw_line[1:])
            continue
        if raw_line.startswith(b"+") and (in_hunk or not raw_line.startswith(b"+++")):
            base_line = pending_minus.pop(0) if pending_minus else b""
            head_line = raw_line[1:]
            yield base_line, head_line
            continue
        if raw_line.startswith(b" "):
            pending_minus.clear()
    while pending_minus:
        yield pending_minus.pop(0), b""


@dataclass(frozen=True)
class ChangedPath:
    head_path: str
    base_path: str


def git_changed_paths(repo_root: str, base: str, head: str) -> list[ChangedPath]:
    # -z avoids core.quotepath mangling so non-ASCII names stay lossless.
    r = subprocess.run(
        [
            "git",
            "-C",
            repo_root,
            "diff",
            "--name-status",
            "-z",
            "-M",
            f"{base}...{head}",
        ],
        capture_output=True,
        check=True,
    )
    out: list[ChangedPath] = []
    fields = [f.decode("utf-8", "surrogateescape") for f in r.stdout.split(b"\0") if f]
    i = 0
    while i < len(fields):
        status = fields[i]
        i += 1
        if status.startswith("R") or status.startswith("C"):
            if i + 1 >= len(fields):
                break
            base_path = fields[i]
            head_path = fields[i + 1]
            i += 2
            out.append(ChangedPath(head_path=head_path, base_path=base_path))
            continue
        if i >= len(fields):
            break
        path = fields[i]
        i += 1
        if status == "D":
            continue
        if status in ("A", "M", "T"):
            out.append(ChangedPath(head_path=path, base_path=path))
    return out


def is_scanned_path(path: str) -> bool:
    if not any(path.startswith(p) for p in FIRST_PARTY_PREFIXES):
        return False
    # Windows source classes: suffix match must be case-insensitive on Linux CI.
    lower = path.lower()
    if lower.endswith(SOURCE_SUFFIXES):
        return True
    if lower.endswith(ISS_SUFFIX):
        return True
    return False


def is_valid_utf8(data: bytes) -> bool:
    try:
        data.decode("utf-8")
        return True
    except UnicodeDecodeError:
        return False


def utf8_error_byte_counts(data: bytes) -> dict[int, int]:
    """Multiset of byte values that participate in UTF-8 decode errors."""
    counts: dict[int, int] = {}
    if is_valid_utf8(data):
        return counts
    i = 0
    n = len(data)
    while i < n:
        try:
            data[i:].decode("utf-8")
            break
        except UnicodeDecodeError as exc:
            start = i + exc.start
            end = i + max(exc.end, exc.start + 1)
            end = min(end, n)
            if end <= start:
                end = min(start + 1, n)
            for b in data[start:end]:
                counts[b] = counts.get(b, 0) + 1
            i = end
            if i <= start:
                i = start + 1
    return counts


def line_introduces_invalid_utf8_debt(base_line: bytes, head_line: bytes) -> bool:
    """True when head adds invalid UTF-8 debt relative to base on this line."""
    if not head_line or head_line == base_line or is_valid_utf8(head_line):
        return False
    if is_valid_utf8(base_line):
        return True
    head_err = utf8_error_byte_counts(head_line)
    base_err = utf8_error_byte_counts(base_line)
    return any(head_err.get(b, 0) > base_err.get(b, 0) for b in head_err)


def count_c1_controls_if_valid_utf8(data: bytes) -> int:
    """Count UTF-8 encodings of U+0080..U+009F (C2 80 .. C2 9F).

    Scan byte sequences even when the blob is not valid UTF-8 overall, so
    legacy invalid lines still surface newly introduced Unicode C1 controls.
    """
    n = 0
    i = 0
    limit = len(data) - 1
    while i < limit:
        b0 = data[i]
        if b0 == 0xC2:
            b1 = data[i + 1]
            if 0x80 <= b1 <= 0x9F:
                n += 1
                i += 2
                continue
        i += 1
    return n


def _line_without_utf8_bom(line: bytes) -> bytes:
    """Strip a leading UTF-8 BOM for prefix matching only."""
    if line.startswith(UTF8_BOM):
        return line[len(UTF8_BOM) :]
    return line


def sensitive_header_lines(data: bytes) -> list[bytes]:
    out: list[bytes] = []
    for line in data.split(b"\n"):
        check = _line_without_utf8_bom(line)
        for prefix in ENVY_HEADER_PREFIXES:
            if check.startswith(prefix):
                # Keep the original line (including BOM) for byte comparison.
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
    if not base_lines:
        # New file: header metrics (FFFD/C1/mojibake) cover corruption; do not
        # require an empty baseline to match Envy's standard header block count.
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


def _line_metric_delta(base_line: bytes, head_line: bytes) -> FileMetrics:
    return FileMetrics(
        fffd=max(0, head_line.count(FFFD) - base_line.count(FFFD)),
        utf8_c29d=max(0, head_line.count(UTF8_C29D) - base_line.count(UTF8_C29D)),
        c1_controls_utf8=max(
            0,
            count_c1_controls_if_valid_utf8(head_line)
            - count_c1_controls_if_valid_utf8(base_line),
        ),
        mojibake={
            seq: max(0, head_line.count(seq) - base_line.count(seq))
            for seq in MOJIBAKE_SEQUENCES
        },
        sensitive_lines=[],
        iss_copyright_lines=[],
    )


def compare_changed_lines(patch: bytes) -> list[str]:
    errors: list[str] = []
    change_idx = 0
    for base_line, head_line in iter_changed_line_pairs(patch):
        if base_line == head_line:
            continue
        change_idx += 1
        # Reject new invalid UTF-8 on added/replaced lines even when the whole
        # base blob was already invalid (no FFFD/C1/mojibake whole-file delta),
        # including mutations that append/replace bytes on an already-invalid line.
        if line_introduces_invalid_utf8_debt(base_line, head_line):
            errors.append(
                f"new invalid UTF-8 bytes in diff hunk change #{change_idx}"
            )
        delta = _line_metric_delta(base_line, head_line)
        if delta.fffd:
            errors.append(f"new U+FFFD (EF BF BD) in diff hunk change #{change_idx}")
        if delta.utf8_c29d:
            errors.append(
                f"new UTF-8 U+009D bytes (C2 9D) in diff hunk change #{change_idx}"
            )
        if delta.c1_controls_utf8:
            errors.append(
                f"new Unicode C1 controls (U+0080-U+009F) in diff hunk change #{change_idx}"
            )
        for seq, added in delta.mojibake.items():
            if added:
                errors.append(
                    f"new mojibake sequence {seq!r} in diff hunk change #{change_idx}"
                )
    return errors


def compare_metrics(
    path: str, base: FileMetrics, head: FileMetrics, base_blob: bytes | None
) -> list[str]:
    errors: list[str] = []

    header_err = compare_sensitive_lines(base.sensitive_lines, head.sensitive_lines)
    if header_err:
        errors.append(header_err)
    elif not base.sensitive_lines:
        for line in head.sensitive_lines:
            if is_corrupt_copyright_line(line):
                errors.append("copyright/license header corruption on new file")

    iss_err = compare_sensitive_lines(base.iss_copyright_lines, head.iss_copyright_lines)
    if iss_err:
        errors.append(f"installer metadata: {iss_err}")
    elif not base.iss_copyright_lines:
        for line in head.iss_copyright_lines:
            if is_corrupt_copyright_line(line):
                errors.append("installer metadata: copyright corruption on new file")

    return errors


def compare_whole_blob_regressions(
    base_metrics: FileMetrics, head_metrics: FileMetrics
) -> list[str]:
    errors: list[str] = []
    if head_metrics.fffd > base_metrics.fffd:
        errors.append("whole-file U+FFFD (EF BF BD) count increased")
    if head_metrics.utf8_c29d > base_metrics.utf8_c29d:
        errors.append("whole-file UTF-8 U+009D (C2 9D) count increased")
    if head_metrics.c1_controls_utf8 > base_metrics.c1_controls_utf8:
        errors.append("whole-file Unicode C1 control count increased")
    for seq in MOJIBAKE_SEQUENCES:
        if head_metrics.mojibake.get(seq, 0) > base_metrics.mojibake.get(seq, 0):
            errors.append(f"whole-file mojibake sequence {seq!r} count increased")
    return errors


def compare_blob_byte_regressions(
    repo_root: str,
    baseline_sha: str,
    head_sha: str,
    base_path: str,
    head_path: str,
) -> list[str]:
    patch = git_file_diff(repo_root, baseline_sha, head_sha, base_path, head_path)
    return compare_changed_lines(patch)


# encoding-migration label may warn-only on intentional legacy byte preservation;
# corruption signals (FFFD, mojibake, C1 controls, explicit header corruption)
# remain fatal per #350.
MIGRATION_WARN_ONLY_MARKERS = (
    "copyright/license header bytes changed (preserve legacy bytes byte-for-byte)",
)


def partition_encoding_errors(errors: list[str]) -> tuple[list[str], list[str]]:
    fatal: list[str] = []
    warn_only: list[str] = []
    for msg in errors:
        if any(marker in msg for marker in MIGRATION_WARN_ONLY_MARKERS):
            warn_only.append(msg)
        else:
            fatal.append(msg)
    return fatal, warn_only


def encoding_migration_pr_from_github_event() -> bool:
    event_path = os.environ.get("GITHUB_EVENT_PATH", "").strip()
    if not event_path or not os.path.isfile(event_path):
        return False
    try:
        import json

        with open(event_path, encoding="utf-8") as handle:
            payload = json.load(handle)
    except (OSError, json.JSONDecodeError):
        return False
    labels = payload.get("pull_request", {}).get("labels") or []
    return any(label.get("name") == "encoding-migration" for label in labels)


def run_check(repo_root: str, base_sha: str, head_sha: str) -> int:
    migration_ok = encoding_migration_pr_from_github_event()
    failed = 0
    baseline_sha = git_merge_base(repo_root, base_sha, head_sha)
    paths = [
        p
        for p in git_changed_paths(repo_root, base_sha, head_sha)
        if is_scanned_path(p.head_path)
    ]

    for entry in paths:
        path = entry.head_path
        base_blob = git_show(repo_root, baseline_sha, entry.base_path)
        if base_blob is not None and not is_scanned_path(entry.base_path):
            # Rename into first-party scope: do not inherit debt from non-scanned paths.
            base_blob = None
        head_blob = git_show(repo_root, head_sha, entry.head_path)
        if head_blob is None:
            continue
        base_metrics = analyze_blob(base_blob or b"")
        head_metrics = analyze_blob(head_blob)
        errors = compare_metrics(path, base_metrics, head_metrics, base_blob)
        if base_blob is not None and is_valid_utf8(base_blob) and not is_valid_utf8(head_blob):
            errors.append("file changed from valid UTF-8 to invalid UTF-8")
        elif base_blob is None and not is_valid_utf8(head_blob):
            errors.append("new file is not valid UTF-8")
        errors.extend(compare_whole_blob_regressions(base_metrics, head_metrics))
        errors.extend(
            compare_blob_byte_regressions(
                repo_root,
                baseline_sha,
                head_sha,
                entry.base_path,
                entry.head_path,
            )
        )
        fatal_errors, migration_warn_errors = (
            partition_encoding_errors(errors) if migration_ok else (errors, [])
        )
        if migration_ok and migration_warn_errors:
            print(
                f"::warning file={path}::Encoding migration label (warn-only): "
                + "; ".join(migration_warn_errors)
            )
        for msg in fatal_errors:
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
