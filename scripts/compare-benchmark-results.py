#!/usr/bin/env python3
"""Compare two Envy benchmark JSON result files (base vs head).

Safe, offline comparison only — does not execute benchmark binaries or shell out.
"""

from __future__ import annotations

import argparse
import json
import math
import os
import re
import stat
import sys
from pathlib import Path
from typing import Any, Dict, List


MAX_FILE_BYTES = 8 * 1024 * 1024
_SAFE_RESULTS_PATH = re.compile(r"^[\w./\\\-]+$")


def validate_results_path(path: str) -> None:
    if not path or len(path) > 4096:
        raise ValueError("invalid path length")
    if ".." in path:
        raise ValueError("path traversal in results path")
    if os.path.basename(path) in ("", ".", ".."):
        raise ValueError("invalid results filename")
    if not _SAFE_RESULTS_PATH.match(path):
        raise ValueError("results path contains disallowed characters")


def _path_has_symlink_component(candidate: Path) -> bool:
    """True if any existing path component (including parents) is a symlink."""
    try:
        absolute = candidate if candidate.is_absolute() else (Path.cwd() / candidate)
        absolute = absolute.absolute()
    except OSError as exc:
        raise ValueError("unable to resolve results path") from exc

    current = Path(absolute.anchor) if absolute.anchor else Path()
    parts = absolute.parts[1:] if absolute.anchor else absolute.parts
    for part in parts:
        current = current / part
        try:
            # Check the component itself (do not require the target to exist).
            if current.is_symlink():
                return True
        except OSError as exc:
            raise ValueError("unable to inspect results path") from exc
    return False


def resolve_results_file(path: str) -> Path:
    """Return a resolved regular file path after validation (CLI input is untrusted)."""
    validate_results_path(path)
    candidate = Path(path)
    if _path_has_symlink_component(candidate):
        raise ValueError("symlinks not allowed for results files")
    try:
        resolved = candidate.resolve(strict=True)
    except FileNotFoundError as exc:
        raise ValueError("results file not found") from exc
    if not resolved.is_file() or resolved.is_symlink():
        raise ValueError("results path is not a regular file")
    return resolved


def _read_regular_file_bytes(file_path: Path, max_bytes: int) -> bytes:
    """Read bytes from an already-resolved path without following a swapped-in symlink."""
    if os.name == "nt":
        return _read_regular_file_bytes_windows(file_path, max_bytes)
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(file_path, flags)
    try:
        mode = os.fstat(fd).st_mode
        if not stat.S_ISREG(mode):
            raise ValueError("results path is not a regular file")
    except BaseException:
        os.close(fd)
        raise
    with os.fdopen(fd, "rb") as stream:
        return stream.read(max_bytes + 1)


def _read_regular_file_bytes_windows(file_path: Path, max_bytes: int) -> bytes:
    import ctypes
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    GENERIC_READ = 0x80000000
    FILE_SHARE_READ = 1
    OPEN_EXISTING = 3
    FILE_ATTRIBUTE_NORMAL = 0x80
    FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000
    FILE_ATTRIBUTE_REPARSE_POINT = 0x400
    INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value

    CreateFileW = kernel32.CreateFileW
    CreateFileW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    ]
    CreateFileW.restype = wintypes.HANDLE

    GetFileInformationByHandle = kernel32.GetFileInformationByHandle
    GetFileInformationByHandle.argtypes = [wintypes.HANDLE, wintypes.LPVOID]
    GetFileInformationByHandle.restype = wintypes.BOOL

    ReadFile = kernel32.ReadFile
    ReadFile.argtypes = [
        wintypes.HANDLE,
        wintypes.LPVOID,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
        wintypes.LPVOID,
    ]
    ReadFile.restype = wintypes.BOOL

    CloseHandle = kernel32.CloseHandle
    CloseHandle.argtypes = [wintypes.HANDLE]
    CloseHandle.restype = wintypes.BOOL

    class BY_HANDLE_FILE_INFORMATION(ctypes.Structure):
        _fields_ = [
            ("dwFileAttributes", wintypes.DWORD),
            ("ftCreationTime", wintypes.FILETIME),
            ("ftLastAccessTime", wintypes.FILETIME),
            ("ftLastWriteTime", wintypes.FILETIME),
            ("dwVolumeSerialNumber", wintypes.DWORD),
            ("nFileSizeHigh", wintypes.DWORD),
            ("nFileSizeLow", wintypes.DWORD),
            ("nNumberOfLinks", wintypes.DWORD),
            ("nFileIndexHigh", wintypes.DWORD),
            ("nFileIndexLow", wintypes.DWORD),
        ]

    path_w = str(file_path)
    handle = CreateFileW(
        path_w,
        GENERIC_READ,
        FILE_SHARE_READ,
        None,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
        None,
    )
    if handle == INVALID_HANDLE_VALUE:
        raise OSError(ctypes.get_last_error(), "unable to open results file")

    try:
        info = BY_HANDLE_FILE_INFORMATION()
        if not GetFileInformationByHandle(handle, ctypes.byref(info)):
            raise OSError(ctypes.get_last_error(), "unable to inspect results file")
        if info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT:
            raise ValueError("symlinks not allowed for results files")

        size = (info.nFileSizeHigh << 32) + info.nFileSizeLow
        to_read = min(size, max_bytes + 1)
        if to_read == 0:
            return b""

        buf = (ctypes.c_ubyte * to_read)()
        read = wintypes.DWORD(0)
        if not ReadFile(handle, buf, to_read, ctypes.byref(read), None):
            raise OSError(ctypes.get_last_error(), "unable to read results file")
        return bytes(buf[: read.value])
    finally:
        CloseHandle(handle)


def load_document(path: str) -> Dict[str, Any]:
    file_path = resolve_results_file(path)
    data = _read_regular_file_bytes(file_path, MAX_FILE_BYTES)
    if len(data) > MAX_FILE_BYTES:
        raise ValueError("file too large")
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


def parse_median_ns(key: str, median: Any) -> float:
    # bool is a subclass of int; reject it explicitly.
    if isinstance(median, bool) or not isinstance(median, (int, float)):
        raise ValueError(f"invalid median_ns for {key}")
    try:
        value = float(median)
    except (OverflowError, ValueError) as exc:
        raise ValueError(f"invalid median_ns for {key}") from exc
    if not math.isfinite(value) or value < 0.0:
        raise ValueError(f"invalid median_ns for {key}")
    return value


def parse_benchmarks(doc: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    items = doc.get("benchmarks")
    if not isinstance(items, list):
        raise ValueError("benchmarks must be an array")
    out: Dict[str, Dict[str, Any]] = {}
    for item in items:
        if not isinstance(item, dict):
            raise ValueError("benchmark entry must be an object")
        key = bench_key(item)
        if key in out:
            raise ValueError(f"duplicate benchmark {key}")
        parse_median_ns(key, item.get("median_ns"))
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
        b = parse_median_ns(key, base[key]["median_ns"])
        h = parse_median_ns(key, head[key]["median_ns"])
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
