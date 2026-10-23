#!/usr/bin/env python3
"""Fold changelog.d/<id>.<category>.md fragments into CHANGELOG.md [Unreleased]."""
import argparse
import pathlib
import re
import sys

CATEGORIES = ["added", "changed", "fixed", "security", "removed"]
FRAGMENT = re.compile(r"^[A-Za-z0-9_-]+\.(" + "|".join(CATEGORIES) + r")\.md$")


class InputError(Exception):
    """Invalid input; reported on stderr with exit status 1."""


class RootError(Exception):
    """--root escapes the working directory; reported with exit status 2."""


def resolve_root(value):
    """Resolve --root and require it to stay under the working directory."""
    cwd = pathlib.Path.cwd().resolve()
    root = pathlib.Path(value).resolve()
    try:
        root.relative_to(cwd)
    except ValueError:
        raise RootError(f"--root must stay under the working directory: {value}") from None
    return root


def read_utf8(path, what):
    try:
        return path.read_bytes().decode("utf-8")
    except UnicodeDecodeError:
        raise InputError(f"{what}: not valid UTF-8") from None
    except OSError as e:
        raise InputError(f"{what}: cannot read ({e.strerror})") from None


def collect(root):
    frag_dir = root / "changelog.d"
    if frag_dir.is_symlink() or not frag_dir.is_dir():
        raise InputError("changelog.d: missing or not a regular directory")
    found = {c: [] for c in CATEGORIES}
    for path in sorted(frag_dir.glob("*.md")):
        if path.name == "README.md":
            continue
        m = FRAGMENT.match(path.name)
        if not m:
            raise InputError(f"bad fragment name: {path.name}")
        if path.is_symlink() or not path.is_file():
            raise InputError(f"{path.name}: not a regular file")
        text = read_utf8(path, path.name).strip()
        if not text or "\n" in text or "\r" in text:
            raise InputError(f"{path.name}: expected exactly one non-empty line")
        found[m.group(1)].append((path, text))
    return found


def merge(changelog, found):
    nl = "\r\n" if "\r\n" in changelog else "\n"
    lines = changelog.split(nl)
    start = next((i for i, l in enumerate(lines) if l.startswith("## [Unreleased]")), None)
    if start is None:
        raise InputError("CHANGELOG.md: missing '## [Unreleased]' section")
    end = next((i for i in range(start + 1, len(lines)) if lines[i].startswith("## [")), len(lines))
    for cat in CATEGORIES:
        entries = ["- " + t for _, t in found[cat]]
        if not entries:
            continue
        head = "### " + cat.capitalize()
        idx = next((i for i in range(start, end) if lines[i].strip() == head), None)
        if idx is None:
            lines[end:end] = [head] + entries + [""]
            end += len(entries) + 2
        else:
            at = idx + 1
            while at < end and lines[at].strip() == "":
                at += 1
            lines[at:at] = entries
            end += len(entries)
    return nl.join(lines)


def run(a):
    root = resolve_root(a.root)
    found = collect(root)
    count = sum(len(v) for v in found.values())
    if not count:
        print("no fragments")
        return 0
    cl = root / "CHANGELOG.md"
    if cl.is_symlink() or not cl.is_file():
        raise InputError("CHANGELOG.md: missing or not a regular file")
    out = merge(read_utf8(cl, "CHANGELOG.md"), found)
    if a.dry_run:
        print(f"{count} fragment(s) would be merged")
        return 0
    cl.write_bytes(out.encode("utf-8"))
    for v in found.values():
        for p, _ in v:
            p.unlink()
    print(f"merged {count} fragment(s)")
    return 0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", default=".")
    ap.add_argument("--dry-run", action="store_true")
    try:
        return run(ap.parse_args())
    except RootError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    except InputError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
