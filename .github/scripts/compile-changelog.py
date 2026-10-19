#!/usr/bin/env python3
"""Fold changelog.d/<id>.<category>.md fragments into CHANGELOG.md [Unreleased]."""
import argparse
import pathlib
import re
import sys

CATEGORIES = ["added", "changed", "fixed", "security", "removed"]
FRAGMENT = re.compile(r"^[A-Za-z0-9_-]+\.(" + "|".join(CATEGORIES) + r")\.md$")


def collect(frag_dir):
    found = {c: [] for c in CATEGORIES}
    for path in sorted(frag_dir.glob("*.md")):
        if path.name == "README.md":
            continue
        m = FRAGMENT.match(path.name)
        if not m:
            raise SystemExit(f"bad fragment name: {path.name}")
        text = path.read_text(encoding="utf-8").strip()
        if not text or "\n" in text:
            raise SystemExit(f"{path.name}: expected exactly one non-empty line")
        found[m.group(1)].append((path, text))
    return found


def merge(changelog, found):
    nl = "\r\n" if "\r\n" in changelog else "\n"
    lines = changelog.split(nl)
    start = next(i for i, l in enumerate(lines) if l.startswith("## [Unreleased]"))
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


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", default=".")
    ap.add_argument("--dry-run", action="store_true")
    a = ap.parse_args()
    root = pathlib.Path(a.root)
    found = collect(root / "changelog.d")
    count = sum(len(v) for v in found.values())
    if not count:
        print("no fragments")
        return 0
    cl = root / "CHANGELOG.md"
    out = merge(cl.read_bytes().decode("utf-8"), found)
    if a.dry_run:
        print(f"{count} fragment(s) would be merged")
        return 0
    cl.write_bytes(out.encode("utf-8"))
    for v in found.values():
        for p, _ in v:
            p.unlink()
    print(f"merged {count} fragment(s)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
