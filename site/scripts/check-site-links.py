#!/usr/bin/env python3
"""Check internal relative links in site/*.html."""
import re
import sys
from pathlib import Path
from urllib.parse import urlsplit

SITE = Path(__file__).resolve().parents[1]
HTML = list(SITE.glob("*.html"))
LINK_RE = re.compile(r'''(?:href|src)=["']([^"']+)["']''')
errors = []

for path in HTML:
    text = path.read_text(encoding="utf-8")
    for raw in LINK_RE.findall(text):
        if raw.startswith(("http://", "https://", "mailto:", "#")):
            continue
        parsed = urlsplit(raw)
        target = (path.parent / parsed.path).resolve()
        try:
            target.relative_to(SITE.resolve())
        except ValueError:
            errors.append(f"{path.name}: external-relative? {raw}")
            continue
        if not target.exists():
            errors.append(f"{path.name}: missing target {raw}")

if errors:
    print("\n".join(errors), file=sys.stderr)
    sys.exit(1)
print(f"OK: checked {len(HTML)} HTML files")
