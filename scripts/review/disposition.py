#!/usr/bin/env python3
"""Shared validation for review-thread disposition replies."""
from __future__ import annotations

import re

DISPOSITION_MARKER = re.compile(r"<!--\s*envy-(?:human-)?disposition\b", re.I)
_ACK_ONLY = re.compile(
    r"(?is)^\s*(thanks?|thank you|ok|okay|ack|lgtm|done|resolved|👍|🙏)[.!]?\s*$"
)
_TECHNICAL_SIGNAL = re.compile(
    r"(?i)\b("
    r"fixed|addressed|evidence|justification|intentional|obsolete|"
    r"false\s*positive|already\s+covered|out\s+of\s+scope|regression|"
    r"selftest|validated|compatib|wire-format|disposition"
    r")\b"
)
_SHA_CITE = re.compile(r"`?[0-9a-f]{7,40}`?", re.I)


def is_valid_disposition_body(body: str) -> bool:
    """True when a reply is a technical disposition, not a bare acknowledgement."""
    text = (body or "").strip()
    if not text or _ACK_ONLY.match(text):
        return False
    if DISPOSITION_MARKER.search(text):
        return True
    if "Evidence:" in text and len(text) >= 24:
        return True
    return bool(_SHA_CITE.search(text) and _TECHNICAL_SIGNAL.search(text) and len(text) >= 40)
