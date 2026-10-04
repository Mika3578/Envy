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


def body_cites_sha(body: str, head_sha: str) -> bool:
    """True when body cites the full HEAD or its unambiguous 7-char prefix."""
    head = str(head_sha or "").strip().lower()
    if len(head) < 7:
        return False
    text = (body or "").lower()
    return head in text or head[:7] in text


def is_valid_disposition_body(body: str, *, head_sha: str = "") -> bool:
    """True when a reply is a technical disposition, not a bare acknowledgement.

    An envy-disposition HTML marker alone is never sufficient: the body must
    still carry Evidence and/or a SHA cite plus a technical signal. When
    ``head_sha`` is supplied, the body must cite that HEAD.
    """
    text = (body or "").strip()
    if not text or _ACK_ONLY.match(text):
        return False
    has_evidence = "Evidence:" in text and len(text) >= 24
    has_technical = bool(_TECHNICAL_SIGNAL.search(text))
    if not has_evidence and not has_technical:
        return False
    if head_sha:
        return body_cites_sha(text, head_sha) and len(text) >= 40
    return bool(_SHA_CITE.search(text)) and len(text) >= 40
