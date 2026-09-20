"""Redact usernames, profile paths, public IPs, keys, and credentials."""

from __future__ import annotations

import ipaddress
import os
import re
from pathlib import Path
from typing import Iterable, List, Tuple


_BEGIN_SECRET = re.compile(
    r"-----BEGIN [A-Z0-9 ]*(PRIVATE KEY|CERTIFICATE)-----.*?-----END [A-Z0-9 ]*(PRIVATE KEY|CERTIFICATE)-----",
    re.DOTALL,
)
_PASSWORD_ASSIGN = re.compile(
    r"(?i)\b(password|passwd|passphrase|secret|token|api[_-]?key)\s*[=:]\s*\S+"
)
_WIN_USER = re.compile(r"(?i)\b[A-Z]:\\Users\\[^\\/\s]+")
_UNIX_HOME = re.compile(r"(?m)(?<![A-Za-z0-9_])/home/[^/\s]+")
_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_IPV6 = re.compile(r"\b(?:[0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}\b")


def _env_values() -> List[str]:
    names = (
        "USER",
        "USERNAME",
        "LOGNAME",
        "HOME",
        "USERPROFILE",
        "APPDATA",
        "LOCALAPPDATA",
        "HOMEPATH",
    )
    values = []
    for name in names:
        raw = os.environ.get(name)
        if raw:
            values.append(raw)
    try:
        values.append(str(Path.home()))
    except OSError:
        pass
    return values


def _is_loopback_ip(text: str) -> bool:
    try:
        addr = ipaddress.ip_address(text.split("%", 1)[0])
    except ValueError:
        return False
    return addr.is_loopback


def _replace_ip(match: re.Match) -> str:
    value = match.group(0)
    if value in {"0.0.0.0", "::", "::1"} or _is_loopback_ip(value):
        return value
    try:
        addr = ipaddress.ip_address(value)
    except ValueError:
        return "<redacted-ip>"
    if addr.version == 4:
        return "<redacted-ipv4>"
    return "<redacted-ipv6>"


def sanitize_text(text: str, extra_needles: Iterable[str] = ()) -> str:
    out = text
    needles: List[Tuple[str, str]] = []
    for raw in list(extra_needles) + _env_values():
        if raw and len(raw) >= 2:
            needles.append((raw, "<redacted-path>"))
            needles.append((raw.replace("\\", "/"), "<redacted-path>"))
    needles.sort(key=lambda item: len(item[0]), reverse=True)
    for needle, repl in needles:
        if needle:
            out = out.replace(needle, repl)
    out = _WIN_USER.sub(r"<redacted-win-profile>", out)
    out = _UNIX_HOME.sub("/home/<redacted-user>", out)
    out = _BEGIN_SECRET.sub("<redacted-secret-block>", out)
    out = _PASSWORD_ASSIGN.sub(lambda m: m.group(0).split("=")[0].split(":")[0] + "=<redacted>", out)
    out = _IPV4.sub(_replace_ip, out)
    out = _IPV6.sub(_replace_ip, out)
    return out


def sanitize_file(src: Path, dest: Path, extra_needles: Iterable[str] = ()) -> None:
    dest.parent.mkdir(parents=True, exist_ok=True)
    try:
        data = src.read_bytes()
    except OSError:
        dest.write_text(f"<unreadable: {src.name}>\n", encoding="utf-8")
        return
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        text = data.decode("latin-1", errors="replace")
    dest.write_text(sanitize_text(text, extra_needles), encoding="utf-8")


def sanitize_tree(
    src_dir: Path,
    dest_dir: Path,
    extra_needles: Iterable[str] = (),
    *,
    skip_raw_bin: bool = False,
) -> None:
    if not src_dir.exists():
        return
    dest_dir.mkdir(parents=True, exist_ok=True)
    skip_suffixes = {".pcap", ".pcapng", ".key", ".pem", ".pfx"}
    if skip_raw_bin:
        # Capture/evidence raw dumps only — never apply to logs (stdout.bin).
        skip_suffixes.add(".bin")
    for path in src_dir.rglob("*"):
        if path.is_dir():
            continue
        rel = path.relative_to(src_dir)
        if path.suffix.lower() in skip_suffixes:
            continue
        sanitize_file(path, dest_dir / rel, extra_needles)
