"""Record configured binary identity without storing operator filesystem paths.

Never launch eMule Community or ENVY just to read a version string (those
binaries are GUI and would start a user-visible instance). aMule/amuled
`--version` is headless and is probed only when that client is configured.
"""

from __future__ import annotations

import hashlib
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

from .config import HarnessConfig
from .sanitizer import sanitize_text

_HASH_LIMIT = 32 * 1024 * 1024
_VERSION_TIMEOUT_SEC = 5.0


def _sha256_file(path: Path, *, limit: int = _HASH_LIMIT) -> Dict[str, Any]:
    digest = hashlib.sha256()
    hashed = 0
    truncated = False
    with path.open("rb") as handle:
        while hashed < limit:
            chunk = handle.read(min(1024 * 1024, limit - hashed))
            if not chunk:
                break
            digest.update(chunk)
            hashed += len(chunk)
    if path.stat().st_size > hashed:
        truncated = True
    return {"sha256": digest.hexdigest(), "sha256_truncated": truncated, "hashed_bytes": hashed}


def describe_executable(
    path: Optional[Path],
    *,
    allow_version_flag: bool,
) -> Dict[str, Any]:
    """Describe a configured binary. Full paths are not stored."""
    if path is None:
        return {"configured": False}
    info: Dict[str, Any] = {
        "configured": True,
        "name": path.name,
        "exists": path.is_file(),
        "size": None,
        "mtime_utc": "",
        "sha256": "",
        "sha256_truncated": False,
        "version_text": "",
        "probe": "none",
    }
    if not path.is_file():
        return info
    st = path.stat()
    info["size"] = int(st.st_size)
    info["mtime_utc"] = datetime.fromtimestamp(st.st_mtime, timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )
    info.update(_sha256_file(path))
    if allow_version_flag:
        try:
            proc = subprocess.run(
                [str(path), "--version"],
                capture_output=True,
                timeout=_VERSION_TIMEOUT_SEC,
                check=False,
                shell=False,
            )
            text = ((proc.stdout or b"") + (proc.stderr or b"")).decode("utf-8", errors="replace")
            info["version_text"] = sanitize_text(text.strip()[:500])
            info["probe"] = "--version"
            info["probe_exit"] = int(proc.returncode)
        except subprocess.TimeoutExpired:
            info["probe"] = "version-flag-timeout"
        except OSError:
            info["probe"] = "version-flag-failed"
    return info


def record_configured_binaries(cfg: HarnessConfig) -> Dict[str, Any]:
    client = cfg.resolved_reference_client()
    amule_probe = client in {"amule", "amuled"} or (
        cfg.amule_exe is not None and cfg.amule_exe.name.lower().startswith("amule")
    )
    return {
        "envy": describe_executable(cfg.envy_exe, allow_version_flag=False),
        "emule": describe_executable(cfg.emule_exe, allow_version_flag=False),
        "amule": describe_executable(cfg.amule_exe, allow_version_flag=amule_probe),
        "operator_reference_client": client,
        "operator_reference_version": cfg.reference_version or "",
        "note": (
            "ENVY/eMule GUI binaries are never launched for --version. "
            "aMule --version is probed only when an aMule path is configured."
        ),
    }
