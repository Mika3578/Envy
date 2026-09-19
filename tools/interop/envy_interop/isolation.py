"""Isolated scratch directories and safe cleanup.

Never delete a path unless it is inside a directory this run created.
Never follow operator paths that resolve to a home/profile root.
"""

from __future__ import annotations

import os
import shutil
import stat
import tempfile
from pathlib import Path
from typing import Set


class IsolationError(ValueError):
    pass


def _is_windows() -> bool:
    return os.name == "nt"


def home_path() -> Path:
    return Path.home().resolve()


def forbidden_cleanup_roots() -> Set[Path]:
    roots = {
        Path("/").resolve(),
        Path(tempfile.gettempdir()).resolve(),
        home_path(),
    }
    if _is_windows():
        for letter in "CD":
            roots.add(Path(f"{letter}:\\"))
        for env_name in ("USERPROFILE", "APPDATA", "LOCALAPPDATA", "HOMEDRIVE"):
            raw = os.environ.get(env_name)
            if raw:
                try:
                    roots.add(Path(raw).resolve())
                except OSError:
                    pass
        users = Path("C:/Users")
        if users.exists():
            roots.add(users.resolve())
    else:
        roots.add(Path("/home").resolve())
        roots.add(Path("/tmp").resolve())
        roots.add(Path("/var/tmp").resolve())
    return roots


def resolve_strict(path: Path) -> Path:
    try:
        return path.expanduser().resolve(strict=False)
    except OSError as exc:
        raise IsolationError(f"cannot resolve path: {path}") from exc


def is_relative_to(path: Path, root: Path) -> bool:
    try:
        path.resolve(strict=False).relative_to(root.resolve(strict=False))
        return True
    except (ValueError, OSError):
        return False


def assert_not_profile_root(path: Path, *, what: str) -> Path:
    resolved = resolve_strict(path)
    if resolved in forbidden_cleanup_roots():
        raise IsolationError(f"{what} resolves to a protected root: {resolved}")
    if resolved == home_path():
        raise IsolationError(f"{what} must not be the user home directory")
    return resolved


class IsolationRoot:
    """Owns one scratch tree for a single harness run."""

    def __init__(self, root: Path) -> None:
        self.root = assert_not_profile_root(root, what="isolation root")
        self.root.mkdir(parents=True, exist_ok=True)
        self._created = True

    def child(self, *parts: str) -> Path:
        path = self.root.joinpath(*parts)
        if not is_relative_to(path, self.root):
            raise IsolationError("refusing path escape from isolation root")
        path.mkdir(parents=True, exist_ok=True)
        return path

    def envy_profile(self) -> Path:
        return self.child("profiles", "envy")

    def emule_profile(self) -> Path:
        return self.child("profiles", "emule")

    def amule_profile(self) -> Path:
        return self.child("profiles", "amule")

    def share_dir(self) -> Path:
        return self.child("share")

    def incoming_dir(self) -> Path:
        return self.child("incoming")

    def envy_launch_env(self) -> dict:
        profile = self.envy_profile()
        roaming = profile / "AppData" / "Roaming"
        local = profile / "AppData" / "Local"
        roaming.mkdir(parents=True, exist_ok=True)
        local.mkdir(parents=True, exist_ok=True)
        env = {
            "APPDATA": str(roaming),
            "LOCALAPPDATA": str(local),
            "USERPROFILE": str(profile),
            "HOME": str(profile),
        }
        return env

    def emule_launch_env(self) -> dict:
        profile = self.emule_profile()
        roaming = profile / "AppData" / "Roaming"
        local = profile / "AppData" / "Local"
        roaming.mkdir(parents=True, exist_ok=True)
        local.mkdir(parents=True, exist_ok=True)
        return {
            "APPDATA": str(roaming),
            "LOCALAPPDATA": str(local),
            "USERPROFILE": str(profile),
            "HOME": str(profile),
        }

    def cleanup(self) -> None:
        if not self._created:
            return
        safe_rmtree(self.root, owned_root=self.root)


def safe_rmtree(path: Path, *, owned_root: Path) -> None:
    """Delete path only when it is inside owned_root (inclusive)."""
    target = resolve_strict(path)
    root = resolve_strict(owned_root)
    if target in forbidden_cleanup_roots():
        raise IsolationError(f"refusing to delete protected path: {target}")
    if not (target == root or is_relative_to(target, root)):
        raise IsolationError(f"refusing to delete {target} (not under {root})")
    if not target.exists():
        return
    shutil.rmtree(target, onerror=_on_rm_error)


def _on_rm_error(func, path, exc_info) -> None:  # pragma: no cover - platform bits
    try:
        os.chmod(path, stat.S_IWRITE | stat.S_IREAD)
        func(path)
    except OSError:
        raise


def create_run_isolation(base: Path, run_id: str) -> IsolationRoot:
    root = resolve_strict(base) / "scratch" / run_id
    return IsolationRoot(root)
