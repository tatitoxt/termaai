"""Classify the filesystem paths a script mentions relative to the workspace."""

from __future__ import annotations

import posixpath
import re
from enum import Enum

SYSTEM_PREFIXES = (
    "/etc",
    "/usr",
    "/bin",
    "/sbin",
    "/lib",
    "/lib32",
    "/lib64",
    "/boot",
    "/var",
    "/opt",
    "/sys",
    "/proc",
    "/root",
    "/srv",
    "/snap",
)
TEMP_PREFIXES = ("/tmp", "/var/tmp", "/dev/shm")
SAFE_DEVICES = frozenset(
    {
        "/dev/null",
        "/dev/stdout",
        "/dev/stderr",
        "/dev/stdin",
        "/dev/tty",
        "/dev/zero",
        "/dev/random",
    }
)
SENSITIVE_HOME = (
    ".ssh",
    ".bashrc",
    ".bash_profile",
    ".profile",
    ".zshrc",
    ".bash_logout",
    ".config/autostart",
    ".aws",
    ".gnupg",
    ".netrc",
    ".git-credentials",
    ".docker/config.json",
    ".kube",
)
_HOME_PREFIX = re.compile(r"^(~[A-Za-z0-9_-]*|\$HOME|\$\{HOME\})(?=/|$)")
_VAR_PREFIX = re.compile(r"^\$(\{[^}]*\}|[A-Za-z_][A-Za-z0-9_]*|[0-9@*#?])")


class Scope(str, Enum):
    WORKSPACE = "workspace"
    ROOT = "root"
    SYSTEM = "system"
    HOME = "home"
    TEMP = "temp"
    DEVICE = "device"
    SAFE_DEVICE = "safe-device"
    OUTSIDE = "outside"
    UNKNOWN = "unknown"

    @property
    def outside_workspace(self) -> bool:
        return self not in {Scope.WORKSPACE, Scope.SAFE_DEVICE}


def home_relative(path: str) -> str | None:
    """Return the part after ``~``/``$HOME`` (``""`` for the home dir itself), else None."""
    match = _HOME_PREFIX.match(path)
    if not match:
        return None
    return path[match.end() :].lstrip("/")


def is_sensitive_home(path: str) -> bool:
    rel = home_relative(path)
    if rel is None:
        return False
    return any(rel == s or rel.startswith(s + "/") for s in SENSITIVE_HOME)


def classify(path: str, workspace: str) -> Scope:
    """Classify ``path`` as seen from a script whose working directory is ``workspace``."""
    if not path:
        return Scope.UNKNOWN
    if home_relative(path) is not None:
        return Scope.HOME
    if _VAR_PREFIX.match(path):
        return Scope.UNKNOWN
    workspace = posixpath.normpath(workspace)
    if path.startswith("/"):
        norm = posixpath.normpath(path)
        if norm.startswith("//"):
            norm = norm[1:]
        stripped = norm.rstrip("*").rstrip("/") or "/"
        if stripped == "/":
            return Scope.ROOT
        if norm == workspace or norm.startswith(workspace.rstrip("/") + "/"):
            return Scope.WORKSPACE
        if norm in SAFE_DEVICES or norm.startswith("/dev/fd/"):
            return Scope.SAFE_DEVICE
        if norm == "/dev" or norm.startswith("/dev/"):
            return Scope.DEVICE
        if _under(norm, TEMP_PREFIXES):
            return Scope.TEMP
        if _under(norm, SYSTEM_PREFIXES):
            return Scope.SYSTEM
        if norm == "/home" or norm.startswith("/home/"):
            return Scope.HOME
        return Scope.OUTSIDE
    norm = posixpath.normpath(path)
    if norm == ".." or norm.startswith("../"):
        return Scope.OUTSIDE
    return Scope.WORKSPACE


def resolve(path: str, workspace: str) -> str:
    """Best-effort absolute form of ``path`` for display in the dry-run plan."""
    if path.startswith("/") or home_relative(path) is not None or _VAR_PREFIX.match(path):
        return path
    return posixpath.normpath(posixpath.join(workspace, path))


def _under(path: str, prefixes: tuple[str, ...]) -> bool:
    return any(path == p or path.startswith(p + "/") for p in prefixes)
