"""External static checks: ``bash -n`` syntax validation and optional ShellCheck."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field


@dataclass(frozen=True)
class SyntaxResult:
    ok: bool
    message: str = ""


@dataclass(frozen=True)
class ShellCheckIssue:
    line: int
    level: str
    code: int
    message: str

    def to_dict(self) -> dict[str, object]:
        return {"line": self.line, "level": self.level, "code": f"SC{self.code}"}


@dataclass
class ShellCheckResult:
    available: bool
    issues: list[ShellCheckIssue] = field(default_factory=list)
    error: str = ""

    @property
    def has_errors(self) -> bool:
        return any(i.level == "error" for i in self.issues)


def _with_temp_script(script: str) -> str:
    fd, path = tempfile.mkstemp(prefix="termaai-check-", suffix=".sh")
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(script)
    return path


def check_syntax(script: str, bash: str = "bash") -> SyntaxResult:
    """Parse the script with ``bash -n`` without executing it."""
    path = _with_temp_script(script)
    try:
        proc = subprocess.run(
            [bash, "-n", path], capture_output=True, text=True, timeout=10, check=False
        )
    finally:
        os.unlink(path)
    if proc.returncode == 0:
        return SyntaxResult(ok=True)
    message = proc.stderr.replace(path, "script").strip()
    return SyntaxResult(ok=False, message=message or "bash -n failed")


def shellcheck_binary() -> str | None:
    override = os.environ.get("TERMAAI_SHELLCHECK")
    if override is not None:
        return shutil.which(override) if override else None
    return shutil.which("shellcheck")


def run_shellcheck(script: str) -> ShellCheckResult:
    """Run ShellCheck when installed; report ``available=False`` otherwise."""
    binary = shellcheck_binary()
    if binary is None:
        return ShellCheckResult(available=False)
    path = _with_temp_script(script)
    try:
        proc = subprocess.run(
            [binary, "--format=json", "--shell=bash", path],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return ShellCheckResult(available=True, error="shellcheck timed out")
    finally:
        os.unlink(path)
    try:
        raw = json.loads(proc.stdout or "[]")
    except json.JSONDecodeError:
        return ShellCheckResult(available=True, error=proc.stderr.strip() or "invalid output")
    issues = [
        ShellCheckIssue(
            line=int(item.get("line", 0)),
            level=str(item.get("level", "info")),
            code=int(item.get("code", 0)),
            message=str(item.get("message", "")),
        )
        for item in raw
    ]
    return ShellCheckResult(available=True, issues=issues)
