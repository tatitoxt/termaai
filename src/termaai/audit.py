"""Append-only JSONL audit log of prompts, scripts, risk decisions and exit codes."""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def data_dir() -> Path:
    if os.environ.get("TERMAAI_HOME"):
        return Path(os.environ["TERMAAI_HOME"])
    base = os.environ.get("XDG_DATA_HOME") or str(Path.home() / ".local" / "share")
    return Path(base) / "termaai"


def history_path() -> Path:
    return data_dir() / "history.jsonl"


@dataclass
class AuditRecord:
    kind: str
    decision: str
    risk_level: str
    script: str
    prompt: str | None = None
    provider: str | None = None
    source: str | None = None
    findings: list[dict[str, object]] = field(default_factory=list)
    shellcheck: list[dict[str, object]] = field(default_factory=list)
    syntax_ok: bool = True
    forced: bool = False
    dry_run: bool = False
    revisions: int = 0
    edited: bool = False
    sandbox: str | None = None
    exit_code: int | None = None
    duration_s: float | None = None
    timed_out: bool = False
    workspace: str | None = None
    policy: str | None = None
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(timespec="seconds")
    )

    @property
    def script_sha256(self) -> str:
        return hashlib.sha256(self.script.encode()).hexdigest()

    def to_json(self) -> str:
        data = asdict(self)
        data["script_sha256"] = self.script_sha256
        return json.dumps(data, sort_keys=True)


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, "") or default)
    except ValueError:
        return default


class AuditLog:
    """Append-only JSONL audit log with size-based segment rotation.

    When the live file grows past ``TERMAAI_AUDIT_MAX_BYTES`` (default 10 MiB,
    ``0`` disables rotation) it is renamed to ``<name>.1.jsonl`` and a fresh
    file starts; up to ``TERMAAI_AUDIT_KEEP`` (default 5) numbered segments are
    kept, oldest dropped.
    """

    def __init__(self, path: Path | None = None) -> None:
        self.path = path or history_path()

    def _segment(self, n: int) -> Path:
        return self.path.with_name(f"{self.path.stem}.{n}{self.path.suffix}")

    def _rotate(self) -> None:
        max_bytes = _env_int("TERMAAI_AUDIT_MAX_BYTES", 10 * 1024 * 1024)
        if max_bytes <= 0 or not self.path.exists() or self.path.stat().st_size <= max_bytes:
            return
        keep = max(1, _env_int("TERMAAI_AUDIT_KEEP", 5))
        # drop the oldest segment plus any left over from a larger previous keep
        n = keep
        while n == keep or self._segment(n).exists():
            self._segment(n).unlink(missing_ok=True)
            n += 1
        # another process may rotate concurrently; a segment that vanished
        # between the size check and the rename was already moved by it
        for n in range(keep - 1, 0, -1):
            with contextlib.suppress(FileNotFoundError):
                self._segment(n).replace(self._segment(n + 1))
        with contextlib.suppress(FileNotFoundError):
            self.path.replace(self._segment(1))

    def append(self, record: AuditRecord) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._rotate()
        fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        with os.fdopen(fd, "a", encoding="utf-8") as fh:
            fh.write(record.to_json() + "\n")

    def _read_file(self, path: Path) -> list[dict[str, Any]]:
        entries: list[dict[str, Any]] = []
        with path.open(encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    entries.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
        return entries

    def read(self, limit: int | None = None, archived: bool = False) -> list[dict[str, Any]]:
        """Live entries, oldest first. With ``archived`` the rotated segments are
        included (oldest segment first, live file last)."""
        entries: list[dict[str, Any]] = []
        if archived:
            for n in range(_env_int("TERMAAI_AUDIT_KEEP", 5), 0, -1):
                seg = self._segment(n)
                if seg.exists():
                    entries.extend(self._read_file(seg))
        if self.path.exists():
            entries.extend(self._read_file(self.path))
        return entries[-limit:] if limit else entries
