"""Append-only JSONL audit log of prompts, scripts, risk decisions and exit codes."""

from __future__ import annotations

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
    sandbox: str | None = None
    exit_code: int | None = None
    duration_s: float | None = None
    timed_out: bool = False
    workspace: str | None = None
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


class AuditLog:
    def __init__(self, path: Path | None = None) -> None:
        self.path = path or history_path()

    def append(self, record: AuditRecord) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        with os.fdopen(fd, "a", encoding="utf-8") as fh:
            fh.write(record.to_json() + "\n")

    def read(self, limit: int | None = None) -> list[dict[str, Any]]:
        if not self.path.exists():
            return []
        entries: list[dict[str, Any]] = []
        with self.path.open(encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    entries.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
        return entries[-limit:] if limit else entries
