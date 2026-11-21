from __future__ import annotations

import hashlib
import json
import stat
from pathlib import Path

import pytest

from termaai.audit import AuditLog, AuditRecord, history_path


def test_append_and_read_roundtrip(tmp_path: Path) -> None:
    log = AuditLog(tmp_path / "sub" / "history.jsonl")
    assert log.read() == []
    for i in range(3):
        log.append(AuditRecord(kind="ask", decision="executed", risk_level="LOW", script=f"{i}"))
    entries = log.read()
    assert [e["script"] for e in entries] == ["0", "1", "2"]
    assert entries[0]["script_sha256"] == hashlib.sha256(b"0").hexdigest()
    assert [e["script"] for e in log.read(limit=2)] == ["1", "2"]
    assert stat.S_IMODE(log.path.stat().st_mode) == 0o600


def test_corrupt_lines_are_skipped(tmp_path: Path) -> None:
    path = tmp_path / "h.jsonl"
    path.write_text('{"kind": "ask"}\nnot json\n\n' + json.dumps({"kind": "explain"}) + "\n")
    assert [e["kind"] for e in AuditLog(path).read()] == ["ask", "explain"]


def test_history_path_env(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("TERMAAI_HOME", str(tmp_path))
    assert history_path() == tmp_path / "history.jsonl"
    monkeypatch.delenv("TERMAAI_HOME")
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg"))
    assert history_path() == tmp_path / "xdg" / "termaai" / "history.jsonl"
