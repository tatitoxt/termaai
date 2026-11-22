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


def test_rotation_on_size_cap(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TERMAAI_AUDIT_MAX_BYTES", "200")
    monkeypatch.setenv("TERMAAI_AUDIT_KEEP", "2")
    log = AuditLog(tmp_path / "history.jsonl")

    for i in range(30):
        log.append(
            AuditRecord(
                kind="ask", decision="executed", risk_level="LOW", script=f"echo {i} " + "x" * 40
            )
        )

    live = tmp_path / "history.jsonl"
    seg1 = tmp_path / "history.1.jsonl"
    assert live.exists() and seg1.exists()
    # Only `keep` segments may exist.
    assert not (tmp_path / "history.3.jsonl").exists()
    # Entries beyond keep are dropped; the newest ones always survive, ordered.
    all_entries = log.read(archived=True)
    assert 0 < len(all_entries) < 30
    last_script = all_entries[-1]["script"]
    assert last_script.startswith("echo 29")
    # Live file only has post-rotation entries.
    live_entries = log.read()
    assert 0 < len(live_entries) < len(all_entries)


def test_rotation_disabled_when_zero(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TERMAAI_AUDIT_MAX_BYTES", "0")
    log = AuditLog(tmp_path / "history.jsonl")
    for i in range(5):
        log.append(AuditRecord(kind="ask", decision="executed", risk_level="LOW", script=str(i)))
    assert not (tmp_path / "history.1.jsonl").exists()
    assert len(log.read()) == 5


def test_read_archived_oldest_first(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TERMAAI_AUDIT_MAX_BYTES", "150")
    monkeypatch.setenv("TERMAAI_AUDIT_KEEP", "10")
    log = AuditLog(tmp_path / "history.jsonl")
    for i in range(10):
        log.append(
            AuditRecord(
                kind="ask", decision="executed", risk_level="LOW", script=f"cmd{i} " + "y" * 30
            )
        )
    archived = log.read(archived=True)
    assert [e["script"][:4] for e in archived] == [f"cmd{i}" for i in range(10)]


def test_rotation_prunes_segments_above_a_reduced_keep(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    for n in range(1, 6):
        (tmp_path / f"history.{n}.jsonl").write_text("{}\n")
    (tmp_path / "history.jsonl").write_text("x" * 300 + "\n")
    monkeypatch.setenv("TERMAAI_AUDIT_MAX_BYTES", "200")
    monkeypatch.setenv("TERMAAI_AUDIT_KEEP", "2")
    AuditLog(tmp_path / "history.jsonl").append(
        AuditRecord(kind="ask", decision="executed", risk_level="LOW", script="echo")
    )
    assert sorted(p.name for p in tmp_path.glob("history.*.jsonl")) == [
        "history.1.jsonl",
        "history.2.jsonl",
    ]


def test_rotation_tolerates_a_concurrent_rotation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    live = tmp_path / "history.jsonl"
    live.write_text("x" * 300 + "\n")
    monkeypatch.setenv("TERMAAI_AUDIT_MAX_BYTES", "200")
    log = AuditLog(live)
    real_replace = Path.replace

    def _racing_replace(self: Path, target: Path) -> Path:
        if self == live:  # another process rotated the live file first
            real_replace(self, target)
            raise FileNotFoundError(str(self))
        return real_replace(self, target)

    monkeypatch.setattr(Path, "replace", _racing_replace)
    log.append(AuditRecord(kind="ask", decision="executed", risk_level="LOW", script="echo"))
    assert [e["script"] for e in log.read()] == ["echo"]
