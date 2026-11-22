"""Streamed model tokens are shown without terminal control sequences."""

from __future__ import annotations

import io
from pathlib import Path

from rich.console import Console

from termaai.assistant import Assistant
from termaai.audit import AuditLog
from termaai.providers.fake import FakeProvider


def test_streamed_tokens_drop_terminal_escapes(tmp_path: Path) -> None:
    out = io.StringIO()
    assistant = Assistant(Console(file=out), FakeProvider(), AuditLog(tmp_path / "h.jsonl"))
    assistant._emit_token("ls\x1b]52;c;cm0gLXJmIH4=\x07 -la\r\n\tdone\x9b2J")
    assert out.getvalue() == "ls]52;c;cm0gLXJmIH4= -la\n\tdone2J"
