"""Record/replay provider: capture real model output once, replay it offline.

`TERMAAI_RECORD_FILE=/path.jsonl` wraps any provider — every call is appended as
a JSON record. `--provider replay` with `TERMAAI_REPLAY_FILE=/path.jsonl` serves
those captured responses verbatim (in call order), so regression tests and demos
can exercise real model output without API keys or network access.
"""

from __future__ import annotations

import json
import os
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast

from termaai.providers.base import Generation, Provider, ProviderError, Streamer


class RecordingProvider:
    """Wrap a provider and append every call to a JSONL fixture file."""

    name = "recording"

    def __init__(self, inner: Provider, path: str | Path) -> None:
        self.inner = inner
        self.path = Path(path)

    def _record(self, entry: dict[str, Any]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        # recordings hold prompts and scripts: owner-only, like the audit log
        fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        with os.fdopen(fd, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry) + "\n")

    def generate(self, request: str) -> Generation:
        gen = self.inner.generate(request)
        self._record(
            {"op": "generate", "request": request, "script": gen.script, "summary": gen.summary}
        )
        return gen

    def generate_stream(self, request: str, on_token: Callable[[str], None]) -> Generation:
        if not isinstance(self.inner, Streamer):
            raise ProviderError(f"{self.inner.name} provider cannot stream")
        gen = self.inner.generate_stream(request, on_token)
        self._record(
            {"op": "generate", "request": request, "script": gen.script, "summary": gen.summary}
        )
        return gen

    def explain(self, script: str) -> str:
        text = self.inner.explain(script)
        self._record({"op": "explain", "script": script, "response": text})
        return text

    def revise(self, request: str, script: str, problems: Sequence[str]) -> Generation:
        if not hasattr(self.inner, "revise"):
            raise ProviderError(f"{self.inner.name} provider cannot revise")
        gen = cast(Generation, self.inner.revise(request, script, problems))
        self._record(
            {
                "op": "revise",
                "request": request,
                "script": script,
                "problems": list(problems),
                "response_script": gen.script,
                "summary": gen.summary,
            }
        )
        return gen


@dataclass
class _Record:
    op: str
    payload: dict[str, Any]


class ReplayProvider:
    """Serves recorded responses in order; fails loudly on any deviation."""

    name = "replay"

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        if not self.path.exists():
            raise ProviderError(f"replay file not found: {self.path}")
        self._records: list[_Record] = []
        for i, line in enumerate(self.path.read_text(encoding="utf-8").splitlines()):
            if not line.strip():
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ProviderError(f"{self.path}:{i + 1}: invalid JSON record") from exc
            self._records.append(_Record(op=rec.get("op", ""), payload=rec))
        self._pos = 0

    def _next(self, op: str, context: str) -> _Record:
        if self._pos >= len(self._records):
            raise ProviderError(
                f"replay exhausted at record {self._pos}: unexpected {op} call ({context})"
            )
        rec = self._records[self._pos]
        if rec.op != op:
            raise ProviderError(
                f"replay mismatch at record {self._pos}: expected {op}, "
                f"the recording has {rec.op!r} — the request flow diverged"
            )
        self._pos += 1
        return rec

    def generate(self, request: str) -> Generation:
        rec = self._next("generate", request[:60])
        if rec.payload.get("request") != request:
            raise ProviderError(
                f"replay mismatch at record {self._pos - 1}: recorded request "
                f"{rec.payload.get('request')!r} != current {request!r}"
            )
        return Generation(
            script=str(rec.payload["script"]), summary=str(rec.payload.get("summary", ""))
        )

    def generate_stream(self, request: str, on_token: Callable[[str], None]) -> Generation:
        gen = self.generate(request)
        # The fixture stores the extracted script, not raw tokens: emit it whole.
        on_token(gen.script)
        return gen

    def explain(self, script: str) -> str:
        rec = self._next("explain", script[:60])
        return str(rec.payload["response"])

    def revise(self, request: str, script: str, problems: Sequence[str]) -> Generation:
        rec = self._next("revise", request[:60])
        return Generation(
            script=rec.payload["response_script"], summary=rec.payload.get("summary", "")
        )
