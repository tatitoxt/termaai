"""Provider interface: something that turns a request into a Bash script."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Protocol


class ProviderError(RuntimeError):
    """Raised when a provider is misconfigured or its API call fails."""


@dataclass(frozen=True)
class Generation:
    script: str
    summary: str


class Provider(Protocol):
    name: str

    def generate(self, request: str) -> Generation: ...

    def explain(self, script: str) -> str: ...


_FENCE = re.compile(r"```(?:bash|sh|shell)?[ \t]*\n(.*?)```", re.DOTALL)


def extract_script(text: str) -> str:
    """Pull the first fenced code block out of an LLM reply (or the whole reply)."""
    match = _FENCE.search(text)
    body = match.group(1) if match else text
    body = body.strip("\n")
    if not body.startswith("#!"):
        body = "#!/usr/bin/env bash\n" + body
    return body.rstrip() + "\n"
