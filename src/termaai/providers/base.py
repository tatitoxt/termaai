"""Provider interface: something that turns a request into a Bash script."""

from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Protocol, runtime_checkable


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


@runtime_checkable
class Reviser(Protocol):
    """Optional provider capability: rewrite a script after the analyzer
    rejected it. `problems` is a human-readable list of findings the new
    version must address while still doing what the request asked for."""

    def revise(self, request: str, script: str, problems: Sequence[str]) -> Generation: ...


_FENCE = re.compile(r"```(?:bash|sh|shell)?[ \t]*\n(.*?)```", re.DOTALL)


def extract_script(text: str) -> str:
    """Pull the first fenced code block out of an LLM reply (or the whole reply)."""
    match = _FENCE.search(text)
    body = match.group(1) if match else text
    body = body.strip("\n")
    if not body.startswith("#!"):
        body = "#!/usr/bin/env bash\n" + body
    return body.rstrip() + "\n"
