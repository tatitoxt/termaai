"""Script providers. The offline fake provider is the default."""

from __future__ import annotations

import os
from collections.abc import Mapping

from termaai.providers.base import (
    Generation,
    Provider,
    ProviderError,
    Reviser,
    extract_script,
)
from termaai.providers.fake import FakeProvider
from termaai.providers.openai_compat import OpenAICompatibleProvider
from termaai.providers.replay import RecordingProvider, ReplayProvider

__all__ = [
    "FakeProvider",
    "Generation",
    "OpenAICompatibleProvider",
    "Provider",
    "ProviderError",
    "RecordingProvider",
    "ReplayProvider",
    "Reviser",
    "extract_script",
    "get_provider",
]

_DEFAULTS = {
    "openai": ("OPENAI_API_KEY", "https://api.openai.com/v1", "gpt-4o-mini"),
    "groq": ("GROQ_API_KEY", "https://api.groq.com/openai/v1", "llama-3.1-8b-instant"),
}
PROVIDER_NAMES = ("fake", "replay", *_DEFAULTS)


def get_provider(name: str | None = None, env: Mapping[str, str] | None = None) -> Provider:
    """Build a provider from ``name`` or ``$TERMAAI_PROVIDER`` (default: ``fake``)."""
    env = os.environ if env is None else env
    choice = (name or env.get("TERMAAI_PROVIDER") or "fake").lower()
    if choice == "fake":
        return FakeProvider()
    if choice == "replay":
        return ReplayProvider(env.get("TERMAAI_REPLAY_FILE") or "termaai-replay.jsonl")
    if choice not in _DEFAULTS:
        raise ProviderError(
            f"unknown provider {choice!r}; choose one of {', '.join(PROVIDER_NAMES)}"
        )
    key_var, base_url, model = _DEFAULTS[choice]
    api_key = env.get(key_var, "")
    if not api_key:
        raise ProviderError(f"{choice} provider selected but {key_var} is not set")
    prefix = f"TERMAAI_{choice.upper()}_"
    provider: Provider = OpenAICompatibleProvider(
        name=choice,
        api_key=api_key,
        model=env.get("TERMAAI_MODEL") or env.get(prefix + "MODEL") or model,
        base_url=env.get(prefix + "BASE_URL") or base_url,
    )
    if record_file := env.get("TERMAAI_RECORD_FILE"):
        provider = RecordingProvider(provider, record_file)
    return provider
