from __future__ import annotations

import pytest

from termaai.providers import (
    FakeProvider,
    OpenAICompatibleProvider,
    ProviderError,
    extract_script,
    get_provider,
)
from termaai.safety.checks import check_syntax


def test_fake_provider_is_deterministic() -> None:
    fake = FakeProvider()
    assert fake.generate("list files") == fake.generate("list files")
    assert "ls -la" in fake.generate("please list my files").script


@pytest.mark.parametrize(
    "request_text",
    ["list files", "create a note", "count lines", "disk usage", "backup", "install it", "xyz"],
)
def test_fake_scripts_parse(request_text: str) -> None:
    assert check_syntax(FakeProvider().generate(request_text).script).ok


def test_fake_unknown_request_is_quoted_safely() -> None:
    gen = FakeProvider().generate("say $(rm -rf /) 'quoted'")
    assert "printf '%s\\n'" in gen.script
    assert "$(rm" in gen.script
    assert gen.script.count("'\"'\"'") == 2


def test_fake_explain_describes_commands() -> None:
    text = FakeProvider().explain("ls -la\nsudo rm -f x\n")
    assert "line 1: `ls -la` - lists directory contents" in text
    assert "(via sudo)" in text
    assert FakeProvider().explain("# nothing\n") == "The script does not run any commands."


def test_extract_script_from_fenced_reply() -> None:
    reply = "Sure!\n```bash\nls -la\n```\nDone."
    assert extract_script(reply) == "#!/usr/bin/env bash\nls -la\n"
    assert extract_script("#!/bin/sh\necho hi") == "#!/bin/sh\necho hi\n"


def test_get_provider_defaults_to_fake() -> None:
    assert get_provider(env={}).name == "fake"
    assert get_provider("FAKE", env={}).name == "fake"


def test_get_provider_requires_api_key_for_real_providers() -> None:
    with pytest.raises(ProviderError, match="GROQ_API_KEY"):
        get_provider("groq", env={})
    with pytest.raises(ProviderError, match="unknown provider"):
        get_provider("nope", env={})


def test_get_provider_reads_env_configuration() -> None:
    provider = get_provider(
        env={
            "TERMAAI_PROVIDER": "openai",
            "OPENAI_API_KEY": "test-key",
            "TERMAAI_MODEL": "my-model",
            "TERMAAI_OPENAI_BASE_URL": "http://127.0.0.1:9/v1/",
        }
    )
    assert isinstance(provider, OpenAICompatibleProvider)
    assert provider.model == "my-model"
    assert provider.base_url == "http://127.0.0.1:9/v1"
    groq = get_provider("groq", env={"GROQ_API_KEY": "k"})
    assert isinstance(groq, OpenAICompatibleProvider)
    assert groq.base_url == "https://api.groq.com/openai/v1"
