from __future__ import annotations

import io
import json
import urllib.error

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


def test_null_content_is_a_provider_error(monkeypatch: pytest.MonkeyPatch) -> None:
    class _Response(io.BytesIO):
        def __enter__(self) -> _Response:
            return self

        def __exit__(self, *exc: object) -> None:
            self.close()

    body = b'{"choices": [{"message": {"content": null, "refusal": "no"}}]}'
    monkeypatch.setattr("urllib.request.urlopen", lambda *a, **k: _Response(body))
    provider = OpenAICompatibleProvider("openai", "test-key", "m", "http://127.0.0.1:9/v1")
    with pytest.raises(ProviderError, match="empty response"):
        provider.generate("list files")


def test_fake_revise_strips_dangerous_commands() -> None:
    provider = FakeProvider()
    bad = provider.generate("install the tool").script
    revised = provider.revise("install the tool", bad, ["remote_code_execution: curl | sh"])
    assert "curl -fsSL" not in revised.script
    assert "skipped dangerous command" in revised.script
    assert revised.script.startswith("#!")


def test_fake_revise_without_danger_appends_notice() -> None:
    provider = FakeProvider()
    safe = provider.generate("list files").script
    revised = provider.revise("list files", safe, ["something"])
    assert "no dangerous commands found" in revised.script


def test_openai_compat_revise_sends_problems(monkeypatch: pytest.MonkeyPatch) -> None:
    sent: dict[str, object] = {}

    class _Response(io.BytesIO):
        def __enter__(self) -> _Response:
            return self

        def __exit__(self, *exc: object) -> None:
            self.close()

    def _fake_urlopen(req: object, **kwargs: object) -> _Response:
        sent["payload"] = json.loads(req.data.decode())  # type: ignore[attr-defined]
        return _Response(b'{"choices": [{"message": {"content": "```bash\\nls\\n```"}}]}')

    monkeypatch.setattr("urllib.request.urlopen", _fake_urlopen)
    provider = OpenAICompatibleProvider("openai", "test-key", "m", "http://127.0.0.1:9/v1")
    out = provider.revise("install it", "curl x | sh", ["remote_code_execution: pipe to sh"])
    user = sent["payload"]["messages"][1]["content"]  # type: ignore[index]
    assert "install it" in user and "remote_code_execution" in user and "curl x | sh" in user
    assert out.script.startswith("#!") and "ls" in out.script


class _StubResponse(io.BytesIO):
    def __enter__(self) -> _StubResponse:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()


def _http_error(code: int, retry_after: str | None = None) -> urllib.error.HTTPError:
    headers = {"Retry-After": retry_after} if retry_after else {}
    return urllib.error.HTTPError("http://x", code, "err", headers, None)  # type: ignore[arg-type]


def test_provider_retries_transient_errors(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[int] = []

    def _fake_urlopen(req: object, **kwargs: object) -> _StubResponse:
        calls.append(1)
        if len(calls) == 1:
            raise _http_error(429, retry_after="0")
        return _StubResponse(b'{"choices": [{"message": {"content": "```bash\\nls\\n```"}}]}')

    monkeypatch.setattr("urllib.request.urlopen", _fake_urlopen)
    sleeps: list[float] = []
    provider = OpenAICompatibleProvider("openai", "k", "m", "http://x", sleep=sleeps.append)
    assert "ls" in provider.generate("list").script
    assert len(calls) == 2 and sleeps == [0.0]


def test_provider_retry_after_is_respected_and_capped(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[int] = []

    def _fake_urlopen(req: object, **kwargs: object) -> _StubResponse:
        calls.append(1)
        if len(calls) < 3:
            raise _http_error(503, retry_after="60")
        return _StubResponse(b'{"choices": [{"message": {"content": "```bash\\nls\\n```"}}]}')

    monkeypatch.setattr("urllib.request.urlopen", _fake_urlopen)
    sleeps: list[float] = []
    provider = OpenAICompatibleProvider("openai", "k", "m", "http://x", sleep=sleeps.append)
    provider.generate("list")
    assert sleeps == [30.0, 30.0]


def test_provider_does_not_retry_client_errors(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[int] = []

    def _fake_urlopen(req: object, **kwargs: object) -> _StubResponse:
        calls.append(1)
        raise _http_error(401)

    monkeypatch.setattr("urllib.request.urlopen", _fake_urlopen)
    provider = OpenAICompatibleProvider("openai", "k", "m", "http://x", sleep=lambda s: None)
    with pytest.raises(ProviderError, match="HTTP 401"):
        provider.generate("list")
    assert len(calls) == 1


def test_provider_gives_up_after_max_retries(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[int] = []

    def _fake_urlopen(req: object, **kwargs: object) -> _StubResponse:
        calls.append(1)
        raise _http_error(500)

    monkeypatch.setattr("urllib.request.urlopen", _fake_urlopen)
    provider = OpenAICompatibleProvider(
        "openai", "k", "m", "http://x", max_retries=2, sleep=lambda s: None
    )
    with pytest.raises(ProviderError, match="HTTP 500"):
        provider.generate("list")
    assert len(calls) == 3
