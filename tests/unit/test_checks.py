from __future__ import annotations

import shutil

import pytest

from termaai.safety.checks import check_syntax, run_shellcheck


def test_syntax_ok_and_error() -> None:
    assert check_syntax("echo hi\n").ok
    result = check_syntax("if true; then\n echo x\n")
    assert not result.ok
    assert "syntax error" in result.message
    assert "termaai-check" not in result.message


def test_shellcheck_disabled_via_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TERMAAI_SHELLCHECK", "")
    assert run_shellcheck("echo $1\n").available is False


@pytest.mark.skipif(shutil.which("shellcheck") is None, reason="shellcheck not installed")
def test_shellcheck_reports_issues(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("TERMAAI_SHELLCHECK", raising=False)
    result = run_shellcheck("#!/bin/bash\necho $1\n")
    assert result.available
    assert [i.code for i in result.issues] == [2086]
    assert result.issues[0].to_dict() == {"line": 2, "level": "info", "code": "SC2086"}
    assert not result.has_errors
