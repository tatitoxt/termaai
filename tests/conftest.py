from __future__ import annotations

import os
from pathlib import Path

import pytest

from termaai.executor import DockerExecutor, SandboxError, docker_available


@pytest.fixture(autouse=True)
def isolated_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    home = tmp_path / "termaai-home"
    monkeypatch.setenv("TERMAAI_HOME", str(home))
    monkeypatch.delenv("TERMAAI_PROVIDER", raising=False)
    return home


def _docker_ready() -> str | None:
    if not docker_available():
        return "Docker daemon not reachable"
    try:
        DockerExecutor().ensure_image()
    except SandboxError as exc:
        return str(exc)
    return None


@pytest.fixture(scope="session")
def docker_ready() -> None:
    reason = _docker_ready()
    if reason is None:
        return
    if os.environ.get("TERMAAI_REQUIRE_DOCKER") == "1":
        pytest.fail(f"TERMAAI_REQUIRE_DOCKER=1 but Docker is unusable: {reason}")
    pytest.skip(reason)
