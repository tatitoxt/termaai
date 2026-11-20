from __future__ import annotations

import os
import time
import tracemalloc
from pathlib import Path

import pytest

from termaai.executor import (
    TIMEOUT_EXIT_CODE,
    DockerExecutor,
    Executor,
    Limits,
    SandboxError,
    SubprocessExecutor,
    select_executor,
)


@pytest.fixture(params=["subprocess", pytest.param("docker", marks=pytest.mark.docker)])
def executor(request: pytest.FixtureRequest) -> Executor:
    if request.param == "docker":
        request.getfixturevalue("docker_ready")
        return DockerExecutor()
    return SubprocessExecutor()


def test_runs_in_workspace_and_captures_output(executor: Executor, tmp_path: Path) -> None:
    result = executor.run(
        "echo out; echo err >&2; printf data > made.txt; echo $TERMAAI_SANDBOX\n",
        tmp_path,
        Limits(timeout=20),
    )
    assert result.exit_code == 0
    assert result.stdout.splitlines() == ["out", executor.name]
    assert result.stderr.strip() == "err"
    assert (tmp_path / "made.txt").read_text() == "data"
    assert result.sandbox == executor.name


def test_propagates_exit_code(executor: Executor, tmp_path: Path) -> None:
    assert executor.run("exit 7\n", tmp_path, Limits(timeout=20)).exit_code == 7


def test_timeout_kills_script(executor: Executor, tmp_path: Path) -> None:
    result = executor.run("sleep 30\n", tmp_path, Limits(timeout=2))
    assert result.timed_out
    assert result.exit_code == TIMEOUT_EXIT_CODE
    assert result.duration_s < 15


def test_files_are_owned_by_the_invoking_user(executor: Executor, tmp_path: Path) -> None:
    executor.run("touch owned.txt\n", tmp_path, Limits(timeout=20))
    assert (tmp_path / "owned.txt").stat().st_uid == os.getuid()


def test_subprocess_env_is_scrubbed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SUPER_SECRET_TOKEN", "should-not-leak")
    result = SubprocessExecutor().run("env\n", tmp_path, Limits(timeout=10))
    assert "SUPER_SECRET_TOKEN" not in result.stdout
    assert f"HOME={tmp_path}" in result.stdout


def test_subprocess_file_size_limit(tmp_path: Path) -> None:
    result = SubprocessExecutor().run(
        "head -c 3000000 /dev/zero > big.bin\n", tmp_path, Limits(timeout=10, file_size_mb=1)
    )
    assert result.exit_code != 0
    assert (tmp_path / "big.bin").stat().st_size <= 1024 * 1024


@pytest.mark.docker
@pytest.mark.usefixtures("docker_ready")
class TestDockerIsolation:
    def test_has_no_network(self, tmp_path: Path) -> None:
        script = "cat /sys/class/net/*/operstate 2>/dev/null | sort -u; ls /sys/class/net\n"
        result = DockerExecutor().run(script, tmp_path, Limits(timeout=20))
        assert result.stdout.split() == ["unknown", "lo"] or result.stdout.split() == ["lo"]

    def test_root_filesystem_is_read_only(self, tmp_path: Path) -> None:
        result = DockerExecutor().run("touch /etc/evil\n", tmp_path, Limits(timeout=20))
        assert result.exit_code != 0
        assert "Read-only file system" in result.stderr

    def test_host_paths_outside_workspace_are_invisible(self, tmp_path: Path) -> None:
        marker = tmp_path.parent / "outside-marker.txt"
        marker.write_text("host")
        result = DockerExecutor().run(
            f"cat {marker} || echo missing\n", tmp_path, Limits(timeout=20)
        )
        assert "missing" in result.stdout

    def test_cgroup_limits_are_applied(self, tmp_path: Path) -> None:
        script = "cat /sys/fs/cgroup/pids.max /sys/fs/cgroup/memory.max /sys/fs/cgroup/cpu.max\n"
        result = DockerExecutor().run(
            script, tmp_path, Limits(timeout=20, pids=32, memory_mb=64, cpus=0.5)
        )
        if result.exit_code != 0:
            pytest.skip("cgroup v2 interface files not visible in this Docker setup")
        assert result.stdout.split() == ["32", str(64 * 1024 * 1024), "50000", "100000"]

    def test_command_line_sets_limits(self, tmp_path: Path) -> None:
        cmd = DockerExecutor(image="img").command(
            tmp_path, tmp_path / "s.sh", Limits(memory_mb=64, cpus=0.5, pids=10), "n"
        )
        joined = " ".join(cmd)
        for flag in (
            "--network none",
            "--memory 64m",
            "--cpus 0.5",
            "--pids-limit 10",
            "--cap-drop ALL",
            "--read-only",
            f"{tmp_path.resolve()}:/workspace:rw",
        ):
            assert flag in joined


def test_select_executor_modes(monkeypatch: pytest.MonkeyPatch) -> None:
    assert isinstance(select_executor("subprocess"), SubprocessExecutor)
    monkeypatch.setattr("termaai.executor.docker_available", lambda docker="docker": False)
    assert isinstance(select_executor("auto"), SubprocessExecutor)
    with pytest.raises(SandboxError, match="not reachable"):
        select_executor("docker")
    with pytest.raises(SandboxError, match="unknown sandbox"):
        select_executor("vm")
    monkeypatch.setattr("termaai.executor.docker_available", lambda docker="docker": True)
    assert isinstance(select_executor("auto"), DockerExecutor)


def test_missing_image_raises(tmp_path: Path, docker_ready: None) -> None:
    with pytest.raises(SandboxError, match="cannot pull"):
        DockerExecutor(image="termaai-test/does-not-exist:never").ensure_image()



def test_script_file_is_private_to_the_user(executor: Executor, tmp_path: Path) -> None:
    result = executor.run('stat -c %a "$0"\n', tmp_path, Limits(timeout=20))
    assert result.exit_code == 0
    assert result.stdout.strip() == "600"
