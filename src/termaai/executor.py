"""Sandboxed execution backends.

* :class:`DockerExecutor` runs the script in a throwaway container with no network,
  dropped capabilities, a read-only root filesystem and CPU/memory/PID/time limits;
  only the workspace is bind-mounted (read-write).
* :class:`SubprocessExecutor` is the fallback when Docker is unavailable: ``bash`` in the
  workspace with a scrubbed environment, rlimits and a timeout. It is a guard-rail, not a
  security boundary.
"""

from __future__ import annotations

import os
import resource
import shutil
import signal
import subprocess
import tempfile
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

DEFAULT_IMAGE = "bash:5.2"
TIMEOUT_EXIT_CODE = 124
OUTPUT_LIMIT = 64 * 1024


@dataclass(frozen=True)
class Limits:
    timeout: float = 30.0
    memory_mb: int = 256
    cpus: float = 1.0
    pids: int = 128
    file_size_mb: int = 64


@dataclass(frozen=True)
class ExecutionResult:
    sandbox: str
    exit_code: int
    stdout: str
    stderr: str
    duration_s: float
    timed_out: bool = False


class Executor(Protocol):
    name: str

    def run(self, script: str, workspace: Path, limits: Limits) -> ExecutionResult: ...


class SandboxError(RuntimeError):
    pass


def _truncate(text: str) -> str:
    if len(text) <= OUTPUT_LIMIT:
        return text
    return text[:OUTPUT_LIMIT] + f"\n[termaai: output truncated at {OUTPUT_LIMIT} bytes]\n"


def _write_script(script: str) -> Path:
    directory = Path(tempfile.mkdtemp(prefix="termaai-script-"))
    path = directory / "script.sh"
    path.write_text(script, encoding="utf-8")
    path.chmod(0o600)
    directory.chmod(0o700)
    return path


class SubprocessExecutor:
    name = "subprocess"

    def __init__(self, bash: str | None = None) -> None:
        self.bash = bash or shutil.which("bash") or "/bin/bash"

    def run(self, script: str, workspace: Path, limits: Limits) -> ExecutionResult:
        script_path = _write_script(script)
        env = {
            "PATH": "/usr/local/bin:/usr/bin:/bin",
            "HOME": str(workspace),
            "LANG": "C.UTF-8",
            "TERM": "dumb",
            "TERMAAI_SANDBOX": self.name,
        }

        def apply_limits() -> None:
            cpu = int(limits.timeout) + 1
            mem = limits.memory_mb * 1024 * 1024
            fsize = limits.file_size_mb * 1024 * 1024
            resource.setrlimit(resource.RLIMIT_CPU, (cpu, cpu))
            resource.setrlimit(resource.RLIMIT_AS, (mem * 4, mem * 4))
            resource.setrlimit(resource.RLIMIT_FSIZE, (fsize, fsize))
            resource.setrlimit(resource.RLIMIT_CORE, (0, 0))

        start = time.monotonic()
        proc = subprocess.Popen(
            [self.bash, "--noprofile", "--norc", str(script_path)],
            cwd=workspace,
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            start_new_session=True,
            preexec_fn=apply_limits,
        )
        timed_out = False
        try:
            stdout, stderr = proc.communicate(timeout=limits.timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            os.killpg(proc.pid, signal.SIGKILL)
            stdout, stderr = proc.communicate()
        finally:
            shutil.rmtree(script_path.parent, ignore_errors=True)
        return ExecutionResult(
            sandbox=self.name,
            exit_code=TIMEOUT_EXIT_CODE if timed_out else proc.returncode,
            stdout=_truncate(stdout),
            stderr=_truncate(stderr),
            duration_s=round(time.monotonic() - start, 3),
            timed_out=timed_out,
        )


class DockerExecutor:
    name = "docker"

    def __init__(self, image: str | None = None, docker: str = "docker") -> None:
        self.image = image or os.environ.get("TERMAAI_SANDBOX_IMAGE") or DEFAULT_IMAGE
        self.docker = docker

    def command(self, workspace: Path, script_path: Path, limits: Limits, name: str) -> list[str]:
        return [
            self.docker,
            "run",
            "--rm",
            "--name",
            name,
            "--network",
            "none",
            "--memory",
            f"{limits.memory_mb}m",
            "--memory-swap",
            f"{limits.memory_mb}m",
            "--cpus",
            str(limits.cpus),
            "--pids-limit",
            str(limits.pids),
            "--ulimit",
            f"fsize={limits.file_size_mb * 1024 * 1024}",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges",
            "--read-only",
            "--tmpfs",
            "/tmp:rw,size=64m",
            "--user",
            f"{os.getuid()}:{os.getgid()}",
            "-e",
            "HOME=/workspace",
            "-e",
            f"TERMAAI_SANDBOX={self.name}",
            "-v",
            f"{workspace.resolve()}:/workspace:rw",
            "-v",
            f"{script_path}:/termaai/script.sh:ro",
            "-w",
            "/workspace",
            self.image,
            "bash",
            "--noprofile",
            "--norc",
            "/termaai/script.sh",
        ]

    def ensure_image(self) -> None:
        inspect = subprocess.run(
            [self.docker, "image", "inspect", self.image], capture_output=True, check=False
        )
        if inspect.returncode == 0:
            return
        pull = subprocess.run(
            [self.docker, "pull", self.image], capture_output=True, text=True, check=False
        )
        if pull.returncode != 0:
            raise SandboxError(f"cannot pull sandbox image {self.image}: {pull.stderr.strip()}")

    def run(self, script: str, workspace: Path, limits: Limits) -> ExecutionResult:
        self.ensure_image()
        script_path = _write_script(script)
        name = f"termaai-{uuid.uuid4().hex[:12]}"
        start = time.monotonic()
        timed_out = False
        try:
            proc = subprocess.run(
                self.command(workspace, script_path, limits, name),
                capture_output=True,
                text=True,
                timeout=limits.timeout,
                check=False,
            )
            stdout, stderr, code = proc.stdout, proc.stderr, proc.returncode
        except subprocess.TimeoutExpired as exc:
            timed_out = True
            subprocess.run([self.docker, "rm", "-f", name], capture_output=True, check=False)
            stdout = _decode(exc.stdout)
            stderr = _decode(exc.stderr)
            code = TIMEOUT_EXIT_CODE
        finally:
            shutil.rmtree(script_path.parent, ignore_errors=True)
        return ExecutionResult(
            sandbox=self.name,
            exit_code=code,
            stdout=_truncate(stdout),
            stderr=_truncate(stderr),
            duration_s=round(time.monotonic() - start, 3),
            timed_out=timed_out,
        )


def _decode(data: bytes | str | None) -> str:
    if data is None:
        return ""
    return data if isinstance(data, str) else data.decode(errors="replace")


def docker_available(docker: str = "docker") -> bool:
    if shutil.which(docker) is None:
        return False
    try:
        proc = subprocess.run(
            [docker, "info", "--format", "{{.ServerVersion}}"],
            capture_output=True,
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    return proc.returncode == 0


def select_executor(mode: str = "auto") -> Executor:
    """Pick a backend: ``docker``, ``subprocess`` or ``auto`` (Docker when available)."""
    if mode == "subprocess":
        return SubprocessExecutor()
    if mode == "docker":
        if not docker_available():
            raise SandboxError("Docker sandbox requested but the Docker daemon is not reachable")
        return DockerExecutor()
    if mode != "auto":
        raise SandboxError(f"unknown sandbox mode {mode!r}")
    return DockerExecutor() if docker_available() else SubprocessExecutor()
