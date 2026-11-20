"""Sandboxed execution backends.

* :class:`DockerExecutor` runs the script in a throwaway container with no network,
  dropped capabilities, a read-only root filesystem and CPU/memory/PID/time limits;
  only the workspace is bind-mounted (read-write).
* :class:`SubprocessExecutor` is the fallback when Docker is unavailable: ``bash`` in the
  workspace with a scrubbed environment, rlimits and a timeout. It is a guard-rail, not a
  security boundary.
"""

from __future__ import annotations

import contextlib
import os
import resource
import shutil
import signal
import subprocess
import tempfile
import threading
import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import IO, Any, Protocol

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


def _pump(stream: IO[bytes], sink: bytearray) -> None:
    """Drain ``stream`` completely but keep at most OUTPUT_LIMIT + 1 bytes in memory."""
    while chunk := stream.read(65536):
        room = OUTPUT_LIMIT + 1 - len(sink)
        if room > 0:
            sink.extend(chunk[:room])
    stream.close()


def _text(data: bytes | bytearray) -> str:
    text = bytes(data[:OUTPUT_LIMIT]).decode("utf-8", errors="replace")
    if len(data) > OUTPUT_LIMIT:
        text += f"\n[termaai: output truncated at {OUTPUT_LIMIT} bytes]\n"
    return text


def _run_capped(
    argv: list[str],
    timeout: float,
    on_timeout: Callable[[subprocess.Popen[bytes]], None],
    after_exit: Callable[[subprocess.Popen[bytes]], None] | None = None,
    **popen_kwargs: Any,
) -> tuple[int, str, str, bool]:
    """Run ``argv`` with bounded output capture; returns (exit code, stdout, stderr, timed out)."""
    proc = subprocess.Popen(
        argv,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        **popen_kwargs,
    )
    assert proc.stdout is not None and proc.stderr is not None
    out, err = bytearray(), bytearray()
    pumps = [
        threading.Thread(target=_pump, args=(proc.stdout, out), daemon=True),
        threading.Thread(target=_pump, args=(proc.stderr, err), daemon=True),
    ]
    for t in pumps:
        t.start()
    timed_out = False
    try:
        code = proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        on_timeout(proc)
        code = proc.wait()
    if after_exit is not None:
        after_exit(proc)
    for t in pumps:
        t.join(timeout=5)
    return (TIMEOUT_EXIT_CODE if timed_out else code), _text(out), _text(err), timed_out


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
        workspace = workspace.resolve()
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

        def kill_group(proc: subprocess.Popen[bytes]) -> None:
            # Also reaps background jobs the script left behind.
            with contextlib.suppress(ProcessLookupError, PermissionError):
                os.killpg(proc.pid, signal.SIGKILL)

        start = time.monotonic()
        try:
            code, stdout, stderr, timed_out = _run_capped(
                [self.bash, "--noprofile", "--norc", str(script_path)],
                limits.timeout,
                on_timeout=kill_group,
                after_exit=kill_group,
                cwd=workspace,
                env=env,
                start_new_session=True,
                preexec_fn=apply_limits,
            )
        finally:
            shutil.rmtree(script_path.parent, ignore_errors=True)
        return ExecutionResult(
            sandbox=self.name,
            exit_code=code,
            stdout=stdout,
            stderr=stderr,
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

        def remove_container(proc: subprocess.Popen[bytes]) -> None:
            subprocess.run([self.docker, "rm", "-f", name], capture_output=True, check=False)
            proc.kill()

        start = time.monotonic()
        try:
            code, stdout, stderr, timed_out = _run_capped(
                self.command(workspace, script_path, limits, name),
                limits.timeout,
                on_timeout=remove_container,
            )
        finally:
            shutil.rmtree(script_path.parent, ignore_errors=True)
        return ExecutionResult(
            sandbox=self.name,
            exit_code=code,
            stdout=stdout,
            stderr=stderr,
            duration_s=round(time.monotonic() - start, 3),
            timed_out=timed_out,
        )


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
