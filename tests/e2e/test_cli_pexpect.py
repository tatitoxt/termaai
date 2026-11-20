"""End-to-end tests: spawn the installed ``termaai`` entrypoint in a pseudo-terminal and
answer its prompts like a user would."""

from __future__ import annotations

import json
import os
import shutil
import sys
from pathlib import Path

import pexpect
import pytest

pytestmark = pytest.mark.e2e

BIN = shutil.which("termaai", path=os.path.dirname(sys.executable)) or shutil.which("termaai")
if BIN is None:
    pytest.skip("termaai entrypoint is not installed (pip install -e .)", allow_module_level=True)


@pytest.fixture(params=["subprocess", pytest.param("docker", marks=pytest.mark.docker)])
def sandbox(request: pytest.FixtureRequest) -> str:
    if request.param == "docker":
        request.getfixturevalue("docker_ready")
    return str(request.param)


def spawn(args: list[str], home: Path, timeout: float = 60) -> pexpect.spawn:
    env = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "HOME": str(home.parent),
        "TERMAAI_HOME": str(home),
        "TERM": "dumb",
        "NO_COLOR": "1",
        "COLUMNS": "200",
        "LINES": "50",
    }
    child = pexpect.spawn(
        str(BIN), args, env=env, encoding="utf-8", timeout=timeout, dimensions=(50, 200)
    )
    return child


def finish(child: pexpect.spawn) -> int:
    child.expect(pexpect.EOF)
    child.close()
    assert child.exitstatus is not None, child.signalstatus
    return int(child.exitstatus)


def history(home: Path) -> list[dict[str, object]]:
    path = home / "history.jsonl"
    return [json.loads(line) for line in path.read_text().splitlines()]


def test_confirm_runs_script(tmp_path: Path, isolated_home: Path, sandbox: str) -> None:
    ws = tmp_path / "ws"
    child = spawn(
        ["ask", "create a note", "--workspace", str(ws), "--sandbox", sandbox], isolated_home
    )
    child.expect("Risk level: LOW")
    child.expect(r"Run this script in the \w+ sandbox")
    child.expect(r"\[y/N\]")
    child.sendline("y")
    child.expect("notes.txt")
    child.expect(f"Finished in {sandbox} sandbox: exit code 0")
    assert finish(child) == 0
    assert (ws / "notes.txt").read_text() == "hello from termaai\n"
    entry = history(isolated_home)[-1]
    assert (entry["decision"], entry["exit_code"], entry["sandbox"]) == ("executed", 0, sandbox)


def test_deny_runs_nothing(tmp_path: Path, isolated_home: Path) -> None:
    ws = tmp_path / "ws"
    child = spawn(
        ["ask", "create a note", "--workspace", str(ws), "--sandbox", "subprocess"], isolated_home
    )
    child.expect(r"\[y/N\]")
    child.sendline("n")
    child.expect("Cancelled; nothing was run.")
    assert finish(child) == 3
    assert not (ws / "notes.txt").exists()
    assert history(isolated_home)[-1]["decision"] == "denied"


def test_empty_answer_defaults_to_no(tmp_path: Path, isolated_home: Path) -> None:
    child = spawn(["ask", "list files", "--sandbox", "subprocess"], isolated_home)
    child.expect(r"\[y/N\]")
    child.sendline("")
    child.expect("Cancelled")
    assert finish(child) == 3


def test_high_risk_blocked_without_force(isolated_home: Path) -> None:
    child = spawn(["ask", "install the tool", "--sandbox", "subprocess"], isolated_home)
    child.expect("Risk level: HIGH")
    child.expect("remote_code_execution")
    child.expect("Blocked:")
    assert finish(child) == 4
    assert "Run this script" not in (child.before or "")
    assert history(isolated_home)[-1]["decision"] == "blocked"


def test_force_wrong_second_confirmation_is_denied(isolated_home: Path) -> None:
    child = spawn(["ask", "install the tool", "--force", "--sandbox", "subprocess"], isolated_home)
    child.expect(r"\[y/N\]")
    child.sendline("y")
    child.expect("Type 'run high-risk'")
    child.sendline("yes")
    child.expect("Second confirmation not given")
    assert finish(child) == 3
    entry = history(isolated_home)[-1]
    assert (entry["decision"], entry["forced"]) == ("denied", True)


def test_force_with_both_confirmations_executes(
    tmp_path: Path, isolated_home: Path, sandbox: str
) -> None:
    # The canned installer targets an .invalid host, so the download always fails: the point
    # is that the script really runs (and its non-zero exit code is audited).
    child = spawn(["ask", "install the tool", "--force", "--sandbox", sandbox], isolated_home)
    child.expect(r"\[y/N\]")
    child.sendline("y")
    child.expect("Type 'run high-risk'")
    child.sendline("run high-risk")
    child.expect(f"Finished in {sandbox} sandbox")
    code = finish(child)
    assert code != 0
    entry = history(isolated_home)[-1]
    assert (entry["decision"], entry["exit_code"], entry["risk_level"]) == (
        "executed",
        code,
        "HIGH",
    )


def test_timeout_is_enforced(isolated_home: Path, sandbox: str) -> None:
    child = spawn(["ask", "loop forever", "--timeout", "2", "--sandbox", sandbox], isolated_home)
    child.expect(r"\[y/N\]")
    child.sendline("y")
    child.expect("timed out")
    assert finish(child) == 124


def test_dry_run_shows_plan(tmp_path: Path, isolated_home: Path) -> None:
    ws = tmp_path / "ws"
    child = spawn(
        ["ask", "backup the workspace", "--dry-run", "--workspace", str(ws)], isolated_home
    )
    child.expect("Dry-run plan")
    child.expect("backup/workspace.tar.gz")
    child.expect("Dry run: nothing was executed.")
    assert finish(child) == 0
    assert not (ws / "backup").exists()


def test_repl_flow(tmp_path: Path, isolated_home: Path) -> None:
    ws = tmp_path / "ws"
    child = spawn(["repl", "--workspace", str(ws), "--sandbox", "subprocess"], isolated_home)
    child.expect("termaai> ")
    child.sendline("create a note")
    child.expect(r"\[y/N\]")
    child.sendline("y")
    child.expect(r"\(exit 0\)")
    child.expect("termaai> ")
    child.sendline("remove the build cache")
    child.expect("Risk level: MEDIUM")
    child.expect(r"\[y/N\]")
    child.sendline("n")
    child.expect(r"\(exit 3\)")
    child.expect("termaai> ")
    child.sendline(":history")
    child.expect("denied")
    child.expect("termaai> ")
    child.sendline(":quit")
    child.expect("bye")
    assert finish(child) == 0
    assert [e["decision"] for e in history(isolated_home)] == ["executed", "denied"]


def test_explain_and_history_commands(tmp_path: Path, isolated_home: Path) -> None:
    script = tmp_path / "cleanup.sh"
    script.write_text(":(){ :|:& };:\n")
    child = spawn(["explain", str(script)], isolated_home)
    child.expect("fork_bomb")
    assert finish(child) == 0
    child = spawn(["history", "--json"], isolated_home)
    child.expect('"decision": "explained"')
    assert finish(child) == 0
