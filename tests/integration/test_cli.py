"""CLI-level integration tests through Typer's runner (stdin is scripted)."""

from __future__ import annotations

import json
import threading
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import ClassVar

import pytest
from typer.testing import CliRunner

from termaai.assistant import EXIT_BLOCKED, EXIT_DENIED, EXIT_ERROR
from termaai.audit import AuditLog
from termaai.cli import app

runner = CliRunner()
SUB = ["--sandbox", "subprocess"]


def invoke(args: list[str], stdin: str = "", env: dict[str, str] | None = None):  # type: ignore[no-untyped-def]
    return runner.invoke(app, args, input=stdin, env={"COLUMNS": "200", **(env or {})})


def last_record() -> dict[str, object]:
    return AuditLog().read(limit=1)[-1]


def test_version() -> None:
    result = invoke(["--version"])
    assert result.exit_code == 0
    assert result.output.strip() == "termaai 0.1.0"


def test_ask_confirmed_runs_and_is_audited(tmp_path: Path) -> None:
    result = invoke(["ask", "create a note", "--workspace", str(tmp_path), *SUB], "y\n")
    assert result.exit_code == 0, result.output
    assert (tmp_path / "notes.txt").read_text() == "hello from termaai\n"
    record = last_record()
    assert record["decision"] == "executed"
    assert record["exit_code"] == 0
    assert record["prompt"] == "create a note"
    assert record["risk_level"] == "LOW"
    assert record["sandbox"] == "subprocess"


def test_ask_denied_runs_nothing(tmp_path: Path) -> None:
    result = invoke(["ask", "create a note", "--workspace", str(tmp_path), *SUB], "n\n")
    assert result.exit_code == EXIT_DENIED
    assert not (tmp_path / "notes.txt").exists()
    assert last_record()["decision"] == "denied"


def test_script_exit_code_is_propagated_and_audited(tmp_path: Path) -> None:
    result = invoke(["ask", "please fail", "--workspace", str(tmp_path), *SUB], "y\n")
    assert result.exit_code == 7
    assert last_record()["exit_code"] == 7


def test_high_risk_is_blocked_without_prompt() -> None:
    result = invoke(["ask", "install the tool", *SUB], "y\n")
    assert result.exit_code == EXIT_BLOCKED
    assert "remote_code_execution" in result.output
    assert "Run this script" not in result.output
    assert last_record()["decision"] == "blocked"


def test_force_requires_exact_second_confirmation() -> None:
    result = invoke(["ask", "install the tool", "--force", *SUB], "y\nyes\n")
    assert result.exit_code == EXIT_DENIED
    record = last_record()
    assert record["decision"] == "denied"
    assert record["forced"] is True


def test_dry_run_shows_plan_and_never_executes(tmp_path: Path) -> None:
    (tmp_path / "keep").mkdir()
    result = invoke(["ask", "backup the workspace", "--dry-run", "--workspace", str(tmp_path)])
    assert result.exit_code == 0
    assert "Dry run" in result.output
    assert "backup/workspace.tar.gz" in result.output
    assert not (tmp_path / "backup").exists()
    assert last_record()["decision"] == "dry_run"


def test_syntax_error_is_blocked() -> None:
    result = invoke(["ask", "something broken", *SUB])
    assert result.exit_code == EXIT_BLOCKED
    assert last_record()["decision"] == "blocked_syntax"


def test_explain_never_executes(tmp_path: Path) -> None:
    script = tmp_path / "danger.sh"
    script.write_text("sudo rm -rf /var/lib/app\n")
    result = invoke(["explain", str(script)])
    assert result.exit_code == 0
    assert "HIGH" in result.output
    assert "privilege_escalation" in result.output
    assert "deletes files" in result.output
    assert last_record()["decision"] == "explained"


def test_history_json_lists_records(tmp_path: Path) -> None:
    invoke(["ask", "create a note", "--workspace", str(tmp_path), *SUB], "n\n")
    invoke(["ask", "install it", *SUB])
    result = invoke(["history", "--json"])
    lines = [json.loads(line) for line in result.output.splitlines()]
    assert [r["decision"] for r in lines] == ["denied", "blocked"]
    assert all(len(str(r["script_sha256"])) == 64 for r in lines)
    table = invoke(["history"])
    assert "denied" in table.output and "blocked" in table.output


def test_history_empty() -> None:
    assert "No history yet" in invoke(["history"]).output


def test_repl_session(tmp_path: Path) -> None:
    stdin = ":help\n:dry\ncreate a note\n:dry\ncreate a note\ny\n:history\n:quit\n"
    result = invoke(["repl", "--workspace", str(tmp_path), *SUB], stdin)
    assert result.exit_code == 0, result.output
    assert "dry-run is now on" in result.output
    assert "dry-run is now off" in result.output
    assert (tmp_path / "notes.txt").exists()
    assert result.output.rstrip().endswith("bye")
    decisions = [r["decision"] for r in AuditLog().read()]
    assert decisions == ["dry_run", "executed"]


def test_missing_api_key_is_a_clean_error(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("GROQ_API_KEY", raising=False)
    result = invoke(["ask", "list files", "--provider", "groq"])
    assert result.exit_code == EXIT_ERROR
    assert "GROQ_API_KEY is not set" in result.output


class _FakeChatAPI(BaseHTTPRequestHandler):
    requests: ClassVar[list[dict[str, object]]] = []

    def do_POST(self) -> None:
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        body["_auth"] = self.headers.get("Authorization")
        body["_path"] = self.path
        type(self).requests.append(body)
        content = "Here you go:\n```bash\nprintf 'from local stub\\n' > stub.txt\n```"
        payload = json.dumps({"choices": [{"message": {"content": content}}]}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *args: object) -> None:
        pass


@pytest.fixture
def chat_api() -> Iterator[str]:
    _FakeChatAPI.requests = []
    server = HTTPServer(("127.0.0.1", 0), _FakeChatAPI)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_port}/v1"
    server.shutdown()


def test_openai_compatible_provider_against_local_stub(chat_api: str, tmp_path: Path) -> None:
    env = {
        "TERMAAI_PROVIDER": "openai",
        "OPENAI_API_KEY": "test-key-not-real",
        "TERMAAI_OPENAI_BASE_URL": chat_api,
    }
    result = invoke(["ask", "write a stub file", "--workspace", str(tmp_path), *SUB], "y\n", env)
    assert result.exit_code == 0, result.output
    assert (tmp_path / "stub.txt").read_text() == "from local stub\n"
    sent = _FakeChatAPI.requests[0]
    assert sent["_path"] == "/v1/chat/completions"
    assert sent["_auth"] == "Bearer test-key-not-real"
    assert sent["model"] == "gpt-4o-mini"
    assert last_record()["provider"] == "openai"


@pytest.mark.docker
def test_ask_in_docker_sandbox(tmp_path: Path, docker_ready: None) -> None:
    result = invoke(
        ["ask", "create a note", "--workspace", str(tmp_path), "--sandbox", "docker"], "y\n"
    )
    assert result.exit_code == 0, result.output
    assert (tmp_path / "notes.txt").exists()
    assert last_record()["sandbox"] == "docker"
