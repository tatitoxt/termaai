"""Command-line interface: ``termaai ask``, ``repl``, ``explain`` and ``history``."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path
from typing import Annotated, Optional

import typer
from rich.console import Console
from rich.markup import escape
from rich.table import Table

from termaai import __version__
from termaai.assistant import EXIT_ERROR, Assistant, RunOptions
from termaai.audit import AuditLog
from termaai.providers import ProviderError, get_provider

app = typer.Typer(
    help="Turn natural-language requests into Bash scripts and run them behind a safety "
    "pipeline (syntax check, ShellCheck, risk analysis, confirmation, sandbox, audit log).",
    no_args_is_help=False,
    add_completion=False,
    rich_markup_mode=None,
)

ProviderOpt = Annotated[
    Optional[str],  # noqa: UP007 - typer 0.12 needs Optional on Python 3.10
    typer.Option("--provider", help="fake (default), openai or groq. Env: TERMAAI_PROVIDER."),
]
SandboxOpt = Annotated[
    str,
    typer.Option(
        "--sandbox",
        help="auto (Docker, then Podman, if available), docker, podman, gvisor or subprocess.",
    ),
]
TimeoutOpt = Annotated[float, typer.Option("--timeout", min=1, help="Execution timeout (s).")]
WorkspaceOpt = Annotated[
    Optional[Path],  # noqa: UP007
    typer.Option(
        "--workspace",
        file_okay=False,
        help="Directory the script runs in. Default: a fresh temporary directory.",
    ),
]
PolicyOpt = Annotated[
    Optional[Path],  # noqa: UP007
    typer.Option(
        "--policy",
        dir_okay=False,
        exists=True,
        readable=True,
        help="Policy file (default: <workspace>/.termaai.toml when it exists).",
    ),
]


def _console() -> Console:
    return Console(highlight=False, soft_wrap=False)


def _assistant(provider: str | None, console: Console) -> Assistant:
    try:
        return Assistant(console, get_provider(provider), AuditLog())
    except ProviderError as exc:
        console.print(f"[bold red]Provider error:[/] {escape(str(exc))}")
        raise typer.Exit(EXIT_ERROR) from exc


def _version(value: bool) -> None:
    if value:
        typer.echo(f"termaai {__version__}")
        raise typer.Exit()


@app.callback(invoke_without_command=True)
def root(
    ctx: typer.Context,
    version: Annotated[
        bool, typer.Option("--version", callback=_version, is_eager=True, help="Show version.")
    ] = False,
) -> None:
    """Start the interactive REPL when no command is given."""
    if ctx.invoked_subcommand is None:
        ctx.invoke(repl)


@app.command()
def ask(
    prompt: Annotated[str, typer.Argument(help="What you want the script to do.")],
    dry_run: Annotated[
        bool, typer.Option("--dry-run", help="Show the plan and touched paths; never execute.")
    ] = False,
    force: Annotated[
        bool, typer.Option("--force", help="Allow HIGH-risk scripts (asks twice).")
    ] = False,
    sandbox: SandboxOpt = "auto",
    timeout: TimeoutOpt = 30.0,
    workspace: WorkspaceOpt = None,
    policy: PolicyOpt = None,
    provider: ProviderOpt = None,
    revise: Annotated[
        int,
        typer.Option(
            "--revise",
            min=0,
            help="Times to feed analyzer findings back to the provider for a safer script.",
        ),
    ] = 2,
    edit: Annotated[
        bool,
        typer.Option(
            "--edit", "-e", help="Open the generated script in $EDITOR before running it."
        ),
    ] = False,
) -> None:
    """Generate a script for PROMPT, review it, and run it after confirmation."""
    console = _console()
    assistant = _assistant(provider, console)
    options = RunOptions(dry_run, force, sandbox, timeout, workspace, policy, revise, edit)
    raise typer.Exit(assistant.ask(prompt, options))


@app.command()
def repl(
    sandbox: SandboxOpt = "auto",
    timeout: TimeoutOpt = 30.0,
    workspace: WorkspaceOpt = None,
    policy: PolicyOpt = None,
    provider: ProviderOpt = None,
) -> None:
    """Interactive session. Every request goes through the same safety pipeline."""
    console = _console()
    assistant = _assistant(provider, console)
    ws = workspace or Path(tempfile.mkdtemp(prefix="termaai-ws-"))
    options = RunOptions(sandbox=sandbox, timeout=timeout, workspace=ws, policy_file=policy)
    console.print(
        escape(f"TermaAI {__version__} - provider: {assistant.provider.name}, workspace: {ws}")
        + "\n"
        "Type a request, ':dry' to toggle dry-run, ':history', ':help' or ':quit'."
    )
    while True:
        try:
            line = console.input("termaai> ").strip()
        except (EOFError, KeyboardInterrupt):
            console.print()
            break
        if not line:
            continue
        if line in {":quit", ":q", ":exit", "exit", "quit"}:
            break
        if line == ":help":
            console.print(
                ":dry      toggle dry-run mode\n:history  show the last 10 audit entries\n"
                ":quit     leave the REPL"
            )
        elif line == ":dry":
            options.dry_run = not options.dry_run
            console.print(f"dry-run is now {'on' if options.dry_run else 'off'}")
        elif line == ":history":
            _print_history(console, AuditLog().read(limit=10))
        else:
            code = assistant.ask(line, options)
            console.print(f"[dim](exit {code})[/]")
    console.print("bye")


@app.command()
def explain(
    script: Annotated[Path, typer.Argument(exists=True, dir_okay=False, readable=True)],
    provider: ProviderOpt = None,
) -> None:
    """Explain a script and show its risk analysis and dry-run plan. Never executes it."""
    console = _console()
    assistant = _assistant(provider, console)
    text = script.read_text(encoding="utf-8")
    raise typer.Exit(assistant.explain(text, str(script)))


def _print_history(console: Console, entries: list[dict[str, object]]) -> None:
    if not entries:
        console.print("No history yet.")
        return
    table = Table(title=escape(f"Audit history ({AuditLog().path})"))
    for col in ("time", "kind", "prompt / source", "risk", "decision", "sandbox", "exit"):
        table.add_column(col)
    for e in entries:
        table.add_row(
            str(e.get("timestamp", "")),
            str(e.get("kind", "")),
            escape(str(e.get("prompt") or e.get("source") or "")),
            str(e.get("risk_level", "")),
            str(e.get("decision", "")),
            str(e.get("sandbox") or "-"),
            "-" if e.get("exit_code") is None else str(e.get("exit_code")),
        )
    console.print(table)


@app.command()
def history(
    limit: Annotated[int, typer.Option("--limit", "-n", min=1, help="Entries to show.")] = 20,
    as_json: Annotated[bool, typer.Option("--json", help="Print raw JSONL records.")] = False,
) -> None:
    """Show the audit history of prompts, scripts, risk decisions and exit codes."""
    entries = AuditLog().read(limit=limit)
    if as_json:
        for entry in entries:
            typer.echo(json.dumps(entry, sort_keys=True))
        return
    _print_history(_console(), entries)


def main() -> None:
    app()
