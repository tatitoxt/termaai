"""The safety pipeline: generate -> check -> analyze -> confirm -> sandbox -> audit."""

from __future__ import annotations

import tempfile
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from rich.console import Console
from rich.markup import escape
from rich.panel import Panel
from rich.syntax import Syntax
from rich.table import Table
from rich.text import Text

from termaai.audit import AuditLog, AuditRecord
from termaai.executor import (
    DockerExecutor,
    ExecutionResult,
    Executor,
    Limits,
    SandboxError,
    SubprocessExecutor,
    select_executor,
)
from termaai.plan import Plan, build_plan
from termaai.providers import Provider, ProviderError
from termaai.safety.checks import ShellCheckResult, SyntaxResult, check_syntax, run_shellcheck
from termaai.safety.risk import RiskLevel, RiskReport, analyze

EXIT_OK = 0
EXIT_DENIED = 3
EXIT_BLOCKED = 4
EXIT_ERROR = 5
FORCE_PHRASE = "run high-risk"
LEVEL_STYLE = {RiskLevel.LOW: "green", RiskLevel.MEDIUM: "yellow", RiskLevel.HIGH: "bold red"}


class Prompter(Protocol):
    def confirm(self, question: str) -> bool: ...

    def text(self, question: str) -> str: ...


class ConsolePrompter:
    """Reads answers from the terminal; anything but y/yes (or EOF) means no."""

    def __init__(self, console: Console) -> None:
        self.console = console

    def confirm(self, question: str) -> bool:
        return self.text(f"{question} [y/N]: ").strip().lower() in {"y", "yes"}

    def text(self, question: str) -> str:
        try:
            return self.console.input(escape(question))
        except (EOFError, KeyboardInterrupt):
            self.console.print()
            return ""


@dataclass
class RunOptions:
    dry_run: bool = False
    force: bool = False
    sandbox: str = "auto"
    timeout: float = 30.0
    workspace: Path | None = None


@dataclass
class Review:
    script: str
    workspace: Path
    syntax: SyntaxResult
    shellcheck: ShellCheckResult
    report: RiskReport
    plan: Plan


class Assistant:
    def __init__(
        self,
        console: Console,
        provider: Provider,
        audit: AuditLog,
        prompter: Prompter | None = None,
        executor_factory: Callable[[str], Executor] = select_executor,
    ) -> None:
        self.console = console
        self.provider = provider
        self.audit = audit
        self.prompter = prompter or ConsolePrompter(console)
        self.executor_factory = executor_factory

    # ----------------------------------------------------------------- review
    def review(self, script: str, workspace: Path) -> Review:
        ws = str(workspace.resolve())
        return Review(
            script=script,
            workspace=workspace,
            syntax=check_syntax(script),
            shellcheck=run_shellcheck(script),
            report=analyze(script, ws),
            plan=build_plan(script, ws),
        )

    def _record(self, review: Review, kind: str, decision: str, **extra: object) -> AuditRecord:
        record = AuditRecord(
            kind=kind,
            decision=decision,
            risk_level=str(review.report.level),
            script=review.script,
            provider=self.provider.name,
            findings=[f.to_dict() for f in review.report.findings],
            shellcheck=[i.to_dict() for i in review.shellcheck.issues],
            syntax_ok=review.syntax.ok,
            workspace=str(review.workspace),
        )
        for key, value in extra.items():
            setattr(record, key, value)
        self.audit.append(record)
        return record

    # ------------------------------------------------------------- rendering
    def show_script(self, script: str, title: str) -> None:
        self.console.print(
            Panel(Syntax(script, "bash", theme="ansi_dark", line_numbers=True), title=title)
        )

    def show_checks(self, review: Review) -> None:
        if review.syntax.ok:
            self.console.print("[green]bash -n:[/] syntax OK")
        else:
            self.console.print(
                f"[bold red]bash -n: syntax error[/]\n{escape(review.syntax.message)}"
            )
        sc = review.shellcheck
        if not sc.available:
            self.console.print("[dim]ShellCheck: not installed, skipped[/]")
        elif sc.error:
            self.console.print(f"[yellow]ShellCheck: {escape(sc.error)}[/]")
        elif not sc.issues:
            self.console.print("[green]ShellCheck:[/] no issues")
        else:
            table = Table(title="ShellCheck", show_lines=False)
            for col in ("line", "level", "code", "message"):
                table.add_column(col)
            for issue in sc.issues:
                table.add_row(
                    str(issue.line), issue.level, f"SC{issue.code}", escape(issue.message)
                )
            self.console.print(table)

    def show_risk(self, report: RiskReport) -> None:
        level = report.level
        style = LEVEL_STYLE[level]
        self.console.print(f"Risk level: [{style}]{level}[/]")
        if report.findings:
            table = Table(title="Risk findings")
            for col in ("level", "rule", "line", "why"):
                table.add_column(col)
            for f in report.findings:
                table.add_row(
                    f"[{LEVEL_STYLE[f.level]}]{f.level}[/]", f.rule, str(f.line), escape(f.message)
                )
            self.console.print(table)

    def show_plan(self, plan: Plan) -> None:
        table = Table(title=escape(f"Dry-run plan (workspace: {plan.workspace})"))
        for col in ("#", "line", "command", "effects"):
            table.add_column(col)
        for idx, step in enumerate(plan.steps, start=1):
            table.add_row(str(idx), str(step.line), escape(step.command), ", ".join(step.effects))
        self.console.print(table)
        touches = plan.touches
        if touches:
            t2 = Table(title="Paths that would be touched")
            for col in ("action", "path", "resolved", "scope"):
                t2.add_column(col)
            for t in touches:
                scope = f"[red]{t.scope}[/]" if t.outside_workspace else t.scope
                t2.add_row(t.action, escape(t.path), escape(t.resolved), scope)
            self.console.print(t2)
        else:
            self.console.print("No file paths detected.")
        for warning in plan.warnings:
            self.console.print(f"[yellow]parser warning:[/] {escape(warning)}")

    def show_result(self, result: ExecutionResult) -> None:
        if result.stdout:
            self.console.print(Panel(Text(result.stdout.rstrip("\n")), title="stdout"))
        if result.stderr:
            self.console.print(Panel(Text(result.stderr.rstrip("\n")), title="stderr"))
        status = "timed out" if result.timed_out else f"exit code {result.exit_code}"
        style = "green" if result.exit_code == 0 else "red"
        self.console.print(
            f"[{style}]Finished in {result.sandbox} sandbox: {status} "
            f"({result.duration_s:.2f}s)[/]"
        )

    # ----------------------------------------------------------------- flows
    def ask(self, prompt: str, options: RunOptions) -> int:
        try:
            generation = self.provider.generate(prompt)
        except ProviderError as exc:
            self.console.print(f"[bold red]Provider error:[/] {escape(str(exc))}")
            return EXIT_ERROR
        self.console.print(f"[bold]{self.provider.name}[/]: {escape(generation.summary)}")
        return self.run_script(generation.script, options, kind="ask", prompt=prompt)

    def run_script(
        self,
        script: str,
        options: RunOptions,
        kind: str = "ask",
        prompt: str | None = None,
        source: str | None = None,
    ) -> int:
        workspace = options.workspace or Path(tempfile.mkdtemp(prefix="termaai-ws-"))
        workspace.mkdir(parents=True, exist_ok=True)
        review = self.review(script, workspace)
        base = {"prompt": prompt, "source": source, "forced": options.force}
        self.show_script(script, "Generated script" if kind == "ask" else "Script")
        self.show_checks(review)
        self.show_risk(review.report)

        if not review.syntax.ok:
            self.console.print("[bold red]Blocked:[/] the script does not parse; nothing was run.")
            self._record(review, kind, "blocked_syntax", **base)
            return EXIT_BLOCKED
        if options.dry_run:
            self.show_plan(review.plan)
            self.console.print("[cyan]Dry run:[/] nothing was executed.")
            self._record(review, kind, "dry_run", dry_run=True, **base)
            return EXIT_OK
        high = review.report.level is RiskLevel.HIGH
        if high and not options.force:
            self.console.print(
                "[bold red]Blocked:[/] HIGH-risk script. Review the findings; re-run with "
                "--force to override (a second confirmation will be required)."
            )
            self._record(review, kind, "blocked", **base)
            return EXIT_BLOCKED

        try:
            executor = self._prepare_executor(options.sandbox)
        except SandboxError as exc:
            self.console.print(f"[bold red]Sandbox error:[/] {escape(str(exc))}")
            self._record(review, kind, "error", **base)
            return EXIT_ERROR

        question = f"Run this script in the {executor.name} sandbox (workspace: {workspace})?"
        if not self.prompter.confirm(question):
            self.console.print("Cancelled; nothing was run.")
            self._record(review, kind, "denied", sandbox=executor.name, **base)
            return EXIT_DENIED
        if high:
            answer = self.prompter.text(
                f"This script is HIGH risk. Type '{FORCE_PHRASE}' to execute it anyway: "
            )
            if answer.strip() != FORCE_PHRASE:
                self.console.print("Second confirmation not given; nothing was run.")
                self._record(review, kind, "denied", sandbox=executor.name, **base)
                return EXIT_DENIED

        result = executor.run(script, workspace, Limits(timeout=options.timeout))
        self.show_result(result)
        self._record(
            review,
            kind,
            "executed",
            sandbox=result.sandbox,
            exit_code=result.exit_code,
            duration_s=result.duration_s,
            timed_out=result.timed_out,
            **base,
        )
        return result.exit_code

    def _prepare_executor(self, mode: str) -> Executor:
        executor = self.executor_factory(mode)
        if isinstance(executor, DockerExecutor):
            try:
                executor.ensure_image()
            except SandboxError as exc:
                if mode == "docker":
                    raise
                self.console.print(
                    f"[yellow]{escape(str(exc))}; falling back to the subprocess sandbox[/]"
                )
                return SubprocessExecutor()
        if isinstance(executor, SubprocessExecutor):
            self.console.print(
                "[yellow]Docker unavailable or not selected: using the restricted subprocess "
                "fallback (timeout + rlimits, NOT an isolation boundary).[/]"
            )
        return executor

    def explain(self, script: str, source: str) -> int:
        workspace = Path.cwd()
        review = self.review(script, workspace)
        self.show_script(script, escape(source))
        self.show_checks(review)
        self.show_risk(review.report)
        self.show_plan(review.plan)
        try:
            explanation = self.provider.explain(script)
        except ProviderError as exc:
            self.console.print(f"[bold red]Provider error:[/] {escape(str(exc))}")
            explanation = ""
        if explanation:
            self.console.print(
                Panel(Text(explanation), title=f"Explanation ({self.provider.name})")
            )
        self._record(review, "explain", "explained", source=source)
        return EXIT_OK
