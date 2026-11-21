"""Dry-run planner: describe what a script would run and touch, without running it."""

from __future__ import annotations

from dataclasses import dataclass, field

from termaai.safety import paths
from termaai.safety.risk import (
    DOWNLOADERS,
    INTERPRETERS,
    NETWORK_TOOLS,
    delete_targets,
    find_roots,
    write_targets,
)
from termaai.safety.shellparse import SimpleCommand, apply_cwds, parse, positional_args

READERS = frozenset(
    {
        "cat",
        "less",
        "more",
        "head",
        "tail",
        "wc",
        "ls",
        "du",
        "stat",
        "file",
        "sort",
        "uniq",
        "diff",
        "cut",
        "md5sum",
        "sha256sum",
        "tree",
        "nl",
    }
)
PATTERN_FIRST = frozenset({"grep", "egrep", "fgrep", "rg", "awk", "sed"})


@dataclass(frozen=True)
class Touch:
    path: str
    action: str
    resolved: str
    scope: str

    @property
    def outside_workspace(self) -> bool:
        return paths.Scope(self.scope).outside_workspace

    def to_dict(self) -> dict[str, object]:
        return {"path": self.path, "action": self.action, "scope": self.scope}


@dataclass(frozen=True)
class Step:
    line: int
    command: str
    program: str
    effects: tuple[str, ...]
    touches: tuple[Touch, ...]


@dataclass
class Plan:
    workspace: str
    steps: list[Step] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    @property
    def touches(self) -> list[Touch]:
        seen: dict[tuple[str, str], Touch] = {}
        for step in self.steps:
            for t in step.touches:
                seen.setdefault((t.path, t.action), t)
        return list(seen.values())


def _read_targets(cmd: SimpleCommand) -> list[str]:
    reads = [r.target for r in cmd.redirects if r.op == "<"]
    prog = cmd.program
    if prog in READERS:
        reads += positional_args(cmd.args, frozenset({"-n", "-c", "-d", "-f", "-k", "-t"}))
    elif prog in PATTERN_FIRST:
        args = positional_args(cmd.args, frozenset({"-e", "-f", "-m", "-A", "-B", "-C"}))
        explicit = any(a in {"-e", "-f"} or a.startswith(("--regexp", "--file")) for a in cmd.args)
        reads += args if explicit else args[1:]
    elif prog == "find":
        reads += find_roots(cmd)
    elif prog in {"cp", "mv", "rsync"}:
        sources = positional_args(cmd.args, frozenset({"-t"}))
        reads += sources if "-t" in cmd.args else sources[:-1]
    elif prog in {"tar", "zip"}:
        written = write_targets(cmd)
        reads += [p for p in positional_args(cmd.args, frozenset({"-C"})) if p not in written]
    elif prog == "dd":
        reads += [a[3:] for a in cmd.args if a.startswith("if=")]
    return [r for r in reads if r and r != "-"]


def _effects(
    cmd: SimpleCommand, writes: list[str], deletes: list[str], reads: list[str]
) -> list[str]:
    effects: list[str] = []
    if {"sudo", "doas"} & set(cmd.wrappers) or cmd.program in {"sudo", "su", "doas"}:
        effects.append("privileged")
    if cmd.program in NETWORK_TOOLS or any(
        r.target.startswith(("/dev/tcp/", "/dev/udp/")) for r in cmd.redirects
    ):
        effects.append("network")
    if cmd.program in INTERPRETERS:
        effects.append("exec")
    if deletes:
        effects.append("delete")
    if writes:
        effects.append("write")
    if reads:
        effects.append("read")
    if not effects:
        effects.append("compute")
    return effects


def build_plan(script: str, workspace: str) -> Plan:
    parsed = parse(script)
    apply_cwds(parsed, workspace)
    plan = Plan(workspace=workspace, warnings=list(parsed.warnings))
    for cmd in parsed.commands:
        deletes = delete_targets(cmd)
        writes = write_targets(cmd)
        reads = _read_targets(cmd)
        touches = [
            Touch(
                p,
                action,
                paths.resolve(p, cmd.cwd or workspace),
                paths.classify(paths.resolve(p, cmd.cwd or workspace), workspace).value,
            )
            for action, group in (("delete", deletes), ("write", writes), ("read", reads))
            for p in group
        ]
        if cmd.program in DOWNLOADERS:
            urls = [a for a in cmd.args if "://" in a]
            touches += [Touch(u, "network", u, "outside") for u in urls]
        plan.steps.append(
            Step(
                line=cmd.line,
                command=cmd.display(),
                program=cmd.program,
                effects=tuple(_effects(cmd, writes, deletes, reads)),
                touches=tuple(touches),
            )
        )
    return plan
