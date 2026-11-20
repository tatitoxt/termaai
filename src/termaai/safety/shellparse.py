"""A small, best-effort Bash tokenizer used by the risk analyzer and dry-run planner.

It is intentionally conservative: it understands quoting, comments, pipelines, command
lists, redirections, heredocs, ``$(...)``/backtick substitutions and ``sh -c "..."``
strings well enough to find the commands a script would run. It is *not* a full Bash
parser; anything it cannot resolve statically is reported as such by the callers.
"""

from __future__ import annotations

import posixpath
import re
import shlex
from dataclasses import dataclass, field

SEPARATORS = frozenset({";", "&&", "||", "&", ";;", ";&", ";;&", "(", ")", "{", "}", "|&"})
PIPE = "|"
REDIRECT_OPS = frozenset({">", ">>", "<", "<<", "<<<", ">&", "<&", "&>", "&>>", ">|", "<>"})
WRITE_REDIRECTS = frozenset({">", ">>", "&>", "&>>", ">|", "<>"})
_PUNCT = set("();<>|&")
_OPS_BY_LENGTH = sorted(SEPARATORS | REDIRECT_OPS | {PIPE}, key=len, reverse=True)
KEYWORDS = frozenset(
    {"if", "then", "else", "elif", "fi", "do", "done", "while", "until", "!", "function", "time"}
)
SKIP_COMMANDS = frozenset({"for", "case", "esac", "select", "in", "[[", "]]"})
WRAPPERS = frozenset(
    {
        "sudo",
        "doas",
        "env",
        "command",
        "builtin",
        "nohup",
        "nice",
        "ionice",
        "time",
        "exec",
        "xargs",
        "timeout",
        "stdbuf",
        "setsid",
        "chroot",
    }
)
SHELLS = frozenset({"sh", "bash", "zsh", "dash", "ksh", "ash", "busybox"})
_ASSIGNMENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*(\[[^\]]*\])?\+?=")
_HEREDOC = re.compile(r"<<-?\s*(['\"]?)([A-Za-z_][A-Za-z0-9_]*)\1")
_SUBST = re.compile(r"\$\(([^()]*)\)")
_BACKTICK = re.compile(r"`([^`]*)`")
_SINGLE_QUOTED = re.compile(r"'[^']*'")
_WRAPPER_OPTS_WITH_ARG: dict[str, frozenset[str]] = {
    "sudo": frozenset({"-u", "-g", "-C", "-D", "-h", "-p", "-r", "-t", "-U", "-T"}),
    "doas": frozenset({"-u", "-C"}),
    "nice": frozenset({"-n"}),
    "ionice": frozenset({"-c", "-n", "-p"}),
    "xargs": frozenset({"-I", "-n", "-P", "-d", "-L", "-s", "-a", "-E", "-i"}),
    "timeout": frozenset({"-s", "-k", "--signal", "--kill-after"}),
    "env": frozenset({"-u", "-C", "-S"}),
    "stdbuf": frozenset({"-i", "-o", "-e"}),
}


@dataclass(frozen=True)
class Redirect:
    op: str
    target: str


@dataclass(frozen=True)
class SimpleCommand:
    """One simple command, e.g. ``rm -rf build`` with its redirections."""

    line: int
    argv: tuple[str, ...]
    redirects: tuple[Redirect, ...] = ()
    pipeline: int = 0
    wrappers: tuple[str, ...] = ()
    assignments: tuple[str, ...] = ()

    @property
    def program(self) -> str:
        return posixpath.basename(self.argv[0]) if self.argv else ""

    @property
    def args(self) -> tuple[str, ...]:
        return self.argv[1:]

    def display(self) -> str:
        words = [shlex.quote(p) for p in (*self.wrappers, *self.argv)]
        words += [f"{r.op} {shlex.quote(r.target)}" for r in self.redirects]
        return " ".join(words)


@dataclass
class ParsedScript:
    source: str
    commands: list[SimpleCommand] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def pipelines(self) -> list[list[SimpleCommand]]:
        groups: dict[int, list[SimpleCommand]] = {}
        for cmd in self.commands:
            groups.setdefault(cmd.pipeline, []).append(cmd)
        return [groups[k] for k in sorted(groups)]


def _split_punct(token: str) -> list[str]:
    out: list[str] = []
    i = 0
    while i < len(token):
        for op in _OPS_BY_LENGTH:
            if token.startswith(op, i):
                out.append(op)
                i += len(op)
                break
        else:
            out.append(token[i])
            i += 1
    return out


def tokenize(text: str) -> list[str]:
    """Split shell text into words and operators. Raises ValueError on unbalanced quotes."""
    lexer = shlex.shlex(text, posix=True, punctuation_chars=True)
    lexer.whitespace_split = True
    tokens: list[str] = []
    for tok in lexer:
        if tok and all(ch in _PUNCT for ch in tok):
            tokens.extend(_split_punct(tok))
        else:
            tokens.append(tok)
    return tokens


def _logical_lines(source: str) -> list[tuple[int, str]]:
    """Join continuations, drop heredoc bodies and merge lines with open quotes."""
    raw_lines = source.splitlines()
    result: list[tuple[int, str]] = []
    i = 0
    while i < len(raw_lines):
        start = i + 1
        line = raw_lines[i]
        i += 1
        while line.endswith("\\") and i < len(raw_lines):
            line = line[:-1] + " " + raw_lines[i]
            i += 1
        while i < len(raw_lines):
            try:
                tokenize(line)
                break
            except ValueError:
                line = line + "\n" + raw_lines[i]
                i += 1
        for match in _HEREDOC.finditer(line):
            delimiter = match.group(2)
            while i < len(raw_lines) and raw_lines[i].strip() != delimiter:
                i += 1
            i += 1
        result.append((start, line))
    return result


def _unwrap(argv: list[str]) -> tuple[list[str], list[str]]:
    """Strip wrappers like ``sudo -u x``, ``env A=1`` or ``xargs -n1`` from argv."""
    wrappers: list[str] = []
    while argv and posixpath.basename(argv[0]) in WRAPPERS:
        name = posixpath.basename(argv[0])
        wrappers.append(name)
        rest = argv[1:]
        takes_arg = _WRAPPER_OPTS_WITH_ARG.get(name, frozenset())
        while rest:
            head = rest[0]
            if head == "--":
                rest = rest[1:]
                break
            if head.startswith("-"):
                rest = rest[2:] if head in takes_arg else rest[1:]
                continue
            if name == "env" and _ASSIGNMENT.match(head):
                rest = rest[1:]
                continue
            if name == "timeout" and re.fullmatch(r"[0-9.]+[smhd]?", head):
                rest = rest[1:]
                continue
            if name == "chroot":
                rest = rest[1:]
            break
        argv = rest
    return wrappers, argv


class _Builder:
    def __init__(self, parsed: ParsedScript) -> None:
        self.parsed = parsed
        self.pipeline_counter = 0

    def add_line(self, lineno: int, text: str, depth: int = 0) -> None:
        try:
            tokens = tokenize(text)
        except ValueError as exc:
            self.parsed.warnings.append(f"line {lineno}: could not tokenize ({exc})")
            tokens = text.split()
        self._consume(lineno, tokens, depth)
        if depth <= 4:
            for match in _BACKTICK.finditer(_SINGLE_QUOTED.sub("''", text)):
                if match.group(1).strip():
                    self.add_line(lineno, match.group(1), depth + 1)

    def _consume(self, lineno: int, tokens: list[str], depth: int) -> None:
        argv: list[str] = []
        redirects: list[Redirect] = []
        pipeline = self._next_pipeline()
        i = 0
        while i < len(tokens):
            tok = tokens[i]
            if tok == "$" and i + 1 < len(tokens) and tokens[i + 1] == "(":
                i += 1
                continue
            if tok in REDIRECT_OPS:
                target = tokens[i + 1] if i + 1 < len(tokens) else ""
                if argv and argv[-1].isdigit() and tok not in {"<<", "<<<"}:
                    argv.pop()
                if not (tok in {">&", "<&"} and (target.isdigit() or target == "-")):
                    redirects.append(Redirect(tok, target))
                self._scan_substitutions(lineno, target, depth)
                i += 2
                continue
            if tok == PIPE or tok == "|&":
                self._emit(lineno, argv, redirects, pipeline, depth)
                argv, redirects = [], []
                i += 1
                continue
            if tok in SEPARATORS:
                self._emit(lineno, argv, redirects, pipeline, depth)
                argv, redirects = [], []
                pipeline = self._next_pipeline()
                i += 1
                continue
            if not argv and tok in KEYWORDS:
                i += 1
                continue
            self._scan_substitutions(lineno, tok, depth)
            argv.append(tok)
            i += 1
        self._emit(lineno, argv, redirects, pipeline, depth)

    def _next_pipeline(self) -> int:
        self.pipeline_counter += 1
        return self.pipeline_counter

    def _scan_substitutions(self, lineno: int, token: str, depth: int) -> None:
        if depth > 4:
            return
        for match in _SUBST.finditer(token):
            if match.group(1).strip():
                self.add_line(lineno, match.group(1), depth + 1)

    def _emit(
        self,
        lineno: int,
        argv: list[str],
        redirects: list[Redirect],
        pipeline: int,
        depth: int,
    ) -> None:
        assignments: list[str] = []
        while argv and _ASSIGNMENT.match(argv[0]):
            assignments.append(argv.pop(0))
        wrappers, argv = _unwrap(argv)
        if not argv and not redirects:
            return
        if argv and argv[0] in SKIP_COMMANDS:
            return
        cmd = SimpleCommand(
            line=lineno,
            argv=tuple(argv),
            redirects=tuple(redirects),
            pipeline=pipeline,
            wrappers=tuple(wrappers),
            assignments=tuple(assignments),
        )
        self.parsed.commands.append(cmd)
        if cmd.program in SHELLS and depth <= 4:
            inline = _inline_script(cmd.args)
            if inline is not None:
                self.add_line(lineno, inline, depth + 1)


def _inline_script(args: tuple[str, ...]) -> str | None:
    for idx, arg in enumerate(args):
        if arg == "-c" or (arg.startswith("-") and not arg.startswith("--") and "c" in arg[1:]):
            return args[idx + 1] if idx + 1 < len(args) else None
    return None


def parse(source: str) -> ParsedScript:
    parsed = ParsedScript(source=source)
    builder = _Builder(parsed)
    for lineno, text in _logical_lines(source):
        builder.add_line(lineno, text)
    return parsed


def positional_args(
    args: tuple[str, ...], options_with_arg: frozenset[str] = frozenset()
) -> list[str]:
    """Return non-option arguments, honouring ``--`` and options that take a value."""
    out: list[str] = []
    skip = False
    after_dd = False
    for arg in args:
        if skip:
            skip = False
            continue
        if after_dd:
            out.append(arg)
        elif arg == "--":
            after_dd = True
        elif arg.startswith("-") and arg != "-":
            if arg in options_with_arg:
                skip = True
        else:
            out.append(arg)
    return out


def short_flags(args: tuple[str, ...]) -> set[str]:
    """Collect single-letter flags (``-rf`` -> {"r", "f"}) and long flags verbatim."""
    flags: set[str] = set()
    for arg in args:
        if arg == "--":
            break
        if arg.startswith("--"):
            flags.add(arg)
        elif arg.startswith("-") and len(arg) > 1:
            flags.update(arg[1:])
    return flags
