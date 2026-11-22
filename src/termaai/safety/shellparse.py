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
from collections.abc import Iterator
from dataclasses import dataclass, field, replace
from typing import Any

_GRAMMAR_PARSER: Any = None
try:  # optional grammar backend; the hand-written tokenizer remains the fallback
    import tree_sitter as _ts
    import tree_sitter_bash as _tsb

    _GRAMMAR_PARSER = _ts.Parser(_ts.Language(_tsb.language()))
except Exception:  # pragma: no cover - dependency absent
    pass

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
_ARITH_AHEAD = r"(?!\((?:[^()]|\([^()]*\))*\)\))"
_SUBST = re.compile(r"\$\(" + _ARITH_AHEAD + r"((?:[^()]|\([^()]*\))*)\)")
_BACKTICK = re.compile(r"`([^`]*)`")
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
    paren_depth: int = 0
    cwd: str = ""

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


def _split_single_quoted(text: str) -> tuple[str, list[str]]:
    """Return ``text`` with single-quoted contents blanked, plus those contents.

    The shell expands nothing inside single quotes, so the blanked text is what may expand.
    """
    out: list[str] = []
    quoted: list[str] = []
    current: list[str] = []
    in_single = in_double = escaped = False
    for ch in text:
        if in_single:
            if ch == "'":
                in_single = False
                quoted.append("".join(current))
                current = []
                out.append(ch)
            else:
                current.append(ch)
                out.append(" ")
            continue
        out.append(ch)
        if escaped:
            escaped = False
        elif ch == "\\":
            escaped = True
        elif ch == '"':
            in_double = not in_double
        elif ch == "'" and not in_double:
            in_single = True
    if current:
        quoted.append("".join(current))
    return "".join(out), quoted


def _norm(text: str) -> str:
    return " ".join(text.replace('"', "").replace("'", "").split())


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


def _only_single_quoted(inner: str, source: str) -> bool:
    """True when ``$(inner)`` occurs in ``source`` only inside single quotes (so never runs).

    Tokens have lost their quotes, so both sides are compared with quotes removed; anything
    not provably single-quoted is treated as a real substitution (fail-safe).
    """
    wanted = _norm(inner)
    expandable, quoted = _split_single_quoted(source)
    if any(_norm(m.group(1)) == wanted for m in _SUBST.finditer(expandable)):
        return False
    return any(_norm(m.group(1)) == wanted for q in quoted for m in _SUBST.finditer(q))


class _Builder:
    def __init__(self, parsed: ParsedScript) -> None:
        self.parsed = parsed
        self.pipeline_counter = 0
        self.paren_depth = 0

    def add_line(self, lineno: int, text: str, depth: int = 0) -> None:
        try:
            tokens = tokenize(text)
        except ValueError as exc:
            self.parsed.warnings.append(f"line {lineno}: could not tokenize ({exc})")
            tokens = text.split()
        expandable, _ = _split_single_quoted(text)
        self._consume(lineno, tokens, depth, text)
        if depth <= 4:
            for match in _BACKTICK.finditer(expandable):
                if match.group(1).strip():
                    self.add_line(lineno, match.group(1), depth + 1)

    def _consume(self, lineno: int, tokens: list[str], depth: int, source: str) -> None:
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
                self._scan_substitutions(lineno, target, depth, source)
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
                if tok == "(":
                    self.paren_depth += 1
                elif tok == ")":
                    self.paren_depth = max(0, self.paren_depth - 1)
                i += 1
                continue
            if not argv and tok in KEYWORDS:
                i += 1
                continue
            self._scan_substitutions(lineno, tok, depth, source)
            argv.append(tok)
            i += 1
        self._emit(lineno, argv, redirects, pipeline, depth)

    def _next_pipeline(self) -> int:
        self.pipeline_counter += 1
        return self.pipeline_counter

    def _scan_substitutions(self, lineno: int, token: str, depth: int, source: str) -> None:
        if depth > 4:
            return
        for match in _SUBST.finditer(token):
            if match.group(1).strip() and not _only_single_quoted(match.group(1), source):
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
            paren_depth=self.paren_depth,
        )
        self.parsed.commands.append(cmd)
        if cmd.program in SHELLS and depth <= 4:
            inline = inline_script(cmd.args)
            if inline is not None:
                self.add_line(lineno, inline, depth + 1)


def inline_script(args: tuple[str, ...]) -> str | None:
    for idx, arg in enumerate(args):
        if arg == "-c" or (arg.startswith("-") and not arg.startswith("--") and "c" in arg[1:]):
            return args[idx + 1] if idx + 1 < len(args) else None
    return None


def parse(source: str) -> ParsedScript:
    parsed = _parse_grammar(source)
    if parsed is not None:
        return parsed
    parsed = ParsedScript(source=source)
    builder = _Builder(parsed)
    for lineno, text in _logical_lines(source):
        builder.add_line(lineno, text)
    return parsed


# --- tree-sitter grammar backend ---------------------------------------------

_DEPTH_NODES = frozenset({"subshell", "command_substitution", "process_substitution"})
_COMMAND_NODES = frozenset({"command", "declaration_command", "unset_command", "test_command"})
_CONTAINER_NODES = frozenset(
    {
        "program",
        "list",
        "if_statement",
        "elif_clause",
        "else_clause",
        "while_statement",
        "for_statement",
        "c_style_for_statement",
        "do_group",
        "case_statement",
        "case_item",
        "function_definition",
        "compound_statement",
        "negated_command",
    }
)


def _has_error(node: Any) -> bool:
    if node.type in ("ERROR", "MISSING") or node.is_missing:
        return True
    return any(_has_error(c) for c in node.children)


def _redirect_text(source: bytes, node: Any) -> tuple[str, str] | None:
    """Return (operator, target) for a file_redirect/heredoc_redirect node.

    A leading file descriptor (`2>`) folds into the operator. Pure fd
    duplication (`2>&1`) is not a file redirect and is skipped.
    """
    named = [c for c in node.children if c.is_named]
    if not named:
        return None
    dest = named[-1]
    if dest.type in ("file_descriptor", "number"):
        return None
    raw = source[node.start_byte : dest.start_byte].decode("utf-8", "replace").strip()
    op = raw.lstrip("0123456789") if raw[:1].isdigit() else raw
    return op, _word_text(dest, source)


def _walk(
    node: Any, source: bytes, out: list[SimpleCommand], depth: int, pipes: Iterator[int]
) -> None:
    if node.is_missing or node.type == "ERROR":
        raise ValueError("unparseable input")
    t = node.type
    if t in _COMMAND_NODES:
        cmd = _grammar_command(node, source, depth, pipes)
        _walk_subs(node, source, out, depth, pipes)
        out.append(cmd)
        if cmd.program in SHELLS:
            script = inline_script(cmd.args)
            if script:
                inner_tree = _GRAMMAR_PARSER.parse(script.encode("utf-8"))
                _walk(inner_tree.root_node, script.encode("utf-8"), out, depth, pipes)
        return
    if t == "redirected_statement":
        start = len(out)
        for child in node.children:
            if child.is_named and child.type not in ("file_redirect", "heredoc_redirect"):
                _walk(child, source, out, depth, pipes)
        redirects = tuple(
            rt
            for c in node.children
            if c.type in ("file_redirect", "heredoc_redirect")
            for rt in [_redirect_text(source, c)]
            if rt
        )
        # attach to the last command emitted at this depth — nested substitution
        # commands emitted after the parent must not receive its redirect
        if redirects:
            for i in range(len(out) - 1, start - 1, -1):
                if out[i].paren_depth == depth:
                    last = out[i]
                    out[i] = replace(
                        last,
                        redirects=last.redirects
                        + tuple(Redirect(op=o, target=t) for o, t in redirects),
                    )
                    break
        if start == len(out):
            for child in node.children:
                if child.is_named:
                    _walk(child, source, out, depth, pipes)
        return
    if t == "pipeline":
        pid: int = next(pipes)
        for child in node.children:
            if child.is_named and child.type != "comment":
                _walk(child, source, out, depth, iter([pid] * 1_000_000))
        return
    if t in _DEPTH_NODES:
        for child in node.children:
            if child.is_named:
                _walk(child, source, out, depth + 1, pipes)
        return
    if t in _CONTAINER_NODES or node.named_child_count:
        for child in node.children:
            if child.is_named and child.type != "comment":
                _walk(child, source, out, depth, pipes)


def _word_text(node: Any, source: bytes) -> str:
    """Token text with quotes removed, matching the hand tokenizer's output."""
    t = node.type
    if t in ("raw_string", "ansi_c_string"):
        text = source[node.start_byte : node.end_byte].decode("utf-8", "replace")
        return text[text.index("'") + 1 : -1] if "'" in text else text
    if t == "string":
        inner = "".join(_word_text(c, source) for c in node.children if c.is_named)
        return (
            inner
            if inner
            else source[node.start_byte : node.end_byte].decode("utf-8", "replace").strip('"')
        )
    if t == "concatenation":
        return "".join(_word_text(c, source) for c in node.children if c.is_named)
    return source[node.start_byte : node.end_byte].decode("utf-8", "replace")


def _command_words(node: Any, source: bytes) -> list[str]:
    """argv words of a `command` node: name + argument children, unquoted text."""
    return [
        _word_text(c, source)
        for c in node.children
        if c.is_named
        and c.type
        not in (
            "variable_assignment",
            "file_redirect",
            "heredoc_redirect",
            "command_substitution",
            "process_substitution",
        )
    ]


def _walk_subs(
    node: Any, source: bytes, out: list[SimpleCommand], depth: int, pipes: Iterator[int]
) -> None:
    """Emit commands inside $( )/ <( )/ `(backtick)` found anywhere in a command's args."""
    for child in node.children:
        if not child.is_named:
            continue
        if child.type in ("command_substitution", "subshell"):
            _walk(child, source, out, depth, pipes)
        elif child.type == "process_substitution" or child.type in _COMMAND_NODES:
            continue  # process-subst content is already inlined into the parent argv
        else:
            _walk_subs(child, source, out, depth, pipes)


def _grammar_command(node: Any, source: bytes, depth: int, pipes: Iterator[int]) -> SimpleCommand:
    argv: list[str] = []
    assignments: list[str] = []
    redirects: list[tuple[str, str]] = []
    if node.type == "test_command":
        text = source[node.start_byte : node.end_byte].decode("utf-8", "replace")
        op = "[[" if text.startswith("[[") else "["
        inner = [
            source[g.start_byte : g.end_byte].decode("utf-8", "replace")
            for c in node.children
            if c.is_named
            for g in (c.children if c.type in ("unary_expression", "binary_expression") else (c,))
            if g.is_named
        ]
        return SimpleCommand(
            line=node.start_point[0] + 1,
            argv=tuple([op, *inner, op.replace("[", "]")]),
            pipeline=next(pipes),
            paren_depth=depth,
        )
    named = [c for c in node.children if c.is_named]
    for child in named:
        if child.type == "command_name":
            argv.append(_word_text(child, source))
        elif child.type == "variable_assignment":
            assignments.append(source[child.start_byte : child.end_byte].decode("utf-8", "replace"))
        elif child.type in ("file_redirect", "heredoc_redirect"):
            rt = _redirect_text(source, child)
            if rt:
                redirects.append(rt)
        elif child.type == "command_substitution":
            continue  # opaque substitution arg — the inner commands are emitted separately
        elif child.type == "process_substitution":
            redirects.append(("<", "("))
            for inner_cmd in child.children:
                if inner_cmd.is_named and inner_cmd.type == "command":
                    argv.extend(_command_words(inner_cmd, source))
        else:
            argv.append(_word_text(child, source))
    # nested substitutions inside arguments run their own commands
    wrappers, argv = _unwrap(argv)
    lineno = node.start_point[0] + 1
    return SimpleCommand(
        line=lineno,
        argv=tuple(argv),
        redirects=tuple(Redirect(op=o, target=t) for o, t in redirects),
        pipeline=next(pipes),
        wrappers=tuple(wrappers),
        assignments=tuple(assignments),
        paren_depth=depth,
    )


def _parse_grammar(source: str) -> ParsedScript | None:
    """Parse via the real Bash grammar (tree-sitter); None when unavailable/failed."""
    if _GRAMMAR_PARSER is None:
        return None
    try:
        tree = _GRAMMAR_PARSER.parse(source.encode("utf-8"))
        if _has_error(tree.root_node):
            return None
        parsed = ParsedScript(source=source)
        src = source.encode("utf-8")
        pipes = iter(range(1, 1_000_000_000))
        _walk(tree.root_node, src, parsed.commands, 0, pipes)
        parsed.commands.sort(key=lambda c: (c.line))
        return parsed
    except Exception:
        return None


CD_PROGRAMS = frozenset({"cd", "pushd"})


def _cd_target(cmd: SimpleCommand, cwd: str) -> str:
    args = positional_args(cmd.args)
    if not args:
        return "$HOME"
    target = args[0]
    if target.startswith("~"):
        return "$HOME" + target[1:]
    if target == "-" or (target.startswith("$") and not target.startswith(("$HOME", "${HOME}"))):
        # OLDPWD and variable directories are not tracked; keep the current
        # directory so later paths are still classified against a known cwd.
        return cwd
    if target.startswith("/"):
        return posixpath.normpath(target)
    return posixpath.normpath(posixpath.join(cwd, target))


def apply_cwds(parsed: ParsedScript, initial: str) -> None:
    """Annotate every command with the working directory it runs under.

    ``cd``/``pushd`` update the frame at their subshell depth; deeper frames
    inherit the parent cwd and are discarded when the script leaves the
    subshell, matching shell semantics closely enough for path classification.
    """
    frames: list[str] = [posixpath.normpath(initial)]
    for idx, cmd in enumerate(parsed.commands):
        frames = frames[: cmd.paren_depth + 1]
        while len(frames) <= cmd.paren_depth:
            frames.append(frames[-1])
        cwd = frames[cmd.paren_depth]
        parsed.commands[idx] = replace(cmd, cwd=cwd)
        if cmd.program in CD_PROGRAMS:
            frames[cmd.paren_depth] = _cd_target(cmd, cwd)


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
