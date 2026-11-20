"""Rule-based risk analyzer for generated Bash scripts.

Each rule inspects the parsed commands (and, for a few patterns, the raw text) and
emits :class:`Finding` objects. The overall level is the highest finding level.
"""

from __future__ import annotations

import posixpath
import re
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from enum import IntEnum
from itertools import pairwise

from termaai.safety import paths
from termaai.safety.paths import Scope
from termaai.safety.shellparse import (
    SHELLS,
    WRITE_REDIRECTS,
    ParsedScript,
    SimpleCommand,
    inline_script,
    parse,
    positional_args,
    short_flags,
)


class RiskLevel(IntEnum):
    LOW = 1
    MEDIUM = 2
    HIGH = 3

    def __str__(self) -> str:
        return self.name


@dataclass(frozen=True)
class Finding:
    rule: str
    level: RiskLevel
    line: int
    message: str
    command: str = ""

    def to_dict(self) -> dict[str, object]:
        return {
            "rule": self.rule,
            "level": str(self.level),
            "line": self.line,
            "message": self.message,
        }


@dataclass
class RiskReport:
    findings: list[Finding] = field(default_factory=list)

    @property
    def level(self) -> RiskLevel:
        return max((f.level for f in self.findings), default=RiskLevel.LOW)

    @property
    def rules(self) -> list[str]:
        return sorted({f.rule for f in self.findings})


DOWNLOADERS = frozenset({"curl", "wget", "fetch", "aria2c"})
INTERPRETERS = SHELLS | frozenset(
    {"python", "python3", "perl", "ruby", "node", "php", "lua", "source", "."}
)
NETWORK_TOOLS = DOWNLOADERS | frozenset(
    {"nc", "ncat", "netcat", "socat", "telnet", "ssh", "scp", "sftp", "ftp", "rsync", "ping"}
)
DATA_SOURCES = frozenset(
    {"cat", "tar", "zip", "gzip", "base64", "xxd", "od", "find", "env", "printenv", "history"}
)
DISK_TOOLS = frozenset(
    {"mkfs", "wipefs", "fdisk", "sfdisk", "gdisk", "parted", "mkswap", "blkdiscard", "losetup"}
)
_BLOCK_DEVICE = re.compile(r"^/dev/(sd|hd|vd|xvd|nvme|mmcblk|disk|loop|mapper|md|dm-|sr)")
_FORK_BOMB = re.compile(
    r"(?P<name>[A-Za-z_:.][A-Za-z0-9_:.]*)\s*\(\s*\)\s*\{[^}]*"
    r"(?P=name)\s*\|\s*(?P=name)\s*&[^}]*\}"
)
_DOWNLOAD_SUBST = re.compile(r"\$\(\s*(curl|wget)\b")
_CREDENTIAL_PATHS = re.compile(
    r"(/etc/shadow|/etc/gshadow|/etc/sudoers|\.ssh/id_[A-Za-z0-9_]+|\.ssh/authorized_keys"
    r"|\.aws/credentials|\.netrc|\.git-credentials|\.docker/config\.json|\.kube/config"
    r"|\.gnupg/)"
)
_WORLD_WRITABLE_MODE = re.compile(r"^0?[0-7]?[0-7][0-7][2367]$")
_SETUID_MODE = re.compile(r"^0?[4-7][0-7]{3}$")

Rule = Callable[[ParsedScript, str], Iterable[Finding]]
_RULES: list[Rule] = []


def rule(fn: Rule) -> Rule:
    _RULES.append(fn)
    return fn


def _finding(name: str, level: RiskLevel, cmd: SimpleCommand, message: str) -> Finding:
    return Finding(name, level, cmd.line, message, cmd.display())


def delete_targets(cmd: SimpleCommand) -> list[str]:
    if cmd.program in {"rm", "rmdir", "unlink", "shred"}:
        return positional_args(cmd.args)
    if cmd.program == "find" and ("-delete" in cmd.args or _find_execs_rm(cmd)):
        return find_roots(cmd)
    return []


def find_roots(cmd: SimpleCommand) -> list[str]:
    roots: list[str] = []
    for arg in cmd.args:
        if arg.startswith("-") or arg in {"(", "!", ")"}:
            break
        roots.append(arg)
    return roots or ["."]


def _find_execs_rm(cmd: SimpleCommand) -> bool:
    args = list(cmd.args)
    for idx, arg in enumerate(args[:-1]):
        if arg in {"-exec", "-execdir", "-ok"} and args[idx + 1].rsplit("/", 1)[-1] == "rm":
            return True
    return False


def write_targets(cmd: SimpleCommand) -> list[str]:
    """Paths a command writes, creates or modifies (deletions excluded)."""
    targets = [r.target for r in cmd.redirects if r.op in WRITE_REDIRECTS]
    prog, args = cmd.program, cmd.args
    if prog in {"cp", "mv", "install", "ln", "rsync"}:
        pos = positional_args(args, frozenset({"-t", "-S", "--suffix", "-m", "-o", "-g"}))
        if "-t" in args:
            idx = args.index("-t")
            if idx + 1 < len(args):
                targets.append(args[idx + 1])
        elif len(pos) >= 2 and ":" not in pos[-1]:
            targets.append(pos[-1])
    elif prog in {"touch", "mkdir", "tee", "mkfifo"}:
        targets += positional_args(args, frozenset({"-m", "-d", "-t", "-r"}))
    elif prog == "truncate":
        targets += positional_args(args, frozenset({"-s", "--size", "-r"}))
    elif prog in {"chmod", "chown", "chgrp"}:
        targets += positional_args(args)[1:]
    elif prog in {"sed", "perl"} and any(a == "-i" or a.startswith("-i") for a in args):
        pos = positional_args(args, frozenset({"-e", "-f"}))
        targets += pos if ("-e" in args or "-f" in args) else pos[1:]
    elif prog == "dd":
        targets += [a[3:] for a in args if a.startswith("of=")]
    elif prog == "tar":
        targets += _tar_writes(args)
    elif prog in {"unzip"}:
        if "-d" in args:
            idx = args.index("-d")
            targets += list(args[idx + 1 : idx + 2])
    return [t for t in targets if t]


def _tar_writes(args: tuple[str, ...]) -> list[str]:
    if not args:
        return []
    first = args[0].lstrip("-")
    cluster = set(first) if not args[0].startswith("--") else set()
    for a in args:
        if a.startswith("-") and not a.startswith("--"):
            cluster |= set(a[1:])
    out: list[str] = []
    if "c" in cluster or "r" in cluster or "u" in cluster:
        for idx, a in enumerate(args):
            if a.startswith("--file="):
                out.append(a.split("=", 1)[1])
            elif (a == "-f" or (not a.startswith("--") and a.lstrip("-").endswith("f"))) and (
                idx + 1 < len(args)
            ):
                out.append(args[idx + 1])
                break
    if "x" in cluster:
        if "-C" in args:
            idx = args.index("-C")
            out += list(args[idx + 1 : idx + 2])
        else:
            out.append(".")
    return out


@rule
def destructive_rm(parsed: ParsedScript, workspace: str) -> Iterable[Finding]:
    for cmd in parsed.commands:
        targets = delete_targets(cmd)
        if not targets:
            continue
        flags = short_flags(cmd.args)
        recursive = cmd.program == "find" or bool(flags & {"r", "R", "--recursive"})
        if "--no-preserve-root" in cmd.args:
            yield _finding("destructive_rm", RiskLevel.HIGH, cmd, "rm with --no-preserve-root")
            continue
        for target in targets:
            scope = paths.classify(target, workspace)
            if scope in {Scope.ROOT, Scope.SYSTEM} or (
                scope is Scope.HOME and recursive and paths.home_relative(target) in {"", "*"}
            ):
                yield _finding(
                    "destructive_rm",
                    RiskLevel.HIGH,
                    cmd,
                    f"deletes {target!r} ({scope.value} path)",
                )
            elif scope is Scope.UNKNOWN and recursive:
                yield _finding(
                    "destructive_rm",
                    RiskLevel.HIGH,
                    cmd,
                    f"recursive delete of {target!r}: if the variable is empty this "
                    "expands to a path outside the workspace",
                )
            elif scope.outside_workspace:
                yield _finding(
                    "write_outside_workspace",
                    RiskLevel.HIGH if scope is Scope.HOME else RiskLevel.MEDIUM,
                    cmd,
                    f"deletes {target!r} outside the workspace ({scope.value})",
                )
            elif recursive:
                yield _finding(
                    "recursive_delete",
                    RiskLevel.MEDIUM,
                    cmd,
                    f"recursively deletes {target!r} inside the workspace",
                )


@rule
def write_outside_workspace(parsed: ParsedScript, workspace: str) -> Iterable[Finding]:
    for cmd in parsed.commands:
        for target in write_targets(cmd):
            if target.startswith("/dev/tcp/") or target.startswith("/dev/udp/"):
                continue
            scope = paths.classify(target, workspace)
            if scope is Scope.DEVICE:
                continue
            if scope in {Scope.ROOT, Scope.SYSTEM}:
                level, why = RiskLevel.HIGH, "system location"
            elif scope is Scope.HOME and paths.is_sensitive_home(target):
                level, why = RiskLevel.HIGH, "shell startup / credential file in $HOME"
            elif scope in {Scope.HOME, Scope.OUTSIDE}:
                level, why = RiskLevel.MEDIUM, f"{scope.value} path outside the workspace"
            elif scope is Scope.UNKNOWN:
                level, why = RiskLevel.MEDIUM, "path depends on a variable; cannot verify"
            elif scope is Scope.TEMP:
                level, why = RiskLevel.LOW, "temporary directory outside the workspace"
            else:
                continue
            yield _finding("write_outside_workspace", level, cmd, f"writes {target!r} ({why})")


def _runs_downloaded_code(cmd: SimpleCommand) -> bool:
    """``bash <(curl ...)``, ``source <(wget ...)`` or ``sh -c "$(curl ...)"``."""
    if cmd.program not in INTERPRETERS and cmd.program not in {"source", "."}:
        return False
    process_subst = any(r.op == "<" and r.target == "(" for r in cmd.redirects)
    operands = positional_args(cmd.args, frozenset({"-o", "-O", "--rcfile", "--init-file"}))
    if process_subst and operands and posixpath.basename(operands[0]) in DOWNLOADERS:
        return True
    script = inline_script(cmd.args)
    return script is not None and _DOWNLOAD_SUBST.match(script) is not None


@rule
def remote_code_execution(parsed: ParsedScript, workspace: str) -> Iterable[Finding]:
    for pipeline in parsed.pipelines():
        for left, right in pairwise(pipeline):
            if left.program in DOWNLOADERS and (
                right.program in INTERPRETERS or "sudo" in right.wrappers
            ):
                yield _finding(
                    "remote_code_execution",
                    RiskLevel.HIGH,
                    right,
                    f"pipes a download from {left.program} straight into {right.program}",
                )
            if left.program == "base64" and right.program in INTERPRETERS:
                yield _finding(
                    "obfuscated_execution",
                    RiskLevel.HIGH,
                    right,
                    "decodes base64 and executes the result",
                )
    for cmd in parsed.commands:
        if _runs_downloaded_code(cmd):
            yield _finding(
                "remote_code_execution",
                RiskLevel.HIGH,
                cmd,
                "executes a script downloaded at run time",
            )
        if cmd.program == "eval":
            yield _finding("dynamic_eval", RiskLevel.MEDIUM, cmd, "eval executes dynamic code")


@rule
def privilege_escalation(parsed: ParsedScript, workspace: str) -> Iterable[Finding]:
    for cmd in parsed.commands:
        elevated = [w for w in cmd.wrappers if w in {"sudo", "doas"}]
        if elevated or cmd.program in {"sudo", "su", "doas", "pkexec"}:
            name = elevated[0] if elevated else cmd.program
            yield _finding(
                "privilege_escalation", RiskLevel.HIGH, cmd, f"runs with elevated rights ({name})"
            )
        if cmd.program == "chmod":
            mode = (positional_args(cmd.args) or [""])[0]
            if "+s" in mode or _SETUID_MODE.match(mode):
                yield _finding(
                    "privilege_escalation", RiskLevel.HIGH, cmd, f"sets setuid/setgid bit ({mode})"
                )


@rule
def fork_bomb(parsed: ParsedScript, workspace: str) -> Iterable[Finding]:
    flat = parsed.source.replace("\n", " ")
    if _FORK_BOMB.search(flat):
        yield Finding("fork_bomb", RiskLevel.HIGH, 1, "self-replicating function (fork bomb)")


@rule
def insecure_permissions(parsed: ParsedScript, workspace: str) -> Iterable[Finding]:
    for cmd in parsed.commands:
        if cmd.program != "chmod":
            continue
        pos = positional_args(cmd.args)
        if not pos:
            continue
        mode, targets = pos[0], pos[1:]
        world_writable = bool(_WORLD_WRITABLE_MODE.match(mode)) or bool(
            re.search(r"(^|,)(a|o|ugo)?[+=][rx]*w", mode) and re.match(r"^(a|o|ugo|\+)", mode)
        )
        if not world_writable:
            continue
        broad = any(
            paths.classify(t, workspace) in {Scope.ROOT, Scope.SYSTEM, Scope.HOME} for t in targets
        )
        recursive = bool(short_flags(cmd.args) & {"R", "--recursive"})
        level = RiskLevel.HIGH if broad and recursive else RiskLevel.MEDIUM
        yield _finding(
            "insecure_permissions", level, cmd, f"makes files world-writable (chmod {mode})"
        )


@rule
def device_write(parsed: ParsedScript, workspace: str) -> Iterable[Finding]:
    for cmd in parsed.commands:
        base = cmd.program.split(".", 1)[0]
        if base in DISK_TOOLS:
            yield _finding(
                "device_write", RiskLevel.HIGH, cmd, f"{cmd.program} rewrites disks/partitions"
            )
            continue
        devices = [t for t in write_targets(cmd) if _BLOCK_DEVICE.match(t)]
        if cmd.program == "shred":
            devices += [t for t in positional_args(cmd.args) if t.startswith("/dev/")]
        for dev in devices:
            yield _finding("device_write", RiskLevel.HIGH, cmd, f"writes raw data to {dev}")


def _upload_flags(cmd: SimpleCommand) -> list[str]:
    hits: list[str] = []
    args = list(cmd.args)
    data_opts = {"-d", "--data", "--data-binary", "--data-raw", "--data-urlencode", "-F", "--form"}
    for idx, arg in enumerate(args):
        value = None
        if arg in data_opts and idx + 1 < len(args):
            value = args[idx + 1]
        elif "=" in arg and arg.split("=", 1)[0] in data_opts:
            value = arg.split("=", 1)[1]
        if value is not None and ("@" in value or "$(" in value or "`" in value):
            hits.append(f"{arg} {value}")
        if arg in {"-T", "--upload-file", "--post-file"} or arg.startswith("--post-file="):
            hits.append(arg)
    return hits


@rule
def network_exfiltration(parsed: ParsedScript, workspace: str) -> Iterable[Finding]:
    for cmd in parsed.commands:
        if cmd.program in {"curl", "wget"}:
            for hit in _upload_flags(cmd):
                yield _finding(
                    "network_exfiltration",
                    RiskLevel.HIGH,
                    cmd,
                    f"uploads local data over the network ({hit})",
                )
        if cmd.program in {"nc", "ncat", "netcat", "socat", "telnet"} and any(
            r.op == "<" for r in cmd.redirects
        ):
            yield _finding(
                "network_exfiltration", RiskLevel.HIGH, cmd, f"sends a file through {cmd.program}"
            )
        for r in cmd.redirects:
            if r.target.startswith(("/dev/tcp/", "/dev/udp/")):
                yield _finding(
                    "network_exfiltration",
                    RiskLevel.HIGH,
                    cmd,
                    f"opens a raw network socket ({r.target})",
                )
        if cmd.program in {"scp", "rsync"}:
            pos = positional_args(cmd.args, frozenset({"-e", "-P", "-i", "-o"}))
            if len(pos) >= 2 and ":" in pos[-1] and ":" not in pos[0]:
                yield _finding(
                    "network_exfiltration",
                    RiskLevel.HIGH,
                    cmd,
                    f"copies local files to remote host ({pos[-1]})",
                )
    for pipeline in parsed.pipelines():
        for left, right in pairwise(pipeline):
            if left.program in DATA_SOURCES and right.program in NETWORK_TOOLS - {"ping"}:
                yield _finding(
                    "network_exfiltration",
                    RiskLevel.HIGH,
                    right,
                    f"pipes local data from {left.program} into {right.program}",
                )
    for cmd in parsed.commands:
        if cmd.program in NETWORK_TOOLS:
            yield _finding(
                "network_access",
                RiskLevel.LOW,
                cmd,
                f"{cmd.program} needs network access (disabled in the Docker sandbox)",
            )


@rule
def credential_access(parsed: ParsedScript, workspace: str) -> Iterable[Finding]:
    for cmd in parsed.commands:
        for token in (*cmd.argv, *(r.target for r in cmd.redirects)):
            if _CREDENTIAL_PATHS.search(token):
                yield _finding(
                    "credential_access", RiskLevel.HIGH, cmd, f"touches credential file {token!r}"
                )
                break


@rule
def system_state(parsed: ParsedScript, workspace: str) -> Iterable[Finding]:
    for cmd in parsed.commands:
        prog, args = cmd.program, cmd.args
        if prog in {"shutdown", "reboot", "halt", "poweroff"} or (
            prog in {"init", "telinit"} and args[:1] in (("0",), ("6",))
        ):
            yield _finding(
                "system_state", RiskLevel.HIGH, cmd, f"{prog} stops or restarts the host"
            )
        elif prog == "kill" and "-1" in positional_args(args) + list(args[-1:]):
            yield _finding("system_state", RiskLevel.HIGH, cmd, "kill -1 signals every process")
        elif prog in {"killall", "pkill"}:
            yield _finding("system_state", RiskLevel.MEDIUM, cmd, f"{prog} kills processes by name")
        elif (
            prog == "systemctl"
            and args[:1]
            and args[0]
            in {
                "stop",
                "disable",
                "mask",
                "poweroff",
                "reboot",
                "halt",
                "kill",
                "enable",
            }
        ):
            level = (
                RiskLevel.HIGH if args[0] in {"poweroff", "reboot", "halt"} else RiskLevel.MEDIUM
            )
            yield _finding("system_state", level, cmd, f"systemctl {args[0]} changes services")
        elif prog == "crontab":
            level = RiskLevel.HIGH if "-r" in args else RiskLevel.MEDIUM
            yield _finding("persistence", level, cmd, "modifies the user's crontab")
        elif (prog == "history" and "-c" in args) or (prog == "unset" and "HISTFILE" in args):
            yield _finding("history_tampering", RiskLevel.MEDIUM, cmd, "clears shell history")


@rule
def package_install(parsed: ParsedScript, workspace: str) -> Iterable[Finding]:
    managers = {"apt", "apt-get", "yum", "dnf", "apk", "pacman", "zypper", "brew", "snap"}
    for cmd in parsed.commands:
        prog, args = cmd.program, cmd.args
        if (prog in managers and {"install", "remove", "purge", "-S", "add"} & set(args)) or (
            prog in {"pip", "pip3", "npm", "gem"} and "install" in args
        ):
            yield _finding(
                "package_install",
                RiskLevel.MEDIUM,
                cmd,
                f"{prog} changes installed packages and needs the network",
            )


def analyze(script: str, workspace: str = "/workspace") -> RiskReport:
    """Run every rule against ``script`` as if executed with cwd ``workspace``."""
    parsed = parse(script)
    report = RiskReport()
    seen: set[tuple[str, int, str]] = set()
    for check in _RULES:
        for finding in check(parsed, workspace):
            key = (finding.rule, finding.line, finding.message)
            if key not in seen:
                seen.add(key)
                report.findings.append(finding)
    report.findings.sort(key=lambda f: (-f.level, f.line, f.rule))
    return report


def rule_names() -> list[str]:
    return [r.__name__ for r in _RULES]
