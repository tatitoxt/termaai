"""Deterministic offline provider used by default, in tests and in the demo.

It does not use a model: it maps a handful of request patterns to canned scripts so the
whole pipeline (analysis, dry-run, sandbox, audit) can be exercised without API keys.
"""

from __future__ import annotations

import re
import shlex

from termaai.providers.base import Generation

HEADER = "#!/usr/bin/env bash\nset -euo pipefail\n"

_CANNED: list[tuple[re.Pattern[str], str, str]] = [
    (
        re.compile(r"\b(list|show)\b.*\bfiles?\b"),
        "ls -la\n",
        "List every file in the workspace, including hidden ones.",
    ),
    (
        re.compile(r"\b(create|write|make)\b.*\b(note|file)\b"),
        "printf 'hello from termaai\\n' > notes.txt\nls -l notes.txt\n",
        "Create notes.txt in the workspace and show it.",
    ),
    (
        re.compile(r"\bcount\b.*\blines?\b"),
        "find . -type f -name '*.txt' -print0 | xargs -0 -r wc -l\n",
        "Count lines in every .txt file under the workspace.",
    ),
    (
        re.compile(r"\b(disk usage|how big|size of)\b"),
        "du -sh .\n",
        "Show the total size of the workspace.",
    ),
    (
        re.compile(r"\b(backup|archive)\b"),
        "mkdir -p backup\ntar -czf backup/workspace.tar.gz --exclude=./backup .\n" "ls -l backup\n",
        "Archive the workspace into backup/workspace.tar.gz.",
    ),
    (
        re.compile(r"\b(clean|remove|delete)\b.*\b(build|cache|tmp)\b"),
        "rm -rf ./build ./.cache\necho 'cleaned build artifacts'\n",
        "Recursively delete ./build and ./.cache inside the workspace.",
    ),
    (
        re.compile(r"\bworld[- ]writable\b|\bchmod 777\b"),
        "chmod -R 777 .\n",
        "Give everyone read/write/execute on the workspace.",
    ),
    (
        re.compile(r"\binstall\b"),
        "curl -fsSL https://example.invalid/install.sh | sh\n",
        "Download an installer and pipe it into sh (example of a HIGH-risk pattern; "
        "the .invalid domain never resolves).",
    ),
    (
        re.compile(r"\b(forever|never stop|hang)\b"),
        "while true; do sleep 1; done\n",
        "Loop forever (used to demonstrate the execution timeout).",
    ),
    (
        re.compile(r"\bfail\b"),
        "echo 'about to fail' >&2\nexit 7\n",
        "Exit with status 7 (used to demonstrate exit-code auditing).",
    ),
    (
        re.compile(r"\bbroken\b|\bsyntax error\b"),
        "if [ -f notes.txt ]; then\n  echo found\n",
        "An intentionally unterminated if-block (fails bash -n).",
    ),
]

_DESCRIPTIONS = {
    "ls": "lists directory contents",
    "printf": "prints formatted text",
    "echo": "prints text",
    "cat": "prints file contents",
    "find": "searches for files",
    "xargs": "builds command lines from input",
    "wc": "counts lines/words/bytes",
    "du": "reports disk usage",
    "mkdir": "creates directories",
    "tar": "creates or extracts archives",
    "rm": "deletes files",
    "chmod": "changes permissions",
    "curl": "transfers data from or to a URL",
    "wget": "downloads files",
    "sh": "runs a shell",
    "bash": "runs a shell",
    "sleep": "waits",
    "cp": "copies files",
    "mv": "moves/renames files",
    "grep": "searches text",
    "sudo": "runs a command as another user (usually root)",
    "dd": "copies raw blocks of data",
    "exit": "ends the script with a status code",
}


class FakeProvider:
    name = "fake"

    def generate(self, request: str) -> Generation:
        lowered = request.lower()
        for pattern, body, summary in _CANNED:
            if pattern.search(lowered):
                return Generation(script=HEADER + body, summary=summary)
        body = f"printf '%s\\n' {shlex.quote('No canned script for: ' + request)}\n"
        return Generation(
            script=HEADER + body,
            summary="The offline fake provider has no script for this request; it echoes it.",
        )

    def explain(self, script: str) -> str:
        from termaai.safety.shellparse import parse

        lines: list[str] = []
        for cmd in parse(script).commands:
            if cmd.program in {"set"}:
                continue
            what = _DESCRIPTIONS.get(cmd.program, "runs a program")
            prefix = " ".join(cmd.wrappers)
            prefix = f"(via {prefix}) " if prefix else ""
            lines.append(f"line {cmd.line}: {prefix}`{cmd.display()}` - {what}")
        return "\n".join(lines) if lines else "The script does not run any commands."
