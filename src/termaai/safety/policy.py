"""Per-workspace policy files (``.termaai.toml``) for the risk pipeline.

A policy file can tighten the analyzer for a specific workspace:

.. code-block:: toml

    # Programs that always produce a HIGH finding (POSIX ERE, basename match).
    deny_commands = ["mkfs.*", "dd"]

    # Programs whose analyzer findings are suppressed (exact basename match).
    allow_commands = ["make", "pytest"]

    # Analyzer rule names to skip in this workspace (see `rule_names()`).
    disable_rules = ["network_access"]

    # Highest risk level that may still run -- scripts above it are blocked
    # unconditionally, even with --force. Default: "high" (current behaviour).
    max_level = "medium"

The file is discovered at ``<workspace>/.termaai.toml`` or given explicitly
with ``--policy``. Anything wrong with it is a hard error: a policy that
fails to parse must never silently fall back to defaults.
"""

from __future__ import annotations

import re
import sys
from dataclasses import dataclass
from pathlib import Path

if sys.version_info >= (3, 11):
    import tomllib
else:  # pragma: no cover - exercised on Python 3.10
    import tomli as tomllib

from termaai.safety.risk import RiskLevel

POLICY_FILENAME = ".termaai.toml"
MAX_ENTRIES = 64
MAX_PATTERN_LENGTH = 200
KNOWN_KEYS = frozenset({"deny_commands", "allow_commands", "disable_rules", "max_level"})


class PolicyError(Exception):
    """The policy file is missing keys, malformed or internally invalid."""


@dataclass(frozen=True)
class Policy:
    deny_commands: tuple[re.Pattern[str], ...] = ()
    allow_commands: frozenset[str] = frozenset()
    disable_rules: frozenset[str] = frozenset()
    max_level: RiskLevel = RiskLevel.HIGH
    source: Path | None = None

    @property
    def active(self) -> bool:
        return (
            bool(self.deny_commands or self.allow_commands or self.disable_rules)
            or self.max_level is not RiskLevel.HIGH
        )


DEFAULT = Policy()


def discover(workspace: Path) -> Policy:
    """Load ``<workspace>/.termaai.toml`` when it exists, else the default."""
    path = workspace / POLICY_FILENAME
    if not path.is_file():
        return DEFAULT
    return load(path)


def _strings(path: Path, key: str, value: object, seen: set[str]) -> list[str]:
    if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
        raise PolicyError(f"{path.name}: {key} must be a list of strings")
    if len(value) > MAX_ENTRIES:
        raise PolicyError(f"{path.name}: {key} has {len(value)} entries (max {MAX_ENTRIES})")
    out: list[str] = []
    for item in value:
        if len(item) > MAX_PATTERN_LENGTH or not item:
            raise PolicyError(f"{path.name}: invalid entry {item!r} in {key}")
        if item in seen:
            raise PolicyError(f"{path.name}: duplicate entry {item!r} in {key}")
        seen.add(item)
        out.append(item)
    return out


def load(path: Path) -> Policy:
    """Parse and validate a policy file. Raises :class:`PolicyError`."""
    try:
        raw = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise PolicyError(f"{path.name}: {exc}") from exc
    unknown = set(raw) - KNOWN_KEYS
    if unknown:
        raise PolicyError(
            f"{path.name}: unknown keys {sorted(unknown)} " f"(valid: {sorted(KNOWN_KEYS)})"
        )
    deny: list[re.Pattern[str]] = []
    for pattern in _strings(path, "deny_commands", raw.get("deny_commands", []), set()):
        try:
            deny.append(re.compile(pattern))
        except re.error as exc:
            raise PolicyError(f"{path.name}: bad regex {pattern!r}: {exc}") from exc
    allow = _strings(path, "allow_commands", raw.get("allow_commands", []), set())
    for name in allow:
        if not re.fullmatch(r"[A-Za-z0-9_.+-]+", name):
            raise PolicyError(f"{path.name}: {name!r} is not a command basename")
    disable = _strings(path, "disable_rules", raw.get("disable_rules", []), set())
    max_level = RiskLevel.HIGH
    raw_level = raw.get("max_level")
    if raw_level is not None:
        if not isinstance(raw_level, str) or raw_level.upper() not in RiskLevel.__members__:
            raise PolicyError(
                f"{path.name}: max_level must be one of low, medium or high, " f"got {raw_level!r}"
            )
        max_level = RiskLevel[raw_level.upper()]
    return Policy(
        deny_commands=tuple(deny),
        allow_commands=frozenset(allow),
        disable_rules=frozenset(disable),
        max_level=max_level,
        source=path,
    )
