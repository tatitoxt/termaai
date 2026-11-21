"""Run the analyzer against a labelled corpus of dangerous and safe scripts."""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from termaai.safety.risk import RiskLevel, analyze

CORPUS = Path(__file__).resolve().parents[1] / "corpus"
WORKSPACE = "/workspace"


def _cases(kind: str) -> list[Path]:
    return sorted((CORPUS / kind).glob("*.sh"))


def _expect(script: str, key: str) -> str | None:
    match = re.search(rf"^# expect-{key}: (\S+)$", script, re.MULTILINE)
    return match.group(1) if match else None


@pytest.mark.parametrize("path", _cases("dangerous"), ids=lambda p: p.stem)
def test_dangerous_script_is_flagged(path: Path) -> None:
    script = path.read_text()
    report = analyze(script, WORKSPACE)
    assert str(report.level) == _expect(script, "level"), report.findings
    assert _expect(script, "rule") in report.rules, report.rules
    assert all(f.message for f in report.findings)


@pytest.mark.parametrize("path", _cases("safe"), ids=lambda p: p.stem)
def test_safe_script_is_low_risk(path: Path) -> None:
    report = analyze(path.read_text(), WORKSPACE)
    assert report.level is RiskLevel.LOW, report.findings


def test_corpus_is_not_trivially_small() -> None:
    assert len(_cases("dangerous")) >= 50
    assert len(_cases("safe")) >= 20
