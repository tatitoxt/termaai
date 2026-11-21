"""Record/replay: captured model output replays verbatim and fails on divergence."""

from __future__ import annotations

import json

import pytest

from termaai.providers import ProviderError, get_provider
from termaai.providers.fake import FakeProvider
from termaai.providers.replay import RecordingProvider, ReplayProvider


@pytest.fixture()
def fixture_file(tmp_path):
    path = tmp_path / "replay.jsonl"
    inner = RecordingProvider(FakeProvider(), path)
    gen = inner.generate("list files")
    assert gen.script.startswith("#!")
    return path


def test_replay_serves_recorded_generation(fixture_file):
    replay = ReplayProvider(fixture_file)
    gen = replay.generate("list files")
    assert "ls -la" in gen.script


def test_replay_rejects_wrong_request(fixture_file):
    replay = ReplayProvider(fixture_file)
    with pytest.raises(ProviderError, match="recorded request"):
        replay.generate("do something else")


def test_replay_fails_when_exhausted(fixture_file):
    replay = ReplayProvider(fixture_file)
    replay.generate("list files")
    with pytest.raises(ProviderError, match="exhausted"):
        replay.generate("list files")


def test_replay_detects_op_mismatch(tmp_path):
    path = tmp_path / "r.jsonl"
    path.write_text(json.dumps({"op": "explain", "script": "x", "response": "y"}) + "\n")
    replay = ReplayProvider(path)
    with pytest.raises(ProviderError, match="diverged"):
        replay.generate("anything")


def test_replay_requires_existing_file(tmp_path):
    with pytest.raises(ProviderError, match="not found"):
        ReplayProvider(tmp_path / "nope.jsonl")


def test_replay_validates_json_records(tmp_path):
    path = tmp_path / "bad.jsonl"
    path.write_text("{not json\n")
    with pytest.raises(ProviderError, match="invalid JSON"):
        ReplayProvider(path)


def test_recording_captures_explain(tmp_path):
    path = tmp_path / "rec.jsonl"
    inner = RecordingProvider(FakeProvider(), path)
    inner.explain("ls")
    rec = json.loads(path.read_text().strip())
    assert rec["op"] == "explain" and isinstance(rec["response"], str)


def test_get_provider_replay_and_recording(fixture_file, tmp_path):
    replay = get_provider("replay", env={"TERMAAI_REPLAY_FILE": str(fixture_file)})
    assert replay.name == "replay"
    recorded = tmp_path / "out.jsonl"
    env = {"OPENAI_API_KEY": "x", "TERMAAI_RECORD_FILE": str(recorded)}
    provider = get_provider("openai", env=env)
    assert isinstance(provider, RecordingProvider)
