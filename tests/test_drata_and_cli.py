import json
from pathlib import Path

import pytest

from onyx_gate_drata import DrataClient, DrataError, build_markdown, verify_trail_bytes
from onyx_gate_drata.cli import main
from tests.stub_drata import StubDrata

FIXTURES = Path(__file__).parent / "fixtures"
OBOT = FIXTURES / "obot-session.trail.jsonl"


# -- client --------------------------------------------------------------


def test_upload_and_create_roundtrip():
    with StubDrata() as stub:
        client = DrataClient("test-key", base_url=stub.url)
        key = client.upload_evidence_file(7, "t.trail.log", b"line1\n", "text/plain")
        assert key.endswith("/t.trail.log")
        assert stub.uploads[0]["workspace"] == 7
        assert b"line1" in stub.uploads[0]["body"]
        created = client.create_evidence(
            7, "n", "d", [{"type": "S3_FILE", "fileKey": key, "filedAt": "2026-08-28"}], [17, 42]
        )
        assert created["id"] == 4242
        assert stub.evidence[0]["controlIds"] == [17, 42]


def test_wrong_key_raises():
    with StubDrata(api_key="right") as stub:
        client = DrataClient("wrong", base_url=stub.url)
        with pytest.raises(DrataError, match="401"):
            client.upload_evidence_file(1, "x.log", b"x", "text/plain")


def test_unreachable_raises_and_bad_region_rejected():
    with pytest.raises(DrataError, match="unreachable"):
        DrataClient("k", base_url="http://127.0.0.1:1", timeout=0.5).create_evidence(1, "n", "d", [])
    with pytest.raises(DrataError, match="region"):
        DrataClient("k", region="mars")


# -- report --------------------------------------------------------------


def test_report_carries_verdict_head_and_denies():
    report = verify_trail_bytes(OBOT.read_bytes())
    md = build_markdown(report, "obot.trail.log", "2026-08-28T00:00:00+00:00")
    assert "VERIFIED — chain intact" in md
    assert report.chain_head in md
    assert "Denied calls" in md and "no permit policy matches" in md
    assert "eg_verify --audit-log" in md


def test_report_failed_verdict_on_tamper():
    tampered = OBOT.read_bytes().replace(b'"decision":"deny"', b'"decision":"allow"', 1)
    report = verify_trail_bytes(tampered)
    md = build_markdown(report, "t.log", "2026-08-28T00:00:00+00:00")
    assert "FAILED — do not rely on this trail" in md
    assert "Integrity failures" in md


# -- cli -----------------------------------------------------------------


def test_cli_verify_ok(capsys):
    assert main(["verify", str(OBOT), "--require-chained"]) == 0
    assert "chain: VERIFIED" in capsys.readouterr().out


def test_cli_verify_json_shape(capsys):
    assert main(["verify", str(OBOT), "--json"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["ok"] is True
    assert data["counts"]["linked"] == 4


def test_cli_verify_fails_on_tampered(tmp_path, capsys):
    bad = tmp_path / "bad.jsonl"
    bad.write_bytes(OBOT.read_bytes().replace(b'"deny"', b'"allow"', 1))
    assert main(["verify", str(bad)]) == 1


def test_cli_file_dry_run_writes_bundle(tmp_path, capsys):
    rc = main(
        ["file", str(OBOT), "--workspace-id", "7", "--control-ids", "17,42",
         "--dry-run", "--out-dir", str(tmp_path)]
    )
    assert rc == 0
    log = tmp_path / "obot-session.trail.log"
    md = tmp_path / "obot-session.verification.md"
    assert log.read_bytes() == OBOT.read_bytes()  # verbatim bytes, rename only
    assert "VERIFIED — chain intact" in md.read_text()


def test_cli_file_refuses_tampered_trail(tmp_path, monkeypatch, capsys):
    bad = tmp_path / "bad.jsonl"
    bad.write_bytes(OBOT.read_bytes().replace(b'"deny"', b'"allow"', 1))
    monkeypatch.setenv("DRATA_API_KEY", "test-key")
    with StubDrata() as stub:
        monkeypatch.setattr(
            "onyx_gate_drata.cli.DrataClient",
            lambda key, region: DrataClient(key, base_url=stub.url),
        )
        rc = main(["file", str(bad), "--workspace-id", "7"])
        assert rc == 1
        assert stub.uploads == [] and stub.evidence == []  # fail-closed: no network


def test_cli_file_against_stub(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("DRATA_API_KEY", "test-key")
    with StubDrata() as stub:
        monkeypatch.setattr(
            "onyx_gate_drata.cli.DrataClient",
            lambda key, region: DrataClient(key, base_url=stub.url),
        )
        rc = main(["file", str(OBOT), "--workspace-id", "9", "--control-ids", "17"])
        assert rc == 0
        assert [u["filename"] for u in stub.uploads] == [
            "obot-session.trail.log",
            "obot-session.verification.md",
        ]
        ev = stub.evidence[0]
        assert ev["_workspace"] == 9
        assert ev["controlIds"] == [17]
        assert {a["artifactName"] for a in ev["artifacts"]} == {
            "obot-session.trail.log",
            "obot-session.verification.md",
        }
        assert all(a["type"] == "S3_FILE" and a["fileKey"] for a in ev["artifacts"])
        out = capsys.readouterr().out
        assert "filed: evidence 4242" in out


def test_cli_file_without_key_is_usage_error(tmp_path, monkeypatch, capsys):
    monkeypatch.delenv("DRATA_API_KEY", raising=False)
    assert main(["file", str(OBOT), "--workspace-id", "7"]) == 2
