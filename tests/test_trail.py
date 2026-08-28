"""Chain verification against REAL engine-written trails (tests/fixtures/*.jsonl
were produced by eg_gateway --log) plus systematic tamper cases."""

import hashlib
import json
from pathlib import Path

from onyx_gate_drata import genesis_hash, verify_trail_bytes

FIXTURES = Path(__file__).parent / "fixtures"
OBOT = (FIXTURES / "obot-session.trail.jsonl").read_bytes()
CREWAI = (FIXTURES / "crewai-session.trail.jsonl").read_bytes()


def test_genesis_hash_is_the_engines():
    assert genesis_hash() == hashlib.sha256(b"onyx-audit-trail-genesis-v1").hexdigest()


def test_real_obot_trail_verifies():
    r = verify_trail_bytes(OBOT)
    assert r.ok(require_chained=True)
    c = r.counts
    assert (len(r.records), c["linked"], c["allow"], c["deny"]) == (4, 4, 2, 2)
    # The head eg_verify reported for this same trail — the two verifiers agree.
    assert r.chain_head == "bd031f2aa6f3f0776a033024f4832a3f088eeb63848956f4c941aef069e50624"


def test_real_crewai_trail_verifies_with_certificates():
    r = verify_trail_bytes(CREWAI)
    assert r.ok(require_chained=True)
    c = r.counts
    assert len(r.records) == 8
    assert c["certificates"] == 4  # the ?certify=true half of the session
    assert c["allow"] == 6 and c["deny"] == 2


def test_edited_record_breaks_the_next_link():
    tampered = OBOT.replace(b'"decision":"deny"', b'"decision":"allow"', 1)
    assert tampered != OBOT
    r = verify_trail_bytes(tampered)
    assert not r.ok()
    broken = [rec.index for rec in r.records if rec.status == "broken"]
    assert broken  # the record AFTER the edited line no longer matches
    assert "edited, deleted, or reordered" in r.records[broken[0] - 1].detail


def test_deleted_record_breaks_the_chain():
    lines = OBOT.splitlines()
    r = verify_trail_bytes(b"\n".join(lines[:1] + lines[2:]))
    assert not r.ok()
    assert any(rec.status == "broken" for rec in r.records)


def test_reordered_records_break_the_chain():
    lines = OBOT.splitlines()
    lines[1], lines[2] = lines[2], lines[1]
    r = verify_trail_bytes(b"\n".join(lines))
    assert not r.ok()


def test_truncated_tail_still_verifies_but_head_moves():
    # The documented limit: chopping the tail leaves a valid chain — detection
    # is external anchoring of the head, which must therefore change.
    lines = OBOT.splitlines()
    full = verify_trail_bytes(OBOT)
    cut = verify_trail_bytes(b"\n".join(lines[:2]))
    assert cut.ok()
    assert cut.chain_head != full.chain_head


def test_unchained_record_is_tolerated_but_flagged():
    legacy = json.dumps({"tool": "gate", "arguments": {}, "result": {"decision": "allow"}}).encode()
    r = verify_trail_bytes(OBOT + legacy + b"\n")
    assert r.counts["unchained"] == 1
    assert r.ok()  # default: legacy records tolerated (the engine's default)
    assert not r.ok(require_chained=True)


def test_malformed_line_fails_loud():
    r = verify_trail_bytes(OBOT + b"not json\n")
    assert r.counts["malformed"] == 1
    assert not r.ok()


def test_empty_trail_is_not_ok():
    r = verify_trail_bytes(b"")
    assert not r.ok()
    assert r.chain_head == ""


def test_trailing_blank_lines_are_tolerated():
    assert verify_trail_bytes(OBOT + b"\n\n").ok(require_chained=True)
