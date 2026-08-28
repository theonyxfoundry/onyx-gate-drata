"""Independent verification of an Onyx decision trail — pure Python, no engine.

An Onyx gateway (`eg_gateway --log`) or MCP server (`eg_mcp --log`) appends one
JSON record per authorization decision to a JSONL trail. The trail is
**hash-chained**: every record carries a ``chain`` field holding the SHA-256
(lowercase hex) of the previous line's exact bytes; the first record's ``chain``
is ``SHA256("onyx-audit-trail-genesis-v1")``. Editing, deleting, or reordering
any record breaks every later link.

This module re-checks that chain with the Python standard library alone, so an
auditor (or a compliance platform) can confirm trail integrity without
installing or trusting the engine that wrote it. What it deliberately does NOT
do: re-check the decision *certificates* embedded in records — those are
re-derived by the engine's proof kernel (``eg_verify --audit-log``), which this
report points at. Chain integrity here, proof re-checking there; the two
checks are independent, which is the point.

The chain also cannot prove the file is complete — deleting the whole tail (or
file) leaves a valid chain. Anchor the reported chain head externally (a
ticket, a signed email, this filed evidence) to detect truncation.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Optional

GENESIS_TAG = b"onyx-audit-trail-genesis-v1"

LINKED = "linked"
BROKEN = "broken"
UNCHAINED = "unchained"
MALFORMED = "malformed"


def genesis_hash() -> str:
    return hashlib.sha256(GENESIS_TAG).hexdigest()


@dataclass(frozen=True)
class RecordCheck:
    """One trail record's verification outcome."""

    index: int  # 1-based, counting non-blank lines
    status: str  # linked | broken | unchained | malformed
    tool: Optional[str] = None
    decision: Optional[str] = None
    explanation: Optional[str] = None
    has_certificate: bool = False
    detail: Optional[str] = None  # for broken/malformed: what went wrong


@dataclass
class TrailReport:
    """The whole-trail verification result."""

    name: str
    records: list[RecordCheck] = field(default_factory=list)
    chain_head: str = ""  # SHA-256 of the last line — anchor this externally

    @property
    def counts(self) -> dict[str, int]:
        c = {LINKED: 0, BROKEN: 0, UNCHAINED: 0, MALFORMED: 0, "allow": 0, "deny": 0, "certificates": 0}
        for r in self.records:
            c[r.status] += 1
            if r.decision in ("allow", "deny"):
                c[r.decision] += 1
            if r.has_certificate:
                c["certificates"] += 1
        return c

    def ok(self, require_chained: bool = False) -> bool:
        """True iff the chain verifies: at least one record, none broken or
        malformed (``require_chained`` additionally refuses unchained legacy
        records — records written before chaining existed)."""
        c = self.counts
        if not self.records or c[BROKEN] or c[MALFORMED]:
            return False
        if require_chained and c[UNCHAINED]:
            return False
        return True

    def summary_line(self) -> str:
        c = self.counts
        chain = f"{c[LINKED]} linked, {c[UNCHAINED]} unchained, {c[BROKEN]} broken"
        if c[MALFORMED]:
            chain += f", {c[MALFORMED]} malformed"
        return (
            f"{len(self.records)} record(s): {c['allow']} allow / {c['deny']} deny, "
            f"{c['certificates']} with certificates; chain: {chain}"
        )


def verify_trail_bytes(data: bytes, name: str = "trail") -> TrailReport:
    """Re-check the hash chain over the trail's exact bytes.

    The hash covers each line's verbatim bytes (without the newline), so the
    trail must be passed unmodified — never re-serialized, re-encoded, or
    newline-converted.
    """
    report = TrailReport(name=name)
    expected = genesis_hash()
    index = 0
    for raw_line in data.split(b"\n"):
        if not raw_line.strip():
            continue  # the writer never emits blank lines; tolerate trailing ones
        index += 1
        status_detail: Optional[str] = None
        try:
            record = json.loads(raw_line)
            if not isinstance(record, dict):
                raise ValueError("record is not a JSON object")
        except ValueError as e:
            report.records.append(
                RecordCheck(index=index, status=MALFORMED, detail=str(e)[:200])
            )
            # A malformed line still advances the chain expectation by its
            # bytes, exactly as the writer would have hashed whatever is there.
            expected = hashlib.sha256(raw_line).hexdigest()
            continue

        chain = record.get("chain")
        if chain is None:
            status = UNCHAINED
        elif chain == expected:
            status = LINKED
        else:
            status = BROKEN
            status_detail = (
                f"recorded link {str(chain)[:16]}… does not match the expected "
                f"{expected[:16]}… — the previous record was edited, deleted, or "
                "reordered (or this record moved)"
            )

        result = record.get("result") or {}
        report.records.append(
            RecordCheck(
                index=index,
                status=status,
                tool=record.get("tool"),
                decision=result.get("decision"),
                explanation=result.get("explanation"),
                has_certificate=result.get("certificate") is not None,
                detail=status_detail,
            )
        )
        expected = hashlib.sha256(raw_line).hexdigest()

    report.chain_head = expected if report.records else ""
    return report


def verify_trail(path: str) -> TrailReport:
    with open(path, "rb") as f:
        return verify_trail_bytes(f.read(), name=path)
