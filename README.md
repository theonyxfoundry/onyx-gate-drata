# Onyx Gate for Drata

**File verifiable AI-agent authorization evidence into Drata.** An Onyx
gateway decides every agent tool call against policy and appends each decision
— full call arguments, allow/deny verdict, policy version, optional
machine-checkable certificate — to a **hash-chained audit trail**. This bridge
re-verifies that trail's integrity independently (pure Python, no engine, no
dependencies) and files it as Drata Evidence linked to your controls, with a
report that tells the auditor exactly how to re-check everything themselves.

That last part is the point. Most AI-governance evidence is a screenshot or an
export — the auditor trusts whoever produced it. This trail is evidence an
auditor can **re-derive**: the chain rule is fifteen lines of any language,
and the decision certificates re-check against the engine's proof kernel.

```
Onyx gateway ──--log──▶ trail.jsonl ──verify + package──▶ Drata Evidence
 (decides every           hash-chained     onyx-gate-drata      linked to
  agent tool call)        JSONL            (this bridge)        your controls
```

## What it looks like

`verify` re-checks a trail offline — here against a real gateway session
(an accounts-payable agent whose $12,000 out-of-mandate payment was denied):

```text
$ onyx-gate-drata verify crewai-session.trail.jsonl
8 record(s): 6 allow / 2 deny, 4 with certificates; chain: 8 linked, 0 unchained, 0 broken
chain head: 0a91713a091d6c78f1b6ea1256d9f939303fbf49a5be5e3910d0d9fde2a88195
chain: VERIFIED
```

Edit one byte — quietly changing the denied amount from 12000 to 900 — and:

```text
8 record(s): 6 allow / 2 deny, 4 with certificates; chain: 7 linked, 0 unchained, 1 broken
  record 5: broken — recorded link 2ea6e5fe791f8a10… does not match the expected
            3c03da7eec5e6980… — the previous record was edited, deleted, or reordered
chain: FAILED        (exit 1)
```

This verifier is deliberately **independent of the engine** — and agrees with
it hash-for-hash: on the trails above, the engine's own checker (`eg_verify
--audit-log`) reports the identical chain head on the valid trail and the
identical broken link (same recorded/expected hashes) on the tampered one.
Two implementations, two codebases, one verdict.

`file` verifies and then files — **fail-closed: a trail that does not verify
is never filed**, and nothing touches the network on refusal:

```text
$ onyx-gate-drata file crewai-session.trail.jsonl --workspace-id 7 --control-ids 17,42
filed: evidence 4242 in workspace 7 ('Onyx decision trail — crewai-session')
linked controls: [17, 42]
chain head anchored in the evidence description: 0a91713a091d6c78…
```

Two artifacts land on the Evidence item: the **verbatim trail bytes**
(uploaded as `.log` — a rename for Drata's accepted types, the bytes
untouched so the hashes still verify) and a **Markdown verification report**:
the verdict, the decision summary, every deny with its policy reason, the
chain head to anchor, and the independent re-check instructions.

## Setup

```bash
pip install onyx-gate-drata      # standard library only
```

- **Drata side:** create an API key (Drata scopes keys per endpoint — this
  tool needs only the evidence write scope) and note your workspace id and
  the control ids to link (e.g. your AI-governance / access-control controls).
  Set `DRATA_API_KEY` or pass `--api-key-file`; `--region us|eu|apac` selects
  the API base. `--dry-run` writes the evidence bundle locally with no network
  calls, so you can inspect exactly what would be filed.
- **Onyx side:** run the gateway with `--log trail.jsonl`. Every integration
  writes the same trail — the [CrewAI tool guard](https://github.com/theonyxfoundry/onyx-gate-crewai),
  the [Obot MCP Gateway filter](https://github.com/theonyxfoundry/onyx-gate-obot),
  the Claude Code enforcement hook, or direct HTTP/MCP calls.
- Schedule `file` (cron, CI, a workflow) for recurring evidence: each filing
  carries the current chain head, so consecutive filings chain into each
  other — a later trail that doesn't extend the last anchored head is visible.

## The chain rule (the whole thing)

The first record's `chain` field must equal
`SHA256("onyx-audit-trail-genesis-v1")` in lowercase hex; every later
record's `chain` must equal the SHA-256 of the previous line's exact bytes.
That's it — auditors don't need this package, just any language's SHA-256.

```python
import hashlib, json
expected = hashlib.sha256(b"onyx-audit-trail-genesis-v1").hexdigest()
for line in open("trail.jsonl", "rb").read().splitlines():
    assert json.loads(line)["chain"] == expected, "chain broken"
    expected = hashlib.sha256(line).hexdigest()
print("verified; head:", expected)
```

Records may carry **additive keys the rule never reads** — `engine` (the writing
Onyx build's product version, stamped since Onyx 0.3.0) and, inside an embedded
certificate, `format` and `producer` (also since 0.3.0). The chain hashes the
whole line, so they are protected without being trusted, and this verifier
ignores keys it does not read. The construction it implements is exactly the
`onyx-audit-trail-genesis-v1` tag above; a future construction would be a new
tag, never a silent reinterpretation.

## Scope, honestly

- **The chain detects edits, deletions, and reordering within the file** — it
  cannot detect truncation of the tail or deletion of the whole file. That is
  what anchoring the chain head *outside* the file is for, and filing it into
  Drata is exactly such an anchor.
- **Chain integrity ≠ decision correctness.** The chain proves these are the
  decisions the gateway made; the *certificates* embedded in records address
  correctness against the policy in force, and this tool only counts them —
  they re-check with the engine's kernel (`eg_verify --audit-log`), which the
  filed report points the auditor at.
- Certificates are kernel-re-checkable records of the policy reasoning — not
  digital signatures.
- The Drata client covers the two evidence endpoints this bridge needs (per
  Drata's published API v2 spec), nothing more.

## Getting the gateway

This bridge, the chain rule, and the test suite (which runs against real
committed trails and a scripted Drata stub) are Apache-2.0 and engine-free.
The gateway that *writes* the trails (`eg_gateway`) and the certificate
checker (`eg_verify`) are part of the **Onyx engine** — a verification-first
policy engine whose decision calculus is machine-checked in two independent
proof assistants — currently in design-partner preview.

Standing up AI-agent governance evidence for SOC 2 / ISO / your framework?
**contact@onyxfoundry.ai** · [onyxfoundry.ai](https://onyxfoundry.ai)

## License

[Apache-2.0](LICENSE). Drata is a trademark of Drata Inc.; this is an
independent integration, not affiliated with or endorsed by Drata.
