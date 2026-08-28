"""Render a trail verification as a Markdown evidence report.

The report is what lands in the compliance platform beside the raw trail: what
was decided, whether the chain verifies, the chain head to anchor, and exactly
how an auditor re-checks everything independently — including the engine-side
certificate re-check this tool deliberately does not perform.
"""

from __future__ import annotations

from .trail import BROKEN, MALFORMED, UNCHAINED, TrailReport

_MAX_DENIES_LISTED = 25
_MAX_REASON = 300


def build_markdown(
    report: TrailReport,
    trail_filename: str,
    generated_at: str,
    require_chained: bool = True,
) -> str:
    """The evidence report. ``generated_at`` is an ISO-8601 UTC timestamp
    supplied by the caller (this module computes nothing time-dependent)."""
    c = report.counts
    ok = report.ok(require_chained=require_chained)
    verdict = "VERIFIED — chain intact" if ok else "FAILED — do not rely on this trail"

    lines = [
        "# Onyx decision-trail verification report",
        "",
        f"- **Trail file:** `{trail_filename}` (attached verbatim; the `.log` extension is a rename for upload — the bytes are the original JSONL)",
        f"- **Generated:** {generated_at}",
        f"- **Verification:** {verdict}",
        f"- **Chain head (anchor this value):** `{report.chain_head}`",
        "",
        "## What this trail is",
        "",
        "Each line is one authorization decision made by an Onyx gateway for an",
        "agent tool call — the full call arguments, the allow/deny verdict, the",
        "policy version in force, and (where requested) a machine-checkable",
        "certificate of the decision. The trail is hash-chained: every record",
        "carries the SHA-256 of the previous line, so any edit, deletion, or",
        "reordering of past records breaks the chain visibly.",
        "",
        "## Summary",
        "",
        f"| total records | allow | deny | with certificate | linked | unchained | broken | malformed |",
        f"| --- | --- | --- | --- | --- | --- | --- | --- |",
        f"| {len(report.records)} | {c['allow']} | {c['deny']} | {c['certificates']} | {c['linked']} | {c[UNCHAINED]} | {c[BROKEN]} | {c[MALFORMED]} |",
        "",
    ]

    denies = [r for r in report.records if r.decision == "deny"]
    if denies:
        lines += ["## Denied calls", ""]
        for r in denies[:_MAX_DENIES_LISTED]:
            reason = (r.explanation or "no explanation recorded").strip()
            if len(reason) > _MAX_REASON:
                reason = reason[:_MAX_REASON] + "…"
            lines.append(f"- record {r.index} (`{r.tool}`): {reason}")
        if len(denies) > _MAX_DENIES_LISTED:
            lines.append(f"- … and {len(denies) - _MAX_DENIES_LISTED} more (see the attached trail)")
        lines.append("")

    problems = [r for r in report.records if r.status in (BROKEN, MALFORMED)]
    if problems:
        lines += ["## Integrity failures", ""]
        for r in problems:
            lines.append(f"- record {r.index}: **{r.status}** — {r.detail}")
        lines.append("")

    lines += [
        "## How to re-verify independently",
        "",
        "Chain integrity (no vendor tooling — ~15 lines of any language, or this",
        "package's verifier):",
        "",
        "```bash",
        "pip install onyx-gate-drata",
        f"onyx-gate-drata verify {trail_filename}",
        "```",
        "",
        "The rule: the first record's `chain` field must equal",
        '`SHA256("onyx-audit-trail-genesis-v1")` (hex); each later record\'s',
        "`chain` must equal the SHA-256 of the previous line's exact bytes.",
        "",
        "Decision certificates (re-derived by the engine's proof kernel — this",
        "report only counts them):",
        "",
        "```bash",
        f"eg_verify --audit-log {trail_filename}",
        "```",
        "",
        "## Honest limits",
        "",
        "- The chain detects edits, deletions, and reordering **within** the",
        "  file. It cannot detect truncation of the tail or deletion of the",
        "  whole file — that is what anchoring the chain head above is for:",
        "  a future trail claiming to extend this one must chain from this head.",
        "- Chain verification attests integrity, not policy quality: it proves",
        "  these decisions are the ones the gateway made, not that the policy",
        "  was the right policy. The certificates address the decisions'",
        "  correctness against the policy in force.",
    ]
    return "\n".join(lines) + "\n"
