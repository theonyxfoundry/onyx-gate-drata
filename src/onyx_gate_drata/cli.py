"""The ``onyx-gate-drata`` command.

``verify`` — re-check a trail's hash chain offline (no Drata, no engine).
``file``  — verify, then package and file the trail + verification report as
Drata Evidence (fail-closed: a trail that does not verify is never filed).
"""

from __future__ import annotations

import argparse
import datetime
import json
import os
import sys
from pathlib import Path
from typing import Optional

from .drata import DrataClient, DrataError
from .report import build_markdown
from .trail import TrailReport, verify_trail

EXIT_OK = 0
EXIT_VERIFY_FAILED = 1
EXIT_USAGE = 2


def _print_report(report: TrailReport, require_chained: bool, as_json: bool) -> None:
    if as_json:
        print(
            json.dumps(
                {
                    "trail": report.name,
                    "ok": report.ok(require_chained=require_chained),
                    "counts": report.counts,
                    "chain_head": report.chain_head,
                    "records": [
                        {k: v for k, v in vars(r).items() if v not in (None, False)}
                        for r in report.records
                    ],
                },
                indent=2,
            )
        )
        return
    print(f"trail: {report.name}")
    print(report.summary_line())
    for r in report.records:
        if r.detail:
            print(f"  record {r.index}: {r.status} — {r.detail}")
    print(f"chain head: {report.chain_head}")
    print("chain: VERIFIED" if report.ok(require_chained=require_chained) else "chain: FAILED")


def cmd_verify(args: argparse.Namespace) -> int:
    report = verify_trail(args.trail)
    _print_report(report, args.require_chained, args.json)
    return EXIT_OK if report.ok(require_chained=args.require_chained) else EXIT_VERIFY_FAILED


def _read_api_key(args: argparse.Namespace) -> Optional[str]:
    if args.api_key_file:
        try:
            return open(args.api_key_file, encoding="utf-8").read().strip()
        except OSError as e:
            print(f"cannot read --api-key-file: {e}", file=sys.stderr)
            return None
    return os.environ.get("DRATA_API_KEY")


def cmd_file(args: argparse.Namespace) -> int:
    trail_path = Path(args.trail)
    report = verify_trail(str(trail_path))
    require_chained = not args.allow_unchained
    if not report.ok(require_chained=require_chained):
        # Fail-closed: evidence about integrity must itself verify. Never file
        # a broken trail — surface the failure instead.
        _print_report(report, require_chained, as_json=False)
        print("\nREFUSED: this trail does not verify; nothing was filed.", file=sys.stderr)
        return EXIT_VERIFY_FAILED

    stem = trail_path.stem.replace(".trail", "") or "onyx"
    trail_artifact_name = f"{stem}.trail.log"  # .log: an accepted upload type; bytes verbatim
    report_artifact_name = f"{stem}.verification.md"
    generated_at = (
        datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0).isoformat()
    )
    markdown = build_markdown(report, trail_artifact_name, generated_at, require_chained)
    name = args.name or f"Onyx decision trail — {stem}"
    description = (
        f"Hash-chained Onyx authorization decision trail ({report.summary_line()}). "
        f"Chain head {report.chain_head}. Attached: the verbatim trail and the "
        "verification report with independent re-check instructions."
    )
    filed_at = datetime.date.today().isoformat()

    if args.dry_run:
        out_dir = Path(args.out_dir or ".")
        out_dir.mkdir(parents=True, exist_ok=True)
        (out_dir / trail_artifact_name).write_bytes(trail_path.read_bytes())
        (out_dir / report_artifact_name).write_text(markdown, encoding="utf-8")
        print(f"dry run — evidence bundle written to {out_dir}/")
        print(f"  would upload: {trail_artifact_name}, {report_artifact_name}")
        print(f"  would create evidence {name!r} in workspace {args.workspace_id}", end="")
        print(f" linked to controls {args.control_ids}" if args.control_ids else "")
        return EXIT_OK

    api_key = _read_api_key(args)
    if not api_key:
        print(
            "no API key: set DRATA_API_KEY or pass --api-key-file (or use --dry-run)",
            file=sys.stderr,
        )
        return EXIT_USAGE

    try:
        client = DrataClient(api_key, region=args.region)
        trail_key = client.upload_evidence_file(
            args.workspace_id, trail_artifact_name, trail_path.read_bytes(), "text/plain"
        )
        report_key = client.upload_evidence_file(
            args.workspace_id, report_artifact_name, markdown.encode("utf-8"), "text/markdown"
        )
        artifacts = [
            {
                "type": "S3_FILE",
                "artifactName": report_artifact_name,
                "fileKey": report_key,
                "filedAt": filed_at,
            },
            {
                "type": "S3_FILE",
                "artifactName": trail_artifact_name,
                "fileKey": trail_key,
                "filedAt": filed_at,
            },
        ]
        created = client.create_evidence(
            args.workspace_id, name, description, artifacts, args.control_ids
        )
    except DrataError as e:
        print(f"Drata filing failed: {e}", file=sys.stderr)
        return EXIT_USAGE

    evidence_id = created.get("id", "?")
    print(f"filed: evidence {evidence_id} in workspace {args.workspace_id} ({name!r})")
    if args.control_ids:
        print(f"linked controls: {args.control_ids}")
    print(f"chain head anchored in the evidence description: {report.chain_head}")
    return EXIT_OK


def _control_ids(value: str) -> list[int]:
    try:
        return [int(x) for x in value.split(",") if x.strip()]
    except ValueError:
        raise argparse.ArgumentTypeError("control ids must be comma-separated integers")


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="onyx-gate-drata",
        description="Verify an Onyx decision trail and file it as Drata Evidence",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    v = sub.add_parser("verify", help="re-check a trail's hash chain offline")
    v.add_argument("trail")
    v.add_argument(
        "--require-chained",
        action="store_true",
        help="also refuse legacy records written before chaining existed",
    )
    v.add_argument("--json", action="store_true", help="machine-readable report")
    v.set_defaults(func=cmd_verify)

    f = sub.add_parser("file", help="verify, then file the trail as Drata Evidence")
    f.add_argument("trail")
    f.add_argument("--workspace-id", type=int, required=True, help="Drata workspace id")
    f.add_argument(
        "--control-ids",
        type=_control_ids,
        default=None,
        help="comma-separated Drata control ids to link (e.g. 17,42)",
    )
    f.add_argument("--name", help="evidence name (default derived from the trail file)")
    f.add_argument("--region", choices=["us", "eu", "apac"], default="us")
    f.add_argument(
        "--api-key-file",
        help="file holding the Drata API key (falls back to env DRATA_API_KEY); "
        "needs only the evidence write scope",
    )
    f.add_argument(
        "--allow-unchained",
        action="store_true",
        help="file a trail containing pre-chaining legacy records (reported as such)",
    )
    f.add_argument(
        "--dry-run",
        action="store_true",
        help="verify and write the evidence bundle locally; no network calls",
    )
    f.add_argument("--out-dir", help="where --dry-run writes the bundle (default .)")
    f.set_defaults(func=cmd_file)

    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except FileNotFoundError as e:
        print(f"cannot read trail: {e}", file=sys.stderr)
        return EXIT_USAGE


if __name__ == "__main__":
    raise SystemExit(main())
