"""Onyx Gate for Drata — file verified Onyx decision trails as Drata Evidence.

* :mod:`onyx_gate_drata.trail` — pure-Python re-check of the Onyx audit
  trail's hash chain (no engine, no dependencies).
* :mod:`onyx_gate_drata.report` — the Markdown evidence report.
* :mod:`onyx_gate_drata.drata` — a minimal Drata Public API v2 client
  (evidence-files upload + evidence create).
* :mod:`onyx_gate_drata.cli` — the ``onyx-gate-drata`` command
  (``verify`` / ``file``).
"""

from .drata import DrataClient, DrataError
from .report import build_markdown
from .trail import RecordCheck, TrailReport, genesis_hash, verify_trail, verify_trail_bytes

__all__ = [
    "DrataClient",
    "DrataError",
    "RecordCheck",
    "TrailReport",
    "build_markdown",
    "genesis_hash",
    "verify_trail",
    "verify_trail_bytes",
]

__version__ = "0.1.0"
