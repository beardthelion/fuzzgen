"""triage: re-dedup and rebuild summary from an existing fuzzgen-out tree."""

from __future__ import annotations

import json
import sys
from pathlib import Path

from . import records
from .cli import EXIT_OK, EXIT_PARTIAL, Stopped


def run(args) -> int:
    root = Path(args.out_dir).resolve()
    if not root.is_dir():
        raise Stopped(f"{root} is not a directory")
    rows: list[dict] = []
    crashes = 0
    for summary in sorted(root.rglob("summary.json")):
        try:
            doc = json.loads(summary.read_text())
        except json.JSONDecodeError:
            continue
        for row in doc.get("targets", []):
            rows.append(row)
            crashes += row.get("crashes", 0) or 0
    # Fixed-point: rewrite each summary.json + summary.md byte-identically.
    rewritten = 0
    for summary in sorted(root.rglob("summary.json")):
        try:
            doc = json.loads(summary.read_text())
        except json.JSONDecodeError:
            continue
        records.write_json(summary, doc)
        records.atomic_write(
            summary.with_name("summary.md"), records.summary_md(doc)
        )
        rewritten += 1
    sys.stderr.write(
        f"fuzzgen: triage: {rewritten} summaries rebuilt, {crashes} crashes, "
        f"{len(rows)} targets\n"
    )
    return EXIT_OK if rewritten else EXIT_PARTIAL
