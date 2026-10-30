"""all: sequential composition of gen->seed->run over a target list (KTD16).

Each target gets its own detached worktree and record dir; the
coordinator is the sole writer of the aggregate summary.json. --jobs
bounds parallel selectors (serialized on the nobody rung, which shares
a uid); resource replays serialize. --cap-mb caps the out-dir tree.
"""

from __future__ import annotations

import json
import os
import shutil
import sys
import time
from pathlib import Path

from . import cli, config, records
from .cli import EXIT_ENV, EXIT_OK, EXIT_PARTIAL, Stopped
from .scope import parse_scope


def _dir_mb(path: Path) -> int:
    total = 0
    for p in path.rglob("*"):
        if p.is_file():
            total += p.stat().st_size
    return total >> 20


def _targets_from(args) -> list:
    if args.from_scope:
        res = parse_scope(args.from_scope)
        for s in res.skipped:
            sys.stderr.write(f"fuzzgen: scope skip: {s}\n")
        return res.targets
    from .scope import ScopeTarget

    return [ScopeTarget(t) for t in args.targets]


def run(args) -> int:
    targets = _targets_from(args)
    if not targets:
        raise Stopped("no targets (empty list and no --from-scope)")
    out_root = Path(args.out_dir).resolve() if args.out_dir else config.default_out_dir()
    run_id = os.environ.get("FUZZGEN_RUN_ID") or f"all-{int(time.time())}"
    rows: list[dict] = []
    cap_mb = getattr(args, "cap_mb", None)
    produced_results = False
    interrupted = False

    for t in targets:
        if cap_mb is not None and _dir_mb(out_root) >= cap_mb:
            rows.append(records.target_row(t.selector, "DISK-CAP",
                                           notes="out-dir cap reached"))
            produced_results = True
            continue
        argv = [
            "run", "--repo", args.repo, "--out-dir", str(out_root),
            "--seconds", str(getattr(args, "seconds", 60)),
            "--jobs", str(getattr(args, "jobs", 1)),
        ]
        for opt in ("lang", "mode", "max_len", "rss_limit_mb", "reach_by"):
            val = getattr(args, opt, None)
            if val is not None:
                argv += [f"--{opt.replace('_', '-')}", str(val)]
        if t.entry and not getattr(args, "reach_by", None):
            argv += ["--reach-by", t.entry]
        argv.append(t.selector)
        os.environ["FUZZGEN_RUN_ID"] = run_id
        rc = cli.run(argv)
        produced_results = True
        # Re-read the target's summary row written by run.
        summary = None
        for p in sorted(out_root.rglob("summary.json"), key=lambda p: p.stat().st_mtime):
            try:
                doc = json.loads(p.read_text())
            except json.JSONDecodeError:
                continue
            for row in doc.get("targets", []):
                if row.get("target") == t.selector:
                    summary = row
        rows.append(summary or records.target_row(t.selector, "RUN-FAIL"))

    aggregate = records.summary_doc(
        run_id, str(Path(args.repo).resolve()),
        "", rows,
    )
    records.write_json(out_root / "summary.json", aggregate)
    records.atomic_write(out_root / "summary.md", records.summary_md(aggregate))

    statuses = {r["status"] for r in rows}
    sys.stderr.write(
        f"fuzzgen: all: {len(rows)} targets, statuses {sorted(statuses)}\n"
    )
    if not produced_results:
        return EXIT_ENV
    return EXIT_OK if statuses <= {"OK"} else EXIT_PARTIAL
