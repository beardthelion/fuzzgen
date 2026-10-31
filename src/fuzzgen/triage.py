"""triage: re-dedup crash records, rebuild summaries, a true fixed point.

Each crashes/<hash>/ dir is re-hashed from its stack.txt; records that
collapse under the current rules merge (hits summed, smallest input
kept); dirs whose hash changed move. Summary rows get rebuilt crash
counts. Running triage twice produces byte-identical trees.
"""

from __future__ import annotations

import json
import shutil
import sys
from pathlib import Path

from . import records, stackhash
from .cli import EXIT_OK, EXIT_PARTIAL, Stopped


def _rehash_record(rec: dict, stack_text: str) -> str:
    lang = rec.get("lang", "go")
    kind = stackhash.classify_kind(lang, stack_text)
    fn = stackhash.STACK_FNS.get(lang, stackhash.go_stack)
    frames = fn(stack_text)
    return stackhash.stack_hash(kind, frames, stack_text)


def _dedup_tree(target_dir: Path) -> tuple[int, int]:
    """Merge crashes/<hash>/ dirs under target_dir; returns (records, merged)."""
    crashes_root = target_dir / "crashes"
    if not crashes_root.is_dir():
        return 0, 0
    by_hash: dict[str, list[Path]] = {}
    for d in sorted(crashes_root.iterdir()):
        if not d.is_dir():
            continue
        rj = d / "run.json"
        if not rj.is_file():
            continue
        try:
            rec = json.loads(rj.read_text())
        except json.JSONDecodeError:
            continue
        stack = (d / "stack.txt").read_text(errors="replace") if (d / "stack.txt").is_file() else ""
        by_hash.setdefault(_rehash_record(rec, stack), []).append(d)
    merged = 0
    for shash, dirs in by_hash.items():
        if len(dirs) == 1 and dirs[0].name == shash:
            continue
        keep = min(dirs, key=lambda d: (d / "min.bin").stat().st_size
                   if (d / "min.bin").is_file() else 1 << 30)
        hits = 0
        for d in dirs:
            try:
                hits += int(json.loads((d / "run.json").read_text()).get("hits", 1))
            except (json.JSONDecodeError, OSError, TypeError):
                hits += 1
        dst = crashes_root / shash
        if keep != dst:
            if dst.exists():
                merged += 1
                dst = crashes_root / (shash + "-merged")
            keep.rename(dst)
        for d in dirs:
            if d != keep and d.exists():
                shutil.rmtree(d, ignore_errors=True)
                merged += 1
        try:
            rec = json.loads((dst / "run.json").read_text())
            rec["hits"] = hits
            records.write_json(dst / "run.json", rec)
        except (json.JSONDecodeError, OSError):
            pass
    return len(by_hash), merged


def run(args) -> int:
    root = Path(args.out_dir).resolve()
    if not root.is_dir():
        raise Stopped(f"{root} is not a directory")
    corrupt = 0
    rewritten = 0
    total_records = 0
    total_merged = 0
    for summary in sorted(root.rglob("summary.json")):
        try:
            doc = json.loads(summary.read_text())
        except json.JSONDecodeError:
            corrupt += 1
            continue
        target_dir = summary.parent
        n, merged = _dedup_tree(target_dir)
        total_records += n
        total_merged += merged
        for row in doc.get("targets", []):
            if n:
                row["crashes"] = n
        records.write_json(summary, doc)
        records.atomic_write(
            summary.with_name("summary.md"), records.summary_md(doc)
        )
        rewritten += 1
    sys.stderr.write(
        f"fuzzgen: triage: {rewritten} summaries rebuilt, {total_records} "
        f"records ({total_merged} merged), {corrupt} corrupt\n"
    )
    if corrupt:
        return EXIT_PARTIAL
    return EXIT_OK if rewritten else EXIT_PARTIAL
