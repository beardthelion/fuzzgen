"""promote: candidate fnd_*.json rows into <repo>/.clawpatch/findings/ (KTD11).

Schema verified against clawpatch-ledger.py's findingRecordSchema.
Writes are lockfile + tmp+rename against the shared store. Stack-derived
evidence paths are untrusted: they must resolve to a relpath inside the
target repo, else the row degrades to startLine 0 with a note.
Opt-in per run; the only write outside fuzzgen-out/ and the worktree.
"""

from __future__ import annotations

import contextlib
import fcntl
import json
import re
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from . import records
from .cli import EXIT_OK, EXIT_PARTIAL, Stopped

SCHEMA_VERSION = 1
SCHEMA_FIELDS = (
    "schemaVersion",
    "findingId",
    "featureId",
    "title",
    "category",
    "severity",
    "confidence",
    "status",
    "history",
    "signature",
    "evidence",
    "createdByRunId",
    "createdAt",
)


@contextlib.contextmanager
def _lock(findings_dir: Path):
    findings_dir.mkdir(parents=True, exist_ok=True)
    fh = open(findings_dir / ".lock", "w")
    try:
        fcntl.flock(fh, fcntl.LOCK_EX)
        yield
    finally:
        fcntl.flock(fh, fcntl.LOCK_UN)
        fh.close()


def _atomic_put(path: Path, data: str) -> None:
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".tmp-")
    with __import__("os").fdopen(fd, "w") as fh:
        fh.write(data)
    import os

    os.replace(tmp, path)


def _evidence_path(stack_text: str, repo: Path) -> tuple[str, int]:
    """First repo-relative path:line from a stack; (relpath, line) or ("", 0)."""
    for m in re.finditer(r"([\w./-]+\.[a-zA-Z]+):(\d+)", stack_text):
        cand = Path(m.group(1))
        for prefix in ("./", str(repo) + "/"):
            s = str(cand)
            if s.startswith(prefix):
                s = s[len(prefix):]
                cand = Path(s)
        try:
            resolved = (repo / cand).resolve()
            import os

            if os.path.commonpath([str(repo.resolve()), str(resolved)]) == str(
                repo.resolve()
            ) and resolved.is_file():
                return str(cand), int(m.group(2))
        except (OSError, ValueError):
            continue
    return "", 0


def _finding_for(rec: dict, record_dir: Path, repo: Path) -> dict:
    selector = rec["target"]
    shash = rec.get("stack_hash") or "nohash"
    kind = rec.get("kind") or "unknown"
    sel_slug = records.slug(selector)
    stack = ""
    if (record_dir / "stack.txt").is_file():
        stack = (record_dir / "stack.txt").read_text(errors="replace")[:8000]
    path, line = _evidence_path(stack, repo)
    notes = [] if path else ["unsymbolized or out-of-repo stack path"]
    evidence = {
        "path": path,
        "startLine": line,
        "snippet": records.bound_text(stack.splitlines()[0] if stack else "", 200),
        "note": f"fuzzgen record dir {record_dir.name}"
        + ("; " + "; ".join(notes) if notes else ""),
    }
    is_resource = record_dir.parent.name == "resource"
    severity = "medium" if is_resource and not rec.get("incomplete") else "low"
    confidence = "high" if rec.get("repro_verified") else "low"
    if rec.get("incomplete"):
        confidence = "low"
    feature = rec.get("feature_id") or f"fuzzgen-{sel_slug[:40]}"
    return {
        "schemaVersion": SCHEMA_VERSION,
        "findingId": f"fnd_fuzzgen_{sel_slug}_{shash[:8]}",
        "featureId": feature,
        "title": f"{kind} {shash[:8]} at {selector}",
        "category": "fuzz",
        "severity": severity,
        "confidence": confidence,
        "status": "open",
        "history": [
            {
                "at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                "event": "created by fuzzgen promote",
            }
        ],
        "signature": f"{kind}:{shash}",
        "evidence": evidence,
        "createdByRunId": rec.get("run_id") or "",
        "createdAt": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }


def _dedup_key(row: dict) -> tuple:
    ev = row.get("evidence") or {}
    return (
        ev.get("path", ""),
        ev.get("startLine", 0),
        row.get("category", ""),
        row.get("title", ""),
    )


def run(args) -> int:
    out_root = Path(args.out_dir).resolve()
    if not out_root.is_dir():
        raise Stopped(f"{out_root} is not a directory")
    records_files = list(out_root.rglob("run.json"))
    if not records_files:
        raise Stopped(f"no run.json records under {out_root}")

    repo_arg = args.repo
    if not repo_arg:
        try:
            repo_arg = json.loads(records_files[0].read_text()).get("repo_path")
        except json.JSONDecodeError:
            pass
    if not repo_arg:
        raise Stopped("--repo required (run.json repo_path unavailable)")
    repo = Path(repo_arg).resolve()
    findings_dir = repo / ".clawpatch" / "findings"

    written, skipped, failed = 0, 0, 0
    with _lock(findings_dir):
        existing_keys = set()
        for f in findings_dir.glob("fnd_*.json"):
            try:
                existing_keys.add(_dedup_key(json.loads(f.read_text())))
            except (json.JSONDecodeError, OSError):
                continue
        for rf in records_files:
            record_dir = rf.parent
            try:
                rec = json.loads(rf.read_text())
            except json.JSONDecodeError:
                failed += 1
                continue
            row = _finding_for(rec, record_dir, repo)
            key = _dedup_key(row)
            if key in existing_keys:
                skipped += 1
                continue
            data = json.dumps(row, indent=2, sort_keys=True)
            # Round-trip guard: every emitted row carries the full schema tuple.
            back = json.loads(data)
            if tuple(sorted(back.keys())) != tuple(sorted(SCHEMA_FIELDS)):
                failed += 1
                continue
            _atomic_put(findings_dir / f"{row['findingId']}.json", data + "\n")
            existing_keys.add(key)
            written += 1
    sys.stderr.write(
        f"fuzzgen: promote: {written} written, {skipped} dedup-skipped, "
        f"{failed} failed into {findings_dir}\n"
    )
    return EXIT_OK if written or skipped else EXIT_PARTIAL
