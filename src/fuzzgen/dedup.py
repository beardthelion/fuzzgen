"""Crash dedup by stack_hash (KTD6, R10).

Identical inputs re-found bump hits and keep the smallest. Two distinct
bugs at the same leaf still split when the kind or innermost frames differ.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class CrashRecord:
    kind: str
    stack_hash: str
    input: bytes
    min_input: bytes
    stack: str
    hits: int = 1
    repro_verified: bool = False
    min_broke: bool = False
    input_path: Path | None = None


class Deduper:
    def __init__(self) -> None:
        self.records: dict[str, CrashRecord] = {}

    def add(self, kind: str, shash: str, data: bytes, stack: str) -> CrashRecord:
        rec = self.records.get(shash)
        if rec is None:
            rec = CrashRecord(kind, shash, data, data, stack)
            self.records[shash] = rec
            return rec
        rec.hits += 1
        if len(data) < len(rec.min_input):
            rec.min_input = data
            rec.stack = stack
        return rec

    def __len__(self) -> int:
        return len(self.records)


def write_crash_record(out: Path, rec: CrashRecord, run_fields: dict) -> Path:
    """Write crashes/<hash>/ with input.bin, min.bin, stack.txt, run.json."""
    from . import records as _records

    d = _records.confined(out, "crashes", rec.stack_hash)
    d.mkdir(parents=True, exist_ok=True)
    (d / "input.bin").write_bytes(rec.input)
    (d / "min.bin").write_bytes(rec.min_input)
    (d / "stack.txt").write_text(_records.bound_stack(rec.stack))
    run_fields = dict(
        run_fields,
        kind=rec.kind,
        stack_hash=rec.stack_hash,
        hits=rec.hits,
        input_bytes=len(rec.input),
        min_bytes=len(rec.min_input),
        stack_top=rec.stack.splitlines()[0] if rec.stack else "",
        repro_verified=rec.repro_verified,
        min_broke=rec.min_broke,
    )
    # repro is the record dir itself — the portable replay target.
    run_fields["repro"] = f"fuzzgen replay {d}"
    _records.write_json(d / "run.json", _records.run_record(**run_fields))
    return d
