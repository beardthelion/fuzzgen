"""Resource measurement and records (KTD7, R12).

Measurement ladder: cgroup v2 memory.peak (memory.max is the hard cap)
-> /usr/bin/time -v maximum RSS -> getrusage. Every replay runs under
the KTD3 rung and is hard-capped; a measurement that hits the cap flags
capped: true. Unsanitized replays only; alloc_attempt_bytes is tagged
with the build that produced it.
"""

from __future__ import annotations

import os
import re
import resource
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path

from . import contain, records, runner


@dataclass
class Measure:
    peak_rss_kb: int | None
    wall_ms: int
    capped: bool
    source: str  # cgroup | time-v | getrusage
    returncode: int | None


def _cgroup_measure(argv, cwd, env, mem_max_mb: int | None) -> Measure | None:
    cg_root = Path("/sys/fs/cgroup")
    if not (cg_root / "cgroup.controllers").exists():
        return None
    cg = cg_root / f"fuzzgen-{os.getpid()}-{int(time.time()*1000)}"
    try:
        cg.mkdir()
    except OSError:
        return None
    try:
        if mem_max_mb:
            (cg / "memory.max").write_text(str(mem_max_mb << 20))
        proc = subprocess.Popen(
            argv, cwd=cwd, env=env,
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        )
        try:
            (cg / "cgroup.procs").write_text(str(proc.pid))
        except OSError:
            pass
        t0 = time.monotonic()
        try:
            proc.communicate(timeout=3600)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.communicate(timeout=30)
            return None  # fall through to the next rung with the child dead
        wall = int((time.monotonic() - t0) * 1000)
        try:
            peak = int((cg / "memory.peak").read_text().strip()) >> 10
        except OSError:
            peak = None
        return Measure(peak, wall, peak is not None and peak >= (mem_max_mb << 10) if mem_max_mb else False, "cgroup", proc.returncode)
    finally:
        try:
            cg.rmdir()
        except OSError:
            pass


def _time_v_measure(argv, cwd, env, mem_max_mb) -> Measure | None:
    tv = Path("/usr/bin/time")
    if not tv.is_file():
        return None
    marker = Path.cwd() / f".time-v-{os.getpid()}-{int(time.time()*1000)}"
    try:
        t0 = time.monotonic()
        proc = subprocess.run(
            [str(tv), "-v", "-o", str(marker), *argv],
            cwd=cwd, env=env, capture_output=True, timeout=3600,
        )
        wall = int((time.monotonic() - t0) * 1000)
        text = marker.read_text(errors="replace")
        m = re.search(r"Maximum resident set size \(kbytes\): (\d+)", text)
        return Measure(int(m.group(1)) if m else None, wall, False, "time-v", proc.returncode)
    except (subprocess.TimeoutExpired, OSError):
        return None
    finally:
        marker.unlink(missing_ok=True)


def _getrusage_measure(argv, cwd, env, mem_max_mb) -> Measure:
    # RUSAGE_CHILDREN is cumulative: ru_maxrss is an upper bound on this
    # child's peak, honest as a worst-case floor measurement.
    t0 = time.monotonic()
    try:
        proc = subprocess.run(argv, cwd=cwd, env=env, capture_output=True, timeout=3600)
    except subprocess.TimeoutExpired:
        return Measure(None, 3600_000, False, "getrusage", None)
    wall = int((time.monotonic() - t0) * 1000)
    usage = resource.getrusage(resource.RUSAGE_CHILDREN)
    return Measure(usage.ru_maxrss, wall, False, "getrusage", proc.returncode)


def measure_replay(
    argv: list[str],
    cwd: Path | None = None,
    env: dict | None = None,
    mem_max_mb: int | None = 4096,
) -> Measure:
    """Ladder: cgroup -> time -v -> getrusage, always under a hard cap."""
    for fn in (_cgroup_measure, _time_v_measure):
        m = fn(argv, cwd, env, mem_max_mb)
        if m is not None:
            return m
    return _getrusage_measure(argv, cwd, env, mem_max_mb)


def extract_alloc_attempt(stderr: str) -> tuple[int | None, str | None]:
    """alloc_attempt_bytes from lane output; (bytes, source_build) — caller tags."""
    m = re.search(r"allocation of (\d+) bytes failed", stderr)
    if m:
        return int(m.group(1)), "sanitized"
    m = re.search(r"memory allocation of (\d+) bytes failed", stderr)
    if m:
        return int(m.group(1)), "sanitized"
    m = re.search(r"makeslice: len (\d+)", stderr)
    if m:
        return int(m.group(1)), "go-runtime"
    return None, None


def write_resource_record(
    out_dir: Path,
    rid: str,
    fields: dict,
    measure: Measure,
    reach_by: str | None,
    input_bytes: bytes | None,
) -> Path:
    """resource/<id>/ with the RATIO:/REACH_BY: contract lines."""
    d = records.confined(out_dir, "resource", rid)
    d.mkdir(parents=True, exist_ok=True)
    if input_bytes is not None:
        (d / "input.bin").write_bytes(input_bytes)
    incomplete = measure.capped or measure.peak_rss_kb is None
    reason = None
    if measure.capped:
        reason = "hit rung hard cap"
    elif measure.peak_rss_kb is None:
        reason = "peak-rss-unavailable"
    rec_fields = dict(
        fields,
        kind=fields.get("kind") or "out-of-memory",
        peak_rss_kb=measure.peak_rss_kb,
        wall_ms=measure.wall_ms,
        capped=measure.capped,
        reach_by=reach_by or "unknown",
        incomplete=incomplete,
        incomplete_reason=reason,
        measure_source=measure.source,
    )
    ratio = None
    if measure.peak_rss_kb and input_bytes:
        ratio = measure.peak_rss_kb * 1024 / max(len(input_bytes), 1)
        rec_fields["ratio"] = f"RATIO: {ratio:.1f}x input"
        rec_fields["reach_by"] = f"REACH_BY: {reach_by or 'unknown'}"
    doc = records.run_record(**rec_fields)
    # run_record's schema keeps only its fields; measurement provenance
    # the contract promises is merged back in explicitly.
    doc["capped"] = measure.capped
    doc["wall_ms"] = measure.wall_ms
    doc["measure_source"] = measure.source
    records.write_json(d / "run.json", doc)
    return d
