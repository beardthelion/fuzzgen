import json
import sys
from pathlib import Path

import pytest

from fuzzgen import records, resource


def test_getrusage_ladder_measures(tmp_path):
    m = resource._getrusage_measure(
        [sys.executable, "-c", "x=b'0'*10_000_000"], tmp_path, {}, None
    )
    assert m.peak_rss_kb and m.peak_rss_kb > 9000
    assert m.source == "getrusage"
    assert m.wall_ms >= 0


def test_alloc_attempt_extraction():
    n, src = resource.extract_alloc_attempt(
        "runtime error: makeslice: len 1073741824 out of range"
    )
    assert n == 1073741824 and src == "go-runtime"
    n, _ = resource.extract_alloc_attempt(
        "libFuzzer: memory allocation of 4096 bytes failed"
    )
    assert n == 4096


def test_resource_record_shape(tmp_path):
    m = resource.Measure(2048, 10, False, "getrusage", 0)
    d = resource.write_resource_record(
        tmp_path, "r1", dict(target="t", lang="go"), m, "HTTP", b"\x01\x02"
    )
    rec = json.loads((d / "run.json").read_text())
    assert rec["peak_rss_kb"] == 2048
    assert rec["reach_by"].startswith("REACH_BY:")
    assert "RATIO:" in rec["ratio"]
    assert not rec["incomplete"]


def test_capped_marks_incomplete(tmp_path):
    m = resource.Measure(None, 10, True, "cgroup", 137)
    d = resource.write_resource_record(
        tmp_path, "r2", dict(target="t", lang="go"), m, None, None
    )
    rec = json.loads((d / "run.json").read_text())
    assert rec["incomplete"] and rec["incomplete_reason"] == "hit rung hard cap"
    assert rec["ratio"] is None
