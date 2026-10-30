"""Env-gated lane checks: gen code always runs; builds skip without toolchains."""
import shutil
from pathlib import Path

import pytest

from fuzzgen.lanes import c as clane, rust as rustlane
from fuzzgen.probe import ProbeResult
from fuzzgen.selectors import parse_selector

FIXTURES = Path(__file__).resolve().parent / "fixtures"


def test_c_gen_emits_fuzzer(tmp_path):
    repo = tmp_path / "r"
    shutil.copytree(FIXTURES / "c", repo)
    sel = parse_selector("parser.c:parse")
    res = clane.gen_harness(sel, repo)
    assert res.status == "OK"
    src = res.harness_path.read_text()
    assert "LLVMFuzzerTestOneInput" in src and "parse(data, size)" in src


def test_c_build_tool_missing_honest():
    if clane.clang_available():
        pytest.skip("clang present")
    res = clane.build(Path("/x"), clane.CGenResult("OK"), parse_selector("a.c:f"), Path("/x"), "none")
    assert res.status == "TOOL-MISSING"


def test_c_fork_argv():
    argv = clane.run_argv(Path("/b/f"), Path("/c"), Path("/s"), 60, 1)
    assert "-fork" in argv and "-ignore_crashes=1" in argv


def test_rust_gen_emits_target(tmp_path):
    repo = tmp_path / "r"
    shutil.copytree(FIXTURES / "rust" / "basic", repo)
    sel = parse_selector("basic::decode")
    res = rustlane.gen_harness(sel, ProbeResult("OK", kind="bytes"), repo)
    assert res.status == "OK"
    src = res.target_path.read_text()
    assert "fuzz_target!" in src and "basic::decode(data)" in src


def test_rust_lane_env_gate():
    ok, reason = rustlane.rust_lane_available()
    if not ok:
        assert reason  # honest TOOL-MISSING text
    argv = rustlane.run_argv("fuzzgen_decode", Path("/c"), Path("/s"), 60, 1)
    assert "-fork" in argv and "-rss_limit_mb=0" in argv
