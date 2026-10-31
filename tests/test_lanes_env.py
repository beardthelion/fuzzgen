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


def test_pkg_name_of_never_falls_back(tmp_path):
    """pkg_name_of returns a real name or None, never a silent 'main'."""
    import shutil
    from fuzzgen.lanes import go as golane

    repo = tmp_path / "r"
    shutil.copytree(FIXTURES / "go" / "basic", repo)
    pkg_dir = repo / "codec"
    name = golane.pkg_name_of(repo, pkg_dir)
    assert name == "codec"
    empty = repo / "empty"
    empty.mkdir()
    assert golane.pkg_name_of(repo, empty) is None


def test_c_lane_clang_build_and_run(tmp_path):
    """Build+run through the lane's own gen/build/run_argv path."""
    import shutil
    import pytest

    if not clane.clang_available():
        pytest.skip("clang absent")
    repo = tmp_path / "r"
    shutil.copytree(FIXTURES / "c", repo)
    work_dir = tmp_path / "wd"
    work_dir.mkdir()
    sel = parse_selector("parser.c:parse")
    gen = clane.gen_harness(sel, repo)
    assert gen.status == "OK"
    res = clane.build(repo, gen, sel, work_dir, "none")
    assert res.status == "OK", res.reason
    corpus = tmp_path / "corpus"
    stage = tmp_path / "stage"
    corpus.mkdir(); stage.mkdir()
    from fuzzgen import runner
    argv = clane.run_argv(res.binary, corpus, stage, seconds=5, jobs=1)
    proc = runner.run_bounded(argv, timeout=60, cwd=repo)
    assert proc.returncode in (0, 1, 77)


def test_rust_manifest_append_preserves_existing(tmp_path):
    """gen_harness appends only a [[bin]] entry to an existing manifest."""
    from fuzzgen.lanes import rust as rustlane
    from fuzzgen.probe import ProbeResult

    crate = tmp_path / "krate"
    (crate / "fuzz" / "fuzz_targets").mkdir(parents=True)
    (crate / "Cargo.toml").write_text(
        '[package]\nname = "krate"\nversion = "0.1.0"\n'
    )
    existing = (
        '[package]\nname = "krate-fuzz"\nversion = "0.0.0"\n'
        "[package.metadata]\ncargo-fuzz = true\n"
        "[dependencies]\nlibfuzzer-sys = \"0.4\"\nkrate = { path = \"..\" }\n"
        '\n[[bin]]\nname = "old_target"\npath = "fuzz_targets/old_target.rs"\n'
    )
    (crate / "fuzz" / "Cargo.toml").write_text(existing)
    sel = parse_selector("krate::decode", "rust")
    res = rustlane.gen_harness(sel, ProbeResult("OK", kind="bytes"), tmp_path)
    assert res.status == "OK"
    text = (crate / "fuzz" / "Cargo.toml").read_text()
    assert existing.rstrip() in text
    assert 'name = "old_target"' in text
    assert 'name = "fuzzgen_decode"' in text
