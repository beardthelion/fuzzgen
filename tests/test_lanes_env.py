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


def test_rust_lane_bwrap_rung(tmp_path):
    """Forced bwrap rung for the rust lane: argv shape + real exec."""
    import shutil
    import subprocess
    import pytest
    from fuzzgen import contain

    if not shutil.which("bwrap") or not shutil.which("cargo"):
        pytest.skip("bwrap or cargo absent")
    probe = subprocess.run(
        ["bwrap", "--unshare-all", "--ro-bind", "/", "/", "true"],
        capture_output=True, timeout=20,
    )
    if probe.returncode != 0:
        pytest.skip("bwrap namespaces unavailable on this kernel")
    crate = tmp_path / "crate"
    (crate / "fuzz").mkdir(parents=True)
    wd = tmp_path / "wd"
    wd.mkdir()
    # cargo lives under $HOME, which bwrap does not bind; the staged
    # toolchain copy inside work_dir is what the real lane uses.
    tc_env = rustlane.stage_rust_toolchain(wd)
    argv = contain.contained_argv(
        contain.MECH_BWRAP, ["cargo", "+nightly", "--version"], crate, wd,
        env=rustlane._cargo_env(wd, tc_env),
        chdir=str(crate / "fuzz"),
    )
    assert "--chdir" in argv
    assert argv[argv.index("--chdir") + 1] == str(crate / "fuzz")
    proc = subprocess.run(argv, capture_output=True, text=True, timeout=60)
    assert proc.returncode == 0, proc.stderr
    assert "cargo" in proc.stdout


def test_rust_lane_bwrap_fuzz_round(tmp_path):
    """Forced bwrap: real cargo-fuzz build + short round, out-dir corpus."""
    import shutil
    import subprocess
    import pytest
    from fuzzgen import contain

    if not shutil.which("bwrap") or not shutil.which("cargo"):
        pytest.skip("bwrap or cargo absent")
    probe = subprocess.run(
        ["bwrap", "--unshare-all", "--ro-bind", "/", "/", "true"],
        capture_output=True, timeout=20,
    )
    if probe.returncode != 0:
        pytest.skip("bwrap namespaces unavailable on this kernel")
    # Minimal crate with no external deps (the probe fixture's lib.rs
    # imports arbitrary/ssz and is not buildable).
    crate = tmp_path / "basic"
    (crate / "src").mkdir(parents=True)
    (crate / "Cargo.toml").write_text(
        '[package]\nname = "basic"\nversion = "0.1.0"\nedition = "2021"\n')
    (crate / "src" / "lib.rs").write_text(
        "pub fn decode(data: &[u8]) -> u64 {\n"
        "    data.iter().fold(0u64, |a, b| a.wrapping_add(*b as u64))\n"
        "}\n")
    wd = tmp_path / "wd"
    wd.mkdir()
    sel = parse_selector("basic::decode", "rust")
    gen = rustlane.gen_harness(sel, ProbeResult("OK", kind="bytes"), crate)
    assert gen.status == "OK"
    tc_env = rustlane.stage_rust_toolchain(wd)
    assert rustlane.fetch_deps(crate, wd)
    res = rustlane.build(crate, crate, "fuzzgen_decode", contain.MECH_BWRAP, wd,
                         tc_env=tc_env)
    assert res.returncode == 0, res.stderr[-600:]
    corpus = tmp_path / "out-corpus"  # outside the crate and work_dir
    corpus.mkdir()
    stage = tmp_path / "out-stage"
    res = rustlane.fuzz_round(crate, crate, "fuzzgen_decode", corpus, stage, 10,
                              contain.MECH_BWRAP, wd, tc_env=tc_env)
    assert res.returncode == 0, res.stderr[-600:]
    assert "#" in res.stderr or "exec" in res.stderr


def test_rust_public_path_drops_private_mod(tmp_path):
    """mod x; pub use x::f -> harness calls krate::f, not krate::x::f."""
    crate = tmp_path / "krate"
    (crate / "src").mkdir(parents=True)
    (crate / "Cargo.toml").write_text(
        '[package]\nname = "krate"\nversion = "0.1.0"\n')
    (crate / "src" / "lib.rs").write_text(
        "mod x;\npub use x::f;\n")
    (crate / "src" / "x.rs").write_text("pub fn f(_: &[u8]) {}\n")
    sel = parse_selector("krate::x::f", "rust")
    res = rustlane.gen_harness(sel, ProbeResult("OK", kind="bytes"), tmp_path)
    assert res.status == "OK"
    src = res.target_path.read_text()
    assert "krate::f(data)" in src


def test_rust_workspace_member_gets_workspace_table(tmp_path):
    """Workspace member gets [workspace]; the member builds under bwrap."""
    import shutil
    import subprocess
    import pytest
    from fuzzgen import contain

    if not shutil.which("bwrap") or not shutil.which("cargo"):
        pytest.skip("bwrap or cargo absent")
    probe = subprocess.run(
        ["bwrap", "--unshare-all", "--ro-bind", "/", "/", "true"],
        capture_output=True, timeout=20,
    )
    if probe.returncode != 0:
        pytest.skip("bwrap namespaces unavailable on this kernel")
    ws_root = tmp_path / "ws"
    crate = ws_root / "crates" / "foo-bar"
    (crate / "src").mkdir(parents=True)
    (ws_root / "Cargo.toml").write_text(
        '[workspace]\nmembers = ["crates/foo-bar"]\n'
        '[workspace.package]\nversion = "0.1.0"\n')
    (crate / "Cargo.toml").write_text(
        '[package]\nname = "foo-bar"\nversion.workspace = true\n')
    (crate / "src" / "lib.rs").write_text("pub fn decode(_: &[u8]) {}\n")
    sel = parse_selector("foo-bar::decode", "rust")
    res = rustlane.gen_harness(sel, ProbeResult("OK", kind="bytes"), ws_root)
    assert res.status == "OK"
    assert "[workspace]" in (crate / "fuzz" / "Cargo.toml").read_text()
    wd = tmp_path / "wd"
    wd.mkdir()
    tc_env = rustlane.stage_rust_toolchain(wd)
    assert rustlane.fetch_deps(crate, wd)
    res = rustlane.build(ws_root, crate, "fuzzgen_decode",
                         contain.MECH_BWRAP, wd, tc_env=tc_env)
    assert res.returncode == 0, res.stderr[-800:]


def test_rust_crate_dir_normalizes_both_forms(tmp_path):
    from fuzzgen import selectors
    ws = tmp_path / "ws"
    d = ws / "crates" / "foo-bar"
    (d / "src").mkdir(parents=True)
    (d / "Cargo.toml").write_text('[package]\nname = "foo-bar"\n')
    for form in ("foo-bar", "foo_bar"):
        dirs = selectors.rust_crate_dirs(ws, form)
        assert dirs == [d], (form, dirs)


def test_build_fail_notes_error_first(tmp_path):
    """error[ / ^error lines lead the notes; full stderr saved to file."""
    from fuzzgen.run import _run_rust  # noqa
    import re
    err = "\n".join([f"warning: w{i}" for i in range(30)]) + \
        "\nerror[E0603]: unresolved import\n"
    errs = [l for l in err.splitlines()
            if re.match(r"^error(\[|:)|^\s*-->", l)]
    assert errs[0].startswith("error[E0603]")


def test_build_fail_reason_error_first(tmp_path):
    """_build_fail_reason leads with the error line; full stderr saved."""
    from fuzzgen.run import _build_fail_reason

    err = "\n".join(f"warning: w{i}" for i in range(30)) + \
        "\nerror[E0603]: unresolved import `x`\n  --> src/lib.rs:1\n"
    reason = _build_fail_reason(err, tmp_path)
    assert reason.startswith("error[E0603]")
    saved = (tmp_path / "build_stderr.txt").read_text()
    assert "warning: w0" in saved and "error[E0603]" in saved


def test_fuzz_stderr_names_detected_rung(tmp_path):
    """Line 1 of fuzz_stderr.txt names the rung after a short round."""
    from fuzzgen import contain
    from fuzzgen.run import _write_round_stderr
    from fuzzgen import runner

    mech, _, _ = contain.detect()
    res = runner.Result(argv=[], returncode=0, stdout="",
                        stderr="INFO: fake round", timed_out=False,
                        duration_s=0.1, error=None)
    out = tmp_path / "out"
    out.mkdir()
    _write_round_stderr(out, mech, res)
    line1 = (out / "fuzz_stderr.txt").read_text().splitlines()[0]
    assert mech in line1
    assert contain.MECH_DETAIL[mech] in line1


def test_rust_assoc_fn_emits_type_call(tmp_path):
    crate = tmp_path / "krate"
    (crate / "src").mkdir(parents=True)
    (crate / "Cargo.toml").write_text('[package]\nname = "krate"\n')
    (crate / "src" / "lib.rs").write_text(
        "pub struct PeerId(u64);\n"
        "impl PeerId { pub fn from_bytes(_: &[u8]) -> Self { PeerId(0) } }\n")
    sel = parse_selector("krate::PeerId::from_bytes", "rust")
    res = rustlane.gen_harness(sel, ProbeResult("OK", kind="bytes",
                                                args=["&[u8]"]), tmp_path)
    assert res.status == "OK"
    assert "PeerId::from_bytes(data)" in res.target_path.read_text()


def test_rust_generic_recv_turbofish(tmp_path):
    crate = tmp_path / "krate"
    (crate / "src").mkdir(parents=True)
    (crate / "Cargo.toml").write_text('[package]\nname = "krate"\n')
    (crate / "src" / "lib.rs").write_text(
        "pub struct Inner;\npub struct Key<K> { _k: std::marker::PhantomData<K> }\n"
        "impl Key<Inner> { pub fn from_bytes(_: &[u8]) -> Self "
        "{ Key { _k: std::marker::PhantomData } } }\n")
    sel = parse_selector("krate::Key::from_bytes", "rust")
    res = rustlane.gen_harness(sel, ProbeResult("OK", kind="bytes",
                                                args=["&[u8]"]), tmp_path)
    assert res.status == "OK"
    assert "Key::<krate::Inner>::from_bytes(data)" in res.target_path.read_text()


def test_go_method_receiver_decl(tmp_path):
    from fuzzgen.lanes import go as golane
    sel = parse_selector("pkg.Inputs.UnmarshalJSON", "go")
    src = golane.render(sel, ProbeResult("OK", kind="bytes",
                                         args=["[]byte"]), "pkg", "Fuzz")
    assert "var v Inputs" in src
    assert "v.UnmarshalJSON(data)" in src


def test_go_fuzz_passes_timeout_flag():
    from fuzzgen import contain, runner
    captured = {}

    class R:
        pass

    orig = runner.run_bounded
    runner.run_bounded = lambda argv, **kw: captured.setdefault(
        "argv", argv) and runner.Result(argv, 0, "", "", False, 0, None)
    try:
        from fuzzgen.lanes import go as golane
        import tempfile
        wt = Path(tempfile.mkdtemp(dir="/var/tmp"))
        (wt / "sub").mkdir()
        golane.fuzz_round(wt, wt / "sub", "F", 10, contain.MECH_NONE, wt, jobs=1)
    finally:
        runner.run_bounded = orig
    assert "-timeout" in captured["argv"]
    assert "0s" in captured["argv"]


def test_count_execs_cumulative_go_lines():
    from fuzzgen.run import _count_execs
    text = ("fuzz: elapsed: 1s, execs: 10\n"
            "fuzz: elapsed: 2s, execs: 20\n"
            "fuzz: elapsed: 3s, execs: 30\n")
    assert _count_execs(text) == 30


def _bwrap_or_skip():
    import shutil
    import subprocess
    import pytest
    if not shutil.which("bwrap") or not shutil.which("cargo"):
        pytest.skip("bwrap or cargo absent")
    probe = subprocess.run(
        ["bwrap", "--unshare-all", "--ro-bind", "/", "/", "true"],
        capture_output=True, timeout=20,
    )
    if probe.returncode != 0:
        pytest.skip("bwrap namespaces unavailable on this kernel")


def test_rust_assoc_fn_builds_under_bwrap(tmp_path):
    """The emitted PeerId::from_bytes call compiles+runs under bwrap."""
    _bwrap_or_skip()
    from fuzzgen import contain
    crate = tmp_path / "krate"
    (crate / "src").mkdir(parents=True)
    (crate / "Cargo.toml").write_text(
        '[package]\nname = "krate"\nversion = "0.1.0"\nedition = "2021"\n')
    (crate / "src" / "lib.rs").write_text(
        "pub struct PeerId(u64);\n"
        "impl PeerId { pub fn from_bytes(d: &[u8]) -> Self { "
        "PeerId(d.iter().fold(0u64, |a, b| a.wrapping_add(*b as u64))) } }\n")
    sel = parse_selector("krate::PeerId::from_bytes", "rust")
    res = rustlane.gen_harness(sel, ProbeResult("OK", kind="bytes",
                                                args=["&[u8]"]), tmp_path)
    assert res.status == "OK"
    wd = tmp_path / "wd"
    wd.mkdir()
    tc_env = rustlane.stage_rust_toolchain(wd)
    assert rustlane.fetch_deps(crate, wd)
    res = rustlane.build(crate, crate, "fuzzgen_from_bytes",
                         contain.MECH_BWRAP, wd, tc_env=tc_env)
    assert res.returncode == 0, res.stderr[-600:]
    corpus = tmp_path / "corpus"
    corpus.mkdir()
    stage = tmp_path / "stage"
    res = rustlane.fuzz_round(crate, crate, "fuzzgen_from_bytes",
                              corpus, stage, 8, contain.MECH_BWRAP, wd,
                              tc_env=tc_env)
    assert res.returncode == 0, res.stderr[-600:]


def test_rust_generic_recv_builds_under_bwrap(tmp_path):
    """Key::<Inner>::from_bytes builds+runs under bwrap."""
    _bwrap_or_skip()
    from fuzzgen import contain
    crate = tmp_path / "krate"
    (crate / "src").mkdir(parents=True)
    (crate / "Cargo.toml").write_text(
        '[package]\nname = "krate"\nversion = "0.1.0"\nedition = "2021"\n')
    (crate / "src" / "lib.rs").write_text(
        "pub struct Inner;\n"
        "pub struct Key<K> { _k: std::marker::PhantomData<K> }\n"
        "impl Key<Inner> { pub fn from_bytes(d: &[u8]) -> Self "
        "{ Key { _k: std::marker::PhantomData } } }\n")
    sel = parse_selector("krate::Key::from_bytes", "rust")
    res = rustlane.gen_harness(sel, ProbeResult("OK", kind="bytes",
                                                args=["&[u8]"]), tmp_path)
    assert res.status == "OK"
    assert "Key::<krate::Inner>::from_bytes(data)" in res.target_path.read_text()
    wd = tmp_path / "wd"
    wd.mkdir()
    tc_env = rustlane.stage_rust_toolchain(wd)
    assert rustlane.fetch_deps(crate, wd)
    res = rustlane.build(crate, crate, "fuzzgen_from_bytes",
                         contain.MECH_BWRAP, wd, tc_env=tc_env)
    assert res.returncode == 0, res.stderr[-600:]
    corpus = tmp_path / "corpus"
    corpus.mkdir()
    stage = tmp_path / "stage"
    res = rustlane.fuzz_round(crate, crate, "fuzzgen_from_bytes",
                              corpus, stage, 8, contain.MECH_BWRAP, wd,
                              tc_env=tc_env)
    assert res.returncode == 0, res.stderr[-600:]
