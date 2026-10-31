"""Historic-crash leg: sigp/lighthouse 561167fa1 ssz decode panic.

Env-gated (FUZZGEN_GATE_LIVE=1): clones lighthouse at the exact sha,
checks out the pre-fix parent, and fuzzes the real decode_length
through the lane's contained build/fuzz path under whatever rung
detect() picks. The 2018 workspace manifest is unparseable by modern
cargo, so the leg runs a standalone copy of the real ssz crate.
decode_length is a 3-arg fn; generated harnesses are single-arg only
(NEEDS-HAND), so the target file is hand-written here.
"""

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

pytestmark = [
    pytest.mark.skipif(
        os.environ.get("FUZZGEN_GATE_LIVE") != "1",
        reason="historic legs are env-gated (FUZZGEN_GATE_LIVE=1)",
    ),
    pytest.mark.skipif(shutil.which("cargo") is None, reason="cargo absent"),
]

SHA = "561167fa1ef85a34d34c8026c8ba88411431507b"
SSZ_CRATE = "beacon_chain/utils/ssz"

HARNESS = """#![no_main]
extern crate libfuzzer_sys;
extern crate ssz;
use libfuzzer_sys::fuzz_target;
use ssz::decode::decode_length;

fuzz_target!(|data: &[u8]| {
    let _ = decode_length(data, 1, 4);
});
"""

MANIFEST = """[package]
name = "ssz-fuzz"
version = "0.0.0"
edition = "2015"
publish = false

[package.metadata]
cargo-fuzz = true

[dependencies]
libfuzzer-sys = "0.4"
ssz = { path = ".." }

[[bin]]
name = "fuzz_decode_length"
path = "fuzz_targets/fuzz_decode_length.rs"
test = false
doc = false
"""


def test_lighthouse_ssz_historic(tmp_path, monkeypatch):
    repo = tmp_path / "lighthouse"
    subprocess.run(
        ["git", "clone", "-q", "--filter=blob:none", "--no-checkout",
         "https://github.com/sigp/lighthouse", str(repo)],
        check=True, capture_output=True, timeout=600,
    )
    subprocess.run(
        ["git", "-C", str(repo), "fetch", "-q", "--depth", "2", "origin", SHA],
        check=True, capture_output=True, timeout=300,
    )
    subprocess.run(
        ["git", "-C", str(repo), "checkout", "-q", f"{SHA}^"],
        check=True, capture_output=True,
    )
    # Standalone copy: the 2018 workspace manifest breaks modern cargo.
    crate = tmp_path / "ssz-historic"
    shutil.copytree(repo / SSZ_CRATE, crate)
    (crate / "fuzz" / "fuzz_targets").mkdir(parents=True)
    (crate / "fuzz" / "Cargo.toml").write_text(MANIFEST)
    (crate / "fuzz" / "fuzz_targets" / "fuzz_decode_length.rs").write_text(HARNESS)

    # Build + fuzz through the lane under the detected containment rung.
    from fuzzgen import contain, config
    from fuzzgen.lanes import rust as rustlane
    from fuzzgen.lanes import go as golane

    mechanism, denied, _ = contain.detect()
    assert mechanism != contain.MECH_REFUSE
    work_root = tmp_path / "work"
    work_root.mkdir()
    monkeypatch.setattr(config, "work_root", lambda **kw: work_root)
    work_dir = work_root / "wd"
    work_dir.mkdir()
    tc_env = rustlane.stage_rust_toolchain(work_dir)
    golane.provision_for_rung(mechanism, crate, work_dir)
    assert rustlane.fetch_deps(crate, work_dir)
    res = rustlane.build(crate, crate, "fuzz_decode_length", mechanism, work_dir,
                         tc_env=tc_env)
    assert res.returncode == 0, res.stderr[-800:]
    corpus = tmp_path / "corpus"
    corpus.mkdir()
    stage = tmp_path / "stage"
    res = rustlane.fuzz_round(crate, crate, "fuzz_decode_length", corpus, stage,
                              120, mechanism, work_dir, tc_env=tc_env)
    crashers = rustlane.harvest_crashers(crate, "fuzz_decode_length", stage)
    art_dir = crate / "fuzz" / "artifacts" / "fuzz_decode_length"
    if art_dir.is_dir():
        crashers += [p for p in art_dir.glob("crash-*") if p not in crashers]
    assert crashers, res.stderr[-800:]

    # Fold the artifact through fuzzgen's record machinery. Fork mode
    # swallows child backtraces, so replay the crasher non-forked for a
    # real stack with decode_length frames.
    from fuzzgen import dedup, runner, stackhash

    binary = next(
        (work_dir / "cargo-target").rglob("release/fuzz_decode_length"),
        None,
    )
    assert binary, "fuzz binary missing under CARGO_TARGET_DIR"
    argv = contain.contained_argv(
        mechanism, [str(binary), str(crashers[0])], crate, work_dir,
        env=rustlane._cargo_env(work_dir, tc_env),
        rlimits=rustlane._asan_rlimits(),
        rw_mounts=[(crashers[0].parent, crashers[0].parent)],
    )
    rep = runner.run_bounded(argv, timeout=120)
    stderr = (rep.stderr + rep.stdout)[-12000:]
    kind = stackhash.classify_kind("rust", stderr, rep.returncode)
    frames = stackhash.rust_stack(stderr)
    shash = stackhash.stack_hash(kind, frames, stderr)
    d = dedup.Deduper()
    rec = d.add(kind, shash, crashers[0].read_bytes(), stderr)
    out = dedup.write_crash_record(
        tmp_path / "out", rec,
        dict(target="ssz::decode::decode_length", lang="rust",
             repo_path=str(repo), git_sha=SHA),
    )
    run_json = json.loads((out / "run.json").read_text())
    assert run_json["kind"] in ("panic", "crash", "fatal-error")
    stack = (out / "stack.txt").read_text()
    assert "decode_length" in stack
