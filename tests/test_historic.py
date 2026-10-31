"""Historic-crash leg: sigp/lighthouse 561167fa1 ssz decode panic.

Env-gated (FUZZGEN_GATE_LIVE=1): clones lighthouse at the exact sha,
checks out the pre-fix parent, and fuzzes the real decode_length. The
2018 workspace manifest is unparseable by modern cargo, so the leg runs
the standalone ssz crate. decode_length is a 3-arg fn; generated
harnesses are single-arg only (NEEDS-HAND), so the target file is
hand-written here and the lane machinery does build/fuzz/records.
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


def test_lighthouse_ssz_historic(tmp_path):
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

    proc = subprocess.run(
        ["cargo", "+nightly", "fuzz", "run", "fuzz_decode_length", "--",
         "-max_total_time=120"],
        cwd=crate / "fuzz", capture_output=True, text=True, timeout=600,
    )
    assert proc.returncode in (1, 77), proc.stderr[-800:]

    # Fold the artifact through fuzzgen's record machinery.
    from fuzzgen import dedup, stackhash

    art = next((crate / "fuzz" / "artifacts" / "fuzz_decode_length").glob("crash-*"))
    stderr = proc.stderr + proc.stdout
    kind = stackhash.classify_kind("rust", stderr, proc.returncode)
    frames = stackhash.rust_stack(stderr)
    shash = stackhash.stack_hash(kind, frames, stderr)
    d = dedup.Deduper()
    rec = d.add(kind, shash, art.read_bytes(), stderr)
    out = dedup.write_crash_record(
        tmp_path / "out", rec,
        dict(target="ssz::decode::decode_length", lang="rust",
             repo_path=str(repo), git_sha=SHA),
    )
    run_json = json.loads((out / "run.json").read_text())
    assert run_json["kind"] in ("panic", "crash")
    stack = (out / "stack.txt").read_text()
    assert "decode_length" in stack
