"""Rust cargo-fuzz lane (KTD8).

cargo +nightly fuzz build (ASan default; -Zbuild-std when rust-src) and
-fork=<jobs> -ignore_crashes=1 for multi-crash. Env-gated: no nightly/
cargo-fuzz records TOOL-MISSING on the lane, never a hard failure.
"""

from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

from .. import contain, runner
from ..probe import ProbeResult
from ..selectors import Selector, rust_crate_dirs

TMPL = Path(__file__).resolve().parents[1] / "templates" / "rust_fuzz_target.rs.tmpl"


@dataclass
class RustGenResult:
    status: str
    target_path: Path | None = None
    reason: str | None = None


def rust_lane_available() -> tuple[bool, str]:
    if not shutil.which("cargo"):
        return False, "cargo absent"
    if subprocess.run(["cargo", "+nightly", "--version"],
                      capture_output=True).returncode != 0:
        return False, "nightly toolchain absent"
    if subprocess.run(["cargo", "+nightly", "fuzz", "--version"],
                      capture_output=True).returncode != 0:
        return False, "cargo-fuzz absent"
    return True, ""


def gen_harness(sel: Selector, probe_res: ProbeResult, worktree: Path) -> RustGenResult:
    if sel.recv:
        return RustGenResult(
            "NEEDS-HAND",
            reason="method selector: receiver construction is target-specific",
        )
    dirs = rust_crate_dirs(worktree, sel.package)
    if not dirs:
        return RustGenResult("PROBE-FAIL", reason=f"crate {sel.package} not found")
    crate = dirs[0]
    fuzz_dir = crate / "fuzz" / "fuzz_targets"
    fuzz_dir.mkdir(parents=True, exist_ok=True)
    name = f"fuzzgen_{sel.name}"
    parts = sel.raw.split("::")
    path = "::".join(parts[1:-1] + [parts[-1]]) if len(parts) > 2 else sel.name
    crate_ident = sel.package.replace("-", "_")
    src = TMPL.read_text().replace("{{.Crate}}", crate_ident).replace("{{.Path}}", path)
    (fuzz_dir / f"{name}.rs").write_text(src)
    # cargo-fuzz needs the fuzz crate scaffold: fuzz/Cargo.toml naming
    # every target bin, or `cargo fuzz run` has nothing to build.
    manifest = fuzz_dir.parent / "Cargo.toml"
    manifest.write_text(
        f"""[package]
name = "fuzzgen-fuzz"
version = "0.0.0"
edition = "2021"
publish = false

[package.metadata]
cargo-fuzz = true

[dependencies]
libfuzzer-sys = "0.4"
{crate_ident} = {{ path = ".." }}

[[bin]]
name = "{name}"
path = "fuzz_targets/{name}.rs"
test = false
doc = false
"""
    )
    return RustGenResult("OK", target_path=fuzz_dir / f"{name}.rs")


def build_argv(crate: Path, target: str) -> list[str]:
    return ["cargo", "+nightly", "fuzz", "build", target]


def run_argv(target: str, corpus: Path, stage: Path, seconds: int, jobs: int) -> list[str]:
    return ["cargo", "+nightly", "fuzz", "run", target, str(corpus), "--",
            "-artifact_prefix", f"{stage}/", "-max_total_time", str(seconds),
            "-fork", str(jobs), "-ignore_crashes=1", "-ignore_ooms=1",
            "-ignore_timeouts=1", "-rss_limit_mb=0"]
