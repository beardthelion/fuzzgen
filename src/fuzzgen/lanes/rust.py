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
    # every target bin. If the target repo already fuzzes, append only
    # our bin entry and leave the manifest intact.
    manifest = fuzz_dir.parent / "Cargo.toml"
    bin_entry = (
        f'\n[[bin]]\nname = "{name}"\npath = "fuzz_targets/{name}.rs"\n'
        "test = false\ndoc = false\n"
    )
    if manifest.is_file():
        text = manifest.read_text()
        if f'name = "{name}"' not in text:
            manifest.write_text(text.rstrip("\n") + "\n" + bin_entry)
    else:
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
"""
            + bin_entry
        )
    return RustGenResult("OK", target_path=fuzz_dir / f"{name}.rs")


def build_argv(crate: Path, target: str) -> list[str]:
    return ["cargo", "+nightly", "fuzz", "build", target]


def run_argv(target: str, corpus: Path, stage: Path, seconds: int, jobs: int) -> list[str]:
    return ["cargo", "+nightly", "fuzz", "run", target, str(corpus), "--",
            "-artifact_prefix", f"{stage}/", "-max_total_time", str(seconds),
            "-fork", str(jobs), "-ignore_crashes=1", "-ignore_ooms=1",
            "-ignore_timeouts=1", "-rss_limit_mb=0"]


def stage_rust_toolchain(work_dir: Path) -> dict:
    """Hardlink cargo+rustup into work_dir so nobody can reach them.

    The real toolchain lives under $HOME, which a nobody-rung process
    cannot traverse. Hardlinking is instant and the staged copy needs
    no traversal of $HOME at all.
    """
    import os
    import shutil

    tc = work_dir / "toolchain"
    bin_d = tc / "bin"
    rustup_d = tc / "rustup"
    env: dict[str, str] = {}
    cargo = shutil.which("cargo") or str(Path.home() / ".cargo" / "bin" / "cargo")
    if not Path(cargo).exists():
        return env
    bin_d.mkdir(parents=True, exist_ok=True)
    cargo_bin = Path(cargo).resolve().parent
    # Copies, never links: provisioning chmods the staged tree, and a
    # hardlink would rewrite the host toolchain's inode.
    for tool in ("cargo", "cargo-fuzz", "rustc", "rustup"):
        src = cargo_bin / tool
        dst = bin_d / tool
        real = src.resolve() if src.is_symlink() else src
        if real.is_file() and not dst.exists():
            shutil.copy2(real, dst)
            dst.chmod(0o755)
    rustup_home = Path.home() / ".rustup"
    nightly = None
    for d in (rustup_home / "toolchains").glob("nightly-*"):
        nightly = d
        break
    if nightly is not None and not (rustup_d / "toolchains" / nightly.name).exists():
        shutil.copytree(nightly, rustup_d / "toolchains" / nightly.name,
                        copy_function=shutil.copy2, symlinks=True)
        for p in (rustup_d / "toolchains" / nightly.name).rglob("*"):
            if p.is_file() and (p.stat().st_mode & 0o100 or "bin" in p.parts):
                p.chmod(0o755)
        settings = rustup_home / "settings.toml"
        if settings.is_file():
            shutil.copy2(settings, rustup_d / "settings.toml")
    env["PATH"] = f"{bin_d}:{contain._toolchain_path()}"
    env["RUSTUP_HOME"] = str(rustup_d)
    env["CARGO"] = str(bin_d / "cargo")
    return env


def _cargo_env(work_dir: Path, extra: dict | None = None) -> dict:
    env = {
        "CARGO_HOME": str(work_dir / "cargo-home"),
        "CARGO_TARGET_DIR": str(work_dir / "cargo-target"),
        "HOME": str(work_dir),
        "RUSTFLAGS": "",
    }
    env.update(extra or {})
    return env


def fetch_deps(crate: Path, work_dir: Path) -> bool:
    """Host-side prefetch so contained builds run with no network."""
    import os

    env = dict(os.environ, CARGO_TARGET_DIR=str(work_dir / "cargo-target"),
               CARGO_HOME=os.environ.get("CARGO_HOME", str(Path.home() / ".cargo")))
    res = runner.run_bounded(["cargo", "+nightly", "fetch"], cwd=crate / "fuzz",
                             timeout=600, env=env)
    return res.returncode == 0


def _asan_rlimits() -> dict:
    # ASan reserves tens of TB of virtual shadow on aarch64; any AS cap
    # kills it at startup (errno 12 mapping failure). Real memory is still
    # bounded by rss_limit in the engine flags.
    return {**contain.default_rlimits(), "as": "unlimited"}


def build(crate: Path, name: str, mechanism: str, work_dir: Path,
          tc_env: dict | None = None) -> "runner.Result":
    argv = contain.contained_argv(
        mechanism,
        ["cargo", "+nightly", "fuzz", "build", "-s", "address", name],
        crate / "fuzz", work_dir, env=_cargo_env(work_dir, tc_env),
        rlimits=_asan_rlimits(),
    )
    return runner.run_bounded(argv, timeout=1800, cwd=crate / "fuzz")


def fuzz_round(crate: Path, name: str, corpus: Path, stage: Path, seconds: int,
               mechanism: str, work_dir: Path, jobs: int = 1,
               tc_env: dict | None = None) -> "runner.Result":
    stage.mkdir(parents=True, exist_ok=True)
    cmd = ["cargo", "+nightly", "fuzz", "run", "-s", "address", name,
           str(corpus), "--",
           f"-artifact_prefix={stage}/", f"-max_total_time={seconds}",
           f"-fork={jobs}", "-ignore_crashes=1", "-ignore_ooms=1",
           "-ignore_timeouts=1", "-rss_limit_mb=0"]
    argv = contain.contained_argv(
        mechanism, cmd, crate / "fuzz", work_dir, env=_cargo_env(work_dir, tc_env),
        rlimits={**_asan_rlimits(), "cpu": str(seconds + 300)},
    )
    return runner.run_bounded(argv, timeout=seconds + 300, cwd=crate / "fuzz")


def harvest_crashers(crate: Path, name: str, stage: Path,
                     before: set[Path] | None = None) -> list[Path]:
    """Sweep crash-* artifacts from -artifact_prefix and fuzz/artifacts."""
    found: list[Path] = []
    for root in (stage, crate / "fuzz" / "artifacts" / name):
        if not root.is_dir() or root.is_symlink():
            continue
        for p in sorted(root.iterdir()):
            if p.is_file() and not p.is_symlink() and p.name.startswith("crash-"):
                if before and p in before:
                    continue
                found.append(p)
    return found
