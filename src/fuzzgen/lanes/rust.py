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


def _public_path(crate: Path, parts: list[str]) -> str:
    """Shortest public path to the symbol: drop non-pub module segments
    when lib.rs re-exports them (`pub use mod::*` or `pub use mod::sym`)."""
    import re

    lib_rs = crate / "src" / "lib.rs"
    if len(parts) <= 1 or not lib_rs.is_file():
        return "::".join(parts)
    try:
        text = lib_rs.read_text(errors="replace")
    except OSError:
        return "::".join(parts)
    # Private top-level module segment with a re-export -> drop it.
    lead = parts[0]
    if re.search(rf"^\s*(?:pub\s+)?mod\s+{re.escape(lead)}\b", text, re.M) and \
       not re.search(rf"^\s*pub\s+mod\s+{re.escape(lead)}\b", text, re.M):
        name = parts[-1]
        for m in re.finditer(
            rf"pub\s+use\s+{re.escape(lead)}\s*::\s*(\*|{{[^}}]*}}|\w+)",
            text,
        ):
            exported = m.group(1)
            if exported == "*" or name in exported:
                return name
    return "::".join(parts)


def _is_workspace_member(crate: Path) -> bool:
    """True when the crate's manifest references workspace inheritance."""
    try:
        return "workspace" in (crate / "Cargo.toml").read_text(errors="replace")
    except OSError:
        return False


def _concrete_recv(crate: Path, recv: str) -> tuple[str | None, str]:
    """Turbofish args for generic recv types and a note naming the pick:
    concrete {recv}<T> impls (sorted first), then impls of the declared
    bound trait (sorted first), then type-param defaults; None when
    unresolvable."""
    import re

    impl_args: set[str] = set()
    params: dict[str, str] = {}  # param name -> bound trait
    defaults: str | None = None
    for f in sorted((crate / "src").rglob("*.rs")):
        try:
            text = f.read_text(errors="replace")
        except OSError:
            continue
        for m in re.finditer(
            rf"(?:struct|enum|type)\s+{re.escape(recv)}\s*<([^>]*)>", text
        ):
            decl = m.group(1)
            for pm in re.finditer(r"([A-Za-z_]\w*)\s*:\s*([\w:]+)", decl):
                params[pm.group(1)] = pm.group(2).split("+")[0].strip()
            for pm in re.finditer(r"(?:^|,)\s*([A-Za-z_]\w*)\s*[,>]", decl):
                params.setdefault(pm.group(1), "")
            ds = re.findall(r"\w+\s*=\s*([\w:]+)", decl)
            if len(ds) == decl.count(",") + 1:
                defaults = "<" + ", ".join(ds) + ">"
        for m in re.finditer(
            rf"(?:impl|::|=)\s*{re.escape(recv)}\s*<\s*([^<>]+)\s*>", text
        ):
            impl_args.add(m.group(1).strip())
    concrete = sorted(a for a in impl_args if a not in params)
    if concrete:
        return "<" + concrete[0] + ">", f"receiver resolved to {concrete[0]}"
    # No concrete impls: resolve via the declared bound trait's impls.
    bound_impls: set[str] = set()
    for bound in params.values():
        if not bound:
            continue
        for f in sorted((crate / "src").rglob("*.rs")):
            try:
                text = f.read_text(errors="replace")
            except OSError:
                continue
            for m in re.finditer(
                rf"impl(?:<[^>]*>)?\s+{re.escape(bound)}\s+for\s+([\w:]+)", text
            ):
                bound_impls.add(m.group(1))
    if bound_impls:
        pick = sorted(bound_impls)[0]
        return "<" + pick + ">", f"receiver resolved to {pick} via bound trait"
    if defaults:
        return defaults, f"receiver resolved to default params {defaults}"
    return None, ""


def _qualify_type(crate: Path, ident: str) -> str:
    """Crate-relative path for a bare type name: lib.rs pub use wins,
    else the file-derived module path."""
    import re

    if "::" in ident:
        return ident
    lib_rs = crate / "src" / "lib.rs"
    if lib_rs.is_file():
        text = lib_rs.read_text(errors="replace")
        if re.search(rf"pub\s+use\s+\w+(?:::\w+)*::\*?\b{re.escape(ident)}\b",
                     text) or re.search(
                     rf"pub\s+use\s+\w+(?:::\w+)*::\*\s*;", text):
            return ident
    for f in sorted((crate / "src").rglob("*.rs")):
        try:
            if re.search(
                rf"(?:pub\s+)?(?:struct|enum|type)\s+{re.escape(ident)}\b",
                f.read_text(errors="replace"),
            ):
                mod = f.relative_to(crate / "src").with_suffix("")
                parts = [p for p in mod.parts if p not in ("lib", "mod")]
                return "::".join(parts + [ident]) if parts else ident
        except OSError:
            continue
    return ident


def gen_harness(sel: Selector, probe_res: ProbeResult, worktree: Path) -> RustGenResult:
    dirs = rust_crate_dirs(worktree, sel.package)
    if not dirs:
        return RustGenResult("PROBE-FAIL", reason=f"crate {sel.package} not found")
    crate = dirs[0]
    recv_path = None
    if sel.recv:
        args = probe_res.args or ["&[u8]"]
        first = args[0] if args else "&[u8]"
        if first not in ("&[u8]", "&str", "str"):
            return RustGenResult(
                "NEEDS-HAND",
                reason=f"associated fn first param {first} is not &[u8]/&str",
            )
        recv_path = sel.recv
        # Generic receiver: emit Type::<T>::fn or NEEDS-HAND when the
        # concrete type cannot be resolved (E0283 otherwise).
        conc, recv_note = _concrete_recv(crate, sel.recv)
        if conc is None:
            import re
            generic = any(
                re.search(rf"{re.escape(sel.recv)}\s*<",
                          f.read_text(errors="replace"))
                for f in (crate / "src").rglob("*.rs")
            )
            if generic:
                return RustGenResult(
                    "NEEDS-HAND",
                    reason=f"generic receiver {sel.recv}: no concrete impl, "
                           "bound-trait impl, or default type params resolvable",
                )
        else:
            # Qualify turbofish args against the dep crate: bare idents
            # need crate:: paths, not fuzz-crate-relative names.
            inner = conc.strip("<>").split(", ")
            qual = ", ".join(
                f"{sel.package.replace('-', '_')}::{_qualify_type(crate, a)}"
                if a and not a.startswith(("&", "*")) else a
                for a in inner)
            recv_path = f"{sel.recv}::<{qual}>"
    fuzz_dir = crate / "fuzz" / "fuzz_targets"
    fuzz_dir.mkdir(parents=True, exist_ok=True)
    name = f"fuzzgen_{sel.name}"
    if recv_path:
        path = f"{recv_path}::{sel.name}"
    else:
        path = _public_path(crate, sel.raw.split("::")[1:])
    crate_ident = sel.package.replace("-", "_")
    dep_name = sel.package  # manifest dep keeps the real package name
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
        # A fuzz crate inside a workspace member must declare its own
        # workspace or cargo walks up to the parent's [workspace].
        ws = "[workspace]\n" if _is_workspace_member(crate) else ""
        manifest.write_text(
            f"""[package]
name = "fuzzgen-fuzz"
version = "0.0.0"
edition = "2021"
publish = false

{ws}[package.metadata]
cargo-fuzz = true

[dependencies]
libfuzzer-sys = "0.4"
{dep_name} = {{ path = ".." }}
"""
            + bin_entry
        )
    return RustGenResult("OK", target_path=fuzz_dir / f"{name}.rs",
                       reason=locals().get("recv_note") or None)


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
    """Host-side prefetch into the bound CARGO_HOME so contained builds
    resolve the registry with no network."""
    import os

    env = dict(os.environ, CARGO_TARGET_DIR=str(work_dir / "cargo-target"),
               CARGO_HOME=str(work_dir / "cargo-home"))
    res = runner.run_bounded(["cargo", "+nightly", "fetch"], cwd=crate / "fuzz",
                             timeout=600, env=env)
    return res.returncode == 0


def _asan_rlimits() -> dict:
    # ASan reserves tens of TB of virtual shadow on aarch64; any AS cap
    # kills it at startup (errno 12 mapping failure). Real memory is still
    # bounded by rss_limit in the engine flags.
    return {**contain.default_rlimits(), "as": "unlimited"}


def build(root: Path, crate: Path, name: str, mechanism: str, work_dir: Path,
          tc_env: dict | None = None) -> "runner.Result":
    # The whole repo binds as the worktree so workspace inheritance and
    # `path = ".."` deps resolve on every rung; the rung chdir's into
    # crate/fuzz/ where the manifest lives.
    argv = contain.contained_argv(
        mechanism,
        ["cargo", "+nightly", "fuzz", "build", "-s", "address", name],
        root, work_dir, env=_cargo_env(work_dir, tc_env),
        rlimits=_asan_rlimits(),
        chdir=str(crate / "fuzz"),
    )
    return runner.run_bounded(argv, timeout=1800, cwd=crate / "fuzz")


def fuzz_round(root: Path, crate: Path, name: str, corpus: Path, stage: Path,
               seconds: int, mechanism: str, work_dir: Path, jobs: int = 1,
               tc_env: dict | None = None) -> "runner.Result":
    stage.mkdir(parents=True, exist_ok=True)
    cmd = ["cargo", "+nightly", "fuzz", "run", "-s", "address", name,
           str(corpus), "--",
           f"-artifact_prefix={stage}/", f"-max_total_time={seconds}",
           f"-fork={jobs}", "-ignore_crashes=1", "-ignore_ooms=1",
           "-ignore_timeouts=1", "-rss_limit_mb=0"]
    # Record dirs the engine must write inside the ns get rw binds when
    # they live outside the bound worktree/work_dir (bwrap case).
    rw = []
    for p in (corpus, stage):
        rp = Path(p).resolve()
        if not str(rp).startswith(str(root.resolve())) and \
           not str(rp).startswith(str(work_dir.resolve())):
            rw.append((rp, rp))
    argv = contain.contained_argv(
        mechanism, cmd, root, work_dir, env=_cargo_env(work_dir, tc_env),
        rlimits={**_asan_rlimits(), "cpu": str(seconds + 300)},
        chdir=str(crate / "fuzz"), rw_mounts=rw,
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
