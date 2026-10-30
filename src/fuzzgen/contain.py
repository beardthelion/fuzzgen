"""Containment ladder (KTD3).

Detection: docker -> sudo docker -> bwrap/unshare -> nobody -> refuse, per
clawpatch-repro's measured ladder. Only docker and namespace rungs may claim
networkDenied; the nobody rung is recorded as bounded-not-contained.
Every rung carries an env allowlist and per-rung resource ceilings; dep
mounts expose only credential-free subdirs.
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

MECH_DOCKER = "docker"
MECH_SUDO_DOCKER = "sudo-docker"
MECH_BWRAP = "bwrap"
MECH_UNSHARE = "unshare"
MECH_NOBODY = "bounded-not-contained"
MECH_NONE = "none"
MECH_REFUSE = "refuse"

TOOLCHAIN_IMAGE = "fuzzgen-toolchain"

# Outbound-denying rungs.
NETWORK_DENIED = frozenset({MECH_DOCKER, MECH_SUDO_DOCKER, MECH_BWRAP, MECH_UNSHARE})

# Only these vars ever cross the boundary into a contained build/run. No
# GIT_SSH_COMMAND, GITHUB_TOKEN, AWS_*, or registry credentials.
ENV_ALLOW = frozenset(
    {
        "PATH",
        "HOME",
        "GOCACHE",
        "GOMODCACHE",
        "GOPATH",
        "GOFLAGS",
        "GOMEMLIMIT",
        "CARGO_HOME",
        "CARGO_TARGET_DIR",
        "CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUNNER",
        "RUSTFLAGS",
        "RUST_BACKTRACE",
        "ASAN_OPTIONS",
        "UBSAN_OPTIONS",
        "LSAN_OPTIONS",
        "LLVM_PROFILE_FILE",
    }
)

NOBODY_RLIMITS = ("as", "cpu", "fsize", "nproc", "nofile")


def _probe(argv: list[str], timeout: int = 20) -> bool:
    try:
        proc = subprocess.run(argv, capture_output=True, timeout=timeout)
        return proc.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return False


def detect(probe=_probe, image_present: bool = False) -> tuple[str, bool, str]:
    """Return (mechanism, networkDenied, note). probe is injectable for tests."""
    if image_present and probe(["docker", "version"]):
        return MECH_DOCKER, True, "docker daemon as this user"
    if image_present and probe(["sudo", "-n", "docker", "version"]):
        return MECH_SUDO_DOCKER, True, "docker via sudo -n"
    if probe(["bwrap", "--unshare-all", "--ro-bind", "/", "/", "true"]):
        return MECH_BWRAP, True, "bubblewrap user/net/mount namespaces"
    if probe(["unshare", "--user", "--map-root-user", "--net", "true"]):
        return MECH_UNSHARE, True, "user+net namespaces"
    if probe(["sudo", "-n", "-u", "nobody", "true"]):
        return MECH_NOBODY, False, "resource bounds only: open network, shared uid"
    return MECH_REFUSE, False, "no containment mechanism available"


def allow_no_containment(env: dict | None = None) -> bool:
    return (env or os.environ).get("FUZZGEN_ALLOW_NO_CONTAINMENT") == "1"


def scrub_env(base: dict | None = None) -> dict:
    """Allowlist only; credentials never cross the boundary."""
    base = base if base is not None else os.environ
    return {k: v for k, v in base.items() if k in ENV_ALLOW or k.startswith("FUZZGEN_")}


def credential_free_mounts(cache_dir: Path, kind: str) -> list[Path]:
    """Credential-free subdirs of a dep cache; never the whole CARGO_HOME."""
    if kind == "cargo":
        return [cache_dir / "registry", cache_dir / "git"]
    if kind == "go":
        return [cache_dir / "pkg" / "mod", cache_dir / "pkg" / "cache"]
    return []


def contained_argv(
    mechanism: str,
    cmd: list[str],
    worktree: Path,
    work_dir: Path,
    image: str = TOOLCHAIN_IMAGE,
    mounts: list[tuple[Path, Path]] | None = None,
    env: dict | None = None,
    memory: str = "4g",
    cpus: str = "2.0",
    pids: int = 512,
    rlimits: dict[str, str] | None = None,
) -> list[str]:
    """Wrap cmd for the rung. env is pre-scrubbed by the caller."""
    env = scrub_env(env)
    mounts = mounts or []
    wt = str(Path(worktree).resolve())
    wd = str(Path(work_dir).resolve())

    if mechanism in (MECH_DOCKER, MECH_SUDO_DOCKER):
        argv = ["docker", "run", "--rm", "--network", "none",
                "--memory", memory, "--cpus", cpus,
                "--pids-limit", str(pids), "--cap-drop", "ALL",
                "-v", f"{wt}:{wt}", "-w", wt]
        for src, dst in mounts:
            argv += ["-v", f"{src}:{dst}:ro"]
        for k, v in sorted(env.items()):
            argv += ["-e", f"{k}={v}"]
        argv += ["-e", f"HOME={wd}", image, *cmd]
        return (["sudo", "-n"] if mechanism == MECH_SUDO_DOCKER else []) + argv

    if mechanism in (MECH_BWRAP, MECH_UNSHARE):
        env_args = []
        for k, v in sorted(env.items()):
            env_args += ["--setenv", k, v]
        if mechanism == MECH_BWRAP:
            argv = ["bwrap", "--unshare-all", "--die-with-parent",
                    "--clearenv", "--ro-bind", wt, wt, "--bind", wd, wd,
                    "--setenv", "HOME", wd]
            for src, dst in mounts:
                argv += ["--ro-bind", str(src), str(dst)]
            return argv + env_args + ["--", *cmd]
        # unshare: bind-mounts unavailable to us here; run in worktree with
        # net namespace denied.
        return ["unshare", "--user", "--map-root-user", "--net",
                "env", "-i", f"HOME={wd}",
                *[f"{k}={v}" for k, v in sorted(env.items())], *cmd]

    if mechanism == MECH_NOBODY:
        env_args = [f"{k}={v}" for k, v in sorted(env.items())]
        argv = ["sudo", "-n", "-u", "nobody",
                "env", "-i", f"HOME={wd}", "PATH=/usr/local/bin:/usr/bin:/bin",
                *env_args]
        rl = rlimits or {}
        if rl:
            argv += ["prlimit"] + [f"--{k}={v}" for k, v in rl.items() if k in NOBODY_RLIMITS] + ["--"]
        return argv + [*cmd]

    if mechanism == MECH_NONE:
        return ["env", "-i", f"HOME={wd}", *[f"{k}={v}" for k, v in sorted(env.items())], *cmd]

    raise ValueError(f"cannot build argv for mechanism {mechanism!r}")
