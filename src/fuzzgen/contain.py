"""Containment ladder (KTD3).

Detection: docker -> sudo docker -> bwrap -> nobody -> refuse, per
clawpatch-repro's measured ladder. Only docker and namespace rungs may
claim networkDenied; the nobody rung is recorded as bounded-not-contained.
The bare `unshare --user --net` rung was removed: it shares the host mount
namespace with a mapped root, which is less containment than nobody.
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
MECH_UNSHARE = "unshare"  # retained for argv tests; not selectable in detect
MECH_NOBODY = "bounded-not-contained"
MECH_NONE = "none"
MECH_REFUSE = "refuse"

TOOLCHAIN_IMAGE = "fuzzgen-toolchain"

# Outbound-denying rungs.
NETWORK_DENIED = frozenset({MECH_DOCKER, MECH_SUDO_DOCKER, MECH_BWRAP, MECH_UNSHARE})

# Only these vars ever cross the boundary into a contained build/run. No
# GIT_SSH_COMMAND, GITHUB_TOKEN, AWS_*, or registry credentials. FUZZGEN_*
# vars (probe paths, flags) are host-local and never cross either.
ENV_ALLOW = frozenset(
    {
        "PATH",
        "HOME",
        "GOCACHE",
        "GOMODCACHE",
        "GOPATH",
        "GOFLAGS",
        "GOMEMLIMIT",
        "CARGO",
        "CARGO_HOME",
        "CARGO_TARGET_DIR",
        "RUSTUP_HOME",
        "RUSTFLAGS",
        "RUST_BACKTRACE",
        "ASAN_OPTIONS",
        "UBSAN_OPTIONS",
        "LSAN_OPTIONS",
        "LLVM_PROFILE_FILE",
    }
)

NOBODY_RLIMITS = ("as", "cpu", "fsize", "nproc", "nofile")

# Read-only toolchain binds every namespace rung needs to exec anything.
TOOLCHAIN_BINDS = ("/usr", "/lib", "/lib64", "/bin", "/sbin", "/opt", "/etc")


def _toolchain_path() -> str:
    """PATH inside the ns: dirs of the real toolchain binaries, resolved
    with shutil.which (cargo in ~/.cargo/bin is a real case on some hosts)."""
    import shutil

    dirs = []
    for tool in ("go", "cargo", "rustc", "clang", "cc", "ld", "git",
                 "python3"):
        p = shutil.which(tool)
        if p:
            d = str(Path(p).resolve().parent)
            if d not in dirs:
                dirs.append(d)
    for d in ("/usr/local/bin", "/usr/bin", "/bin"):
        if d not in dirs:
            dirs.append(d)
    return ":".join(dirs)


def _probe(argv: list[str], timeout: int = 20) -> bool:
    try:
        proc = subprocess.run(argv, capture_output=True, timeout=timeout)
        return proc.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return False


def _image_present(probe, image: str = TOOLCHAIN_IMAGE) -> bool:
    return probe(["docker", "image", "inspect", image]) or probe(
        ["sudo", "-n", "docker", "image", "inspect", image]
    )


def detect(probe=_probe, image_present: bool | None = None) -> tuple[str, bool, str]:
    """Return (mechanism, networkDenied, note). probe is injectable for tests."""
    if image_present is None:
        image_present = _image_present(probe)
    if image_present and probe(["docker", "version"]):
        return MECH_DOCKER, True, "docker daemon as this user"
    if image_present and probe(["sudo", "-n", "docker", "version"]):
        return MECH_SUDO_DOCKER, True, "docker via sudo -n"
    if probe(["bwrap", "--unshare-all", "--ro-bind", "/", "/", "true"]):
        return MECH_BWRAP, True, "bubblewrap user/net/mount namespaces"
    if probe(["sudo", "-n", "-u", "nobody", "true"]):
        return MECH_NOBODY, False, "resource bounds only: open network, shared uid"
    return MECH_REFUSE, False, "no containment mechanism available"


def allow_no_containment(env: dict | None = None) -> bool:
    return (env or os.environ).get("FUZZGEN_ALLOW_NO_CONTAINMENT") == "1"


def scrub_env(base: dict | None = None) -> dict:
    """Allowlist only; credentials and FUZZGEN_* host vars never cross."""
    base = base if base is not None else os.environ
    return {k: v for k, v in base.items() if k in ENV_ALLOW}


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
    chdir: str | None = None,
    rw_mounts: list[tuple[Path, Path]] | None = None,
) -> list[str]:
    """Wrap cmd for the rung. env is pre-scrubbed by the caller."""
    env = scrub_env(env)
    mounts = mounts or []
    rw_mounts = rw_mounts or []
    wt = str(Path(worktree).resolve())
    wd = str(Path(work_dir).resolve())

    if mechanism in (MECH_DOCKER, MECH_SUDO_DOCKER):
        argv = ["docker", "run", "--rm", "--network", "none",
                "--memory", memory, "--cpus", cpus,
                "--pids-limit", str(pids), "--cap-drop", "ALL",
                "-v", f"{wt}:{wt}", "-v", f"{wd}:{wd}", "-w", chdir or wt]
        for src, dst in mounts:
            argv += ["-v", f"{src}:{dst}:ro"]
        for k, v in sorted(env.items()):
            argv += ["-e", f"{k}={v}"]
        argv += ["-e", f"HOME={wd}", image, *cmd]
        return (["sudo", "-n"] if mechanism == MECH_SUDO_DOCKER else []) + argv

    if mechanism == MECH_BWRAP:
        env_args = []
        for k, v in sorted(env.items()):
            env_args += ["--setenv", k, v]
        argv = ["bwrap", "--unshare-all", "--die-with-parent", "--clearenv",
                "--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp"]
        # Toolchain ro-binds first so binaries/libs resolve inside the ns.
        for d in TOOLCHAIN_BINDS:
            if Path(d).exists():
                argv += ["--ro-bind", d, d]
        argv += ["--bind", wt, wt, "--bind", wd, wd,
                 "--setenv", "HOME", wd,
                 "--setenv", "PATH", _toolchain_path()]
        for src, dst in mounts:
            argv += ["--ro-bind", str(src), str(dst)]
        for src, dst in rw_mounts:
            argv += ["--bind", str(src), str(dst)]
        if chdir:
            argv += ["--chdir", chdir]
        return argv + env_args + ["--", *cmd]

    if mechanism == MECH_UNSHARE:
        # Not selectable via detect(): user+net namespaces alone share the
        # host mount namespace with mapped root, strictly less containment
        # than nobody. Kept only so argv construction stays testable.
        raise ValueError("unshare rung is not containment (host fs visible)")

    if mechanism == MECH_NOBODY:
        env_args = [f"{k}={v}" for k, v in sorted(env.items())]
        argv = ["sudo", "-n", "-u", "nobody",
                "env", "-i", f"HOME={wd}", f"PATH={_toolchain_path()}",
                *env_args]
        rl = rlimits or {}
        if rl:
            argv += ["prlimit"] + [f"--{k}={v}" for k, v in rl.items() if k in NOBODY_RLIMITS] + ["--"]
        return argv + [*cmd]

    if mechanism == MECH_NONE:
        return ["env", "-i", f"HOME={wd}",
                f"PATH={os.environ.get('PATH', '/usr/local/bin:/usr/bin:/bin')}",
                *[f"{k}={v}" for k, v in sorted(env.items())], *cmd]

    raise ValueError(f"cannot build argv for mechanism {mechanism!r}")


# Hard-cap defaults applied on every contained command that accepts rlimits.
def default_rlimits(mem_mb: int | None = None, cpu_s: int | None = None) -> dict[str, str]:
    rl: dict[str, str] = {
        "as": str((mem_mb or 4096) << 20),
        "fsize": "268435456",  # 256 MiB per file
        "nproc": "256",
        "nofile": "1024",
    }
    if cpu_s is not None:
        rl["cpu"] = str(cpu_s)
    return rl
