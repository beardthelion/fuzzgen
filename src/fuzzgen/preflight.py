"""Preflight: per-language capability map (KTD14).

Probes run through the selected containment mechanism when one is supplied:
host PATH says nothing about tools inside the rung, so each check is
``mechanism_cmd + [tool, version-flag]``. With no mechanism (host check),
probes run directly. Missing tools yield TOOL-MISSING on affected lanes only.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

_TIMEOUT = 15


def _run(argv: list[str]) -> tuple[int, str]:
    try:
        proc = subprocess.run(
            argv, capture_output=True, text=True, timeout=_TIMEOUT
        )
        return proc.returncode, (proc.stdout or "") + (proc.stderr or "")
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError) as exc:
        return 127, str(exc)


def _has(cmd: list[str], mechanism: list[str] | None, needle: str | None = None) -> bool:
    rc, out = _run((mechanism or []) + cmd)
    if rc != 0:
        return False
    return needle is None or needle in out


def probe(mechanism: list[str] | None = None) -> dict:
    """Return the capability map. Keys: go, rust, c, docker, nobody, bwrap, cgroup2, time_v."""
    caps = {
        "go": "OK" if _has(["go", "version"], mechanism, "go version") else "TOOL-MISSING",
        "rust": "TOOL-MISSING",
        "c": "TOOL-MISSING",
        "docker": _has(["docker", "version"], mechanism),
        "sudo_docker": _has(["sudo", "-n", "docker", "version"], mechanism),
        "nobody": _has(["sudo", "-n", "-u", "nobody", "true"], mechanism),
        "bwrap": _has(["bwrap", "--version"], mechanism),
        "cgroup2": Path("/sys/fs/cgroup/cgroup.controllers").exists(),
        "time_v": _has(["/usr/bin/time", "--version"], mechanism),
    }
    # Rust lane needs the full nightly+cargo-fuzz chain, not just cargo.
    if _has(["cargo", "--version"], mechanism):
        nightly = _has(["cargo", "+nightly", "--version"], mechanism)
        rust_src = _has(
            ["rustup", "+nightly", "component", "list", "--installed"],
            mechanism,
            "rust-src",
        )
        cargo_fuzz = _has(["cargo", "+nightly", "fuzz", "--version"], mechanism)
        if nightly and rust_src and cargo_fuzz:
            caps["rust"] = "OK"
    if _has(["clang", "--version"], mechanism) and (
        _has(["llvm-symbolizer", "--version"], mechanism)
    ):
        caps["c"] = "OK"
    return caps


def lane_caps(caps: dict) -> dict[str, str]:
    """Lane-keyed view used by preflight reporting and run routing."""
    return {"go": caps["go"], "rust": caps["rust"], "c": caps["c"]}
