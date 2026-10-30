"""Probe helpers: build-once binaries + classification (KTD1, KTD15).

Helpers live in helpers/{rust,go}-probe and build once into bin/ with
stale-rebuild; FUZZGEN_RUST_PROBE / FUZZGEN_GO_PROBE override the path.
Success is parseable stdout, never the exit code. An unmapped signature
is NEEDS-HAND, not a guess.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from .runner import run_bounded
from .selectors import (
    Selector,
    find_rust_file,
    go_package_dir,
    rust_crate_dirs,
)

PKG_ROOT = Path(__file__).resolve().parents[2]


@dataclass
class ProbeResult:
    status: str  # OK | PROBE-FAIL | TOOL-MISSING | NEEDS-HAND
    kind: str | None = None  # bytes, string, multi, io-reader, ssz, rlp, struct, binary, json
    mode: str | None = None  # bytes, struct, ssz, rlp
    args: list[str] = field(default_factory=list)
    markers: list[str] = field(default_factory=list)
    reason: str | None = None


_KIND_TO_MODE = {
    "bytes": "bytes",
    "string": "bytes",
    "multi": "struct",
    "io-reader": "bytes",
    "ssz": "ssz",
    "rlp": "rlp",
    "struct": "struct",
    "binary": "struct",
    "json": "struct",
}


def helper_path(name: str) -> Path | None:
    env_key = f"FUZZGEN_{name.upper().replace('-', '_')}"
    if os.environ.get(env_key):
        return Path(os.environ[env_key])
    cand = PKG_ROOT / "bin" / name
    return cand if cand.is_file() else None


def build_helper(name: str) -> Path | None:
    """Build-once with stale-rebuild; returns None when the toolchain is absent."""
    env_key = f"FUZZGEN_{name.upper().replace('-', '_')}"
    if os.environ.get(env_key):
        return Path(os.environ[env_key])
    src = PKG_ROOT / "helpers" / name
    out = PKG_ROOT / "bin" / name
    if not src.is_dir():
        return None
    if out.is_file() and _fresh(out, src):
        return out
    out.parent.mkdir(exist_ok=True)
    if name == "rust-probe":
        if not shutil.which("cargo"):
            return None
        proc = subprocess.run(
            ["cargo", "build", "--release", "-q"], cwd=src,
            capture_output=True, timeout=600,
        )
        built = src / "target" / "release" / "fuzzgen-rust-probe"
    else:
        if not shutil.which("go"):
            return None
        proc = subprocess.run(
            ["go", "build", "-o", str(out), "."], cwd=src,
            capture_output=True, timeout=300,
        )
        built = out
    if proc.returncode != 0 or not built.is_file():
        return None
    if name == "rust-probe":
        shutil.copy(built, out)
    return out


def _fresh(out: Path, src: Path) -> bool:
    mtime = out.stat().st_mtime
    for p in src.rglob("*"):
        if p.is_file() and "target" not in p.parts and p.stat().st_mtime > mtime:
            return False
    return True


def _run_probe(argv: list[str], cwd: Path) -> dict:
    res = run_bounded(argv, cwd=cwd, timeout=120)
    try:
        return json.loads(res.stdout.strip().splitlines()[-1])
    except (json.JSONDecodeError, IndexError):
        return {"found": False, "reason": res.stderr or "unparseable probe output"}


def probe_signature(sel: Selector, worktree: Path) -> ProbeResult:
    """Classify a selector's input signature inside the worktree."""
    if sel.lang == "go":
        return _probe_go(sel, worktree)
    if sel.lang == "rust":
        return _probe_rust(sel, worktree)
    return _probe_c(sel, worktree)


def _finish(found_kind: str | None, rep: dict) -> ProbeResult:
    if not rep.get("found"):
        return ProbeResult("PROBE-FAIL", reason=rep.get("reason"))
    kind = found_kind or rep.get("kind")
    if kind == "unknown" or kind not in _KIND_TO_MODE:
        return ProbeResult(
            "NEEDS-HAND",
            kind=kind,
            args=rep.get("args", []),
            reason="signature did not map to a seedable input kind",
        )
    return ProbeResult(
        "OK", kind=kind, mode=_KIND_TO_MODE[kind],
        args=rep.get("args", []), markers=rep.get("markers", []),
    )


def _probe_go(sel: Selector, worktree: Path) -> ProbeResult:
    helper = build_helper("go-probe")
    if helper is None:
        return ProbeResult("TOOL-MISSING", reason="go-probe helper missing")
    try:
        pkg_dir = go_package_dir(worktree, sel.package)
    except FileNotFoundError as exc:
        return ProbeResult("PROBE-FAIL", reason=str(exc))
    argv = [str(helper), "-dir", str(pkg_dir), "-name", sel.name]
    if sel.recv:
        argv += ["-type", sel.recv]
    rep = _run_probe(argv, worktree)
    return _finish(None, rep)


def _probe_rust(sel: Selector, worktree: Path) -> ProbeResult:
    helper = build_helper("rust-probe")
    if helper is None:
        return ProbeResult("TOOL-MISSING", reason="rust-probe helper missing")
    dirs = rust_crate_dirs(worktree, sel.package)
    if not dirs:
        return ProbeResult("PROBE-FAIL", reason=f"crate {sel.package} not found")
    if len(dirs) > 1:
        return ProbeResult("PROBE-FAIL", reason=f"crate {sel.package} ambiguous: {dirs}")
    try:
        path = find_rust_file(dirs[0], sel.name, sel.recv)
    except FileNotFoundError as exc:
        return ProbeResult("PROBE-FAIL", reason=str(exc))
    argv = [str(helper), "-file", str(path), "-name", sel.name]
    if sel.recv:
        argv += ["-type", sel.recv]
    rep = _run_probe(argv, worktree)
    return _finish(None, rep)


def _probe_c(sel: Selector, worktree: Path) -> ProbeResult:
    path = worktree / sel.package
    if not path.is_file():
        return ProbeResult("PROBE-FAIL", reason=f"{sel.package} not in worktree")
    import re

    text = path.read_text(errors="replace")
    pat = re.compile(
        rf"(?:^|\n)\s*(?:static\s+)?[\w\s\*]+?\b{re.escape(sel.name)}\s*\(([^)]*)\)"
    )
    m = pat.search(text)
    if not m:
        return ProbeResult("PROBE-FAIL", reason=f"{sel.name} not found in {sel.package}")
    params = m.group(1).strip()
    if params in ("void", ""):
        return ProbeResult("NEEDS-HAND", reason="nullary function")
    if re.search(r"(const\s+)?(u?int8_t|unsigned char|char|uint8_t)\s*\*", params) and re.search(
        r"(size_t|int|unsigned|u?int\d+_t)\s+\w+\s*[,)]", params + ","
    ):
        return ProbeResult("OK", kind="bytes", mode="bytes")
    return ProbeResult("NEEDS-HAND", kind="unknown", reason="C signature is not (buf, len)")
