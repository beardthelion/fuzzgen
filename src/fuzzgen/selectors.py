"""Selector grammar and resolution (KTD15).

Rust: ``crate::path::fn`` or ``crate::path::Type::method``.
Go: ``pkg/path.Func`` or ``pkg/path.Type.Method``.
C: ``file.c:func``.
First selector segment resolves the crate/package inside the worktree;
ambiguity is PROBE-FAIL, never a guess.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path

from .runner import run_bounded


@dataclass
class Selector:
    raw: str
    lang: str
    package: str  # crate name / go import path / source file dir
    name: str
    recv: str | None = None  # method receiver type


def parse_selector(raw: str, lang_hint: str | None = None) -> Selector:
    if "::" in raw:
        parts = raw.split("::")
        if len(parts) >= 3 and parts[-2][:1].isupper():
            return Selector(raw, "rust", parts[0], parts[-1], recv=parts[-2])
        return Selector(raw, "rust", parts[0], parts[-1])
    m = re.match(r"^(.+\.[ch]|.+\.[ch]pp|.*\.cc):([A-Za-z_][A-Za-z0-9_]*)$", raw)
    if m:
        pkg = m.group(1)
        if pkg.startswith("/") or ".." in pkg.split("/"):
            raise ValueError(f"c selector path escapes the worktree: {pkg!r}")
        return Selector(raw, "c", pkg, m.group(2))
    m2 = re.match(r"^(.+)\.([A-Z][A-Za-z0-9_]*)\.([A-Za-z_][A-Za-z0-9_]*)$", raw)
    if m2:
        return Selector(raw, "go", m2.group(1), m2.group(3), recv=m2.group(2))
    m3 = re.match(r"^([A-Za-z0-9_./-]+)\.([A-Za-z_][A-Za-z0-9_]*)$", raw)
    if m3 and ("/" in raw or lang_hint in (None, "go")):
        return Selector(raw, "go", m3.group(1), m3.group(2))
    raise ValueError(f"unparseable selector {raw!r}")


_GOLIST_ENV = {
    "GOFLAGS": "-mod=readonly",
    "GOPROXY": "off",
    "GIT_TERMINAL_PROMPT": "0",
    "GOVCS": "-*",
    "GONOSUMCHECK": "1",
}


def go_package_dir(repo: Path, import_path: str) -> Path:
    """Resolve a go import path to a directory inside the worktree.

    Offline, prompt-free resolution: a hostile go.mod/toolchain directive
    must not trigger a network fetch or credential use at this stage.
    """
    import os

    env = dict(_GOLIST_ENV)
    env["PATH"] = os.environ.get("PATH", "/usr/bin:/bin")
    env["HOME"] = os.environ.get("HOME", "/")
    proc = run_bounded(
        ["go", "list", "-f", "{{.Dir}}", f"./{import_path}" if not import_path.startswith(".") else import_path],
        cwd=repo, timeout=60, env=env,
    )
    if proc.returncode != 0:
        proc = run_bounded(
            ["go", "list", "-f", "{{.Dir}}", import_path], cwd=repo, timeout=60,
            env=env,
        )
    if proc.returncode != 0 or not proc.stdout.strip():
        raise FileNotFoundError(f"go list failed for {import_path}: {proc.stderr}")
    resolved = Path(proc.stdout.strip().splitlines()[-1]).resolve()
    root = repo.resolve()
    import os as _os
    if _os.path.commonpath([str(root), str(resolved)]) != str(root):
        raise FileNotFoundError(
            f"go list resolved {import_path} to {resolved} outside the worktree"
        )
    return resolved


def rust_crate_dirs(repo: Path, crate: str) -> list[Path]:
    """Candidate crate dirs from cargo metadata, confined to the worktree."""
    import os

    env = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "HOME": os.environ.get("HOME", "/"),
        "CARGO_NET_OFFLINE": "true",
        "GIT_TERMINAL_PROMPT": "0",
    }
    proc = run_bounded(
        ["cargo", "metadata", "--format-version", "1", "--no-deps", "--offline"],
        cwd=repo, timeout=120, env=env,
    )
    root = repo.resolve()
    dirs: list[Path] = []
    if proc.returncode == 0 and proc.stdout.strip():
        try:
            meta = json.loads(proc.stdout)
            for pkg in meta.get("packages", []):
                name = pkg.get("name", "").replace("-", "_")
                if name == crate:
                    d = Path(pkg["manifest_path"]).resolve().parent
                    if os.path.commonpath([str(root), str(d)]) == str(root):
                        dirs.append(d)
        except (json.JSONDecodeError, KeyError):
            pass
    if not dirs:
        for cand in (repo / crate, repo / "crates" / crate, repo):
            if (cand / "Cargo.toml").is_file():
                dirs.append(cand)
    return dirs


def find_rust_file(crate_dir: Path, name: str, recv: str | None = None) -> Path:
    """Locate the .rs file declaring the symbol; first match wins."""
    import re as _re

    src = crate_dir / "src"
    root = src if src.is_dir() else crate_dir
    fn_pat = _re.compile(rf"\bfn\s+{_re.escape(name)}\b")
    hits = []
    for path in sorted(root.rglob("*.rs")):
        try:
            text = path.read_text(errors="replace")
        except OSError:
            continue
        if fn_pat.search(text):
            if recv is None:
                return path
            hits.append(path)
    if recv is None:
        raise FileNotFoundError(f"fn {name} not found under {root}")
    impl_pat = _re.compile(rf"impl[^\n{{]*\b{_re.escape(recv)}\b")
    for path in hits:
        text = path.read_text(errors="replace")
        if impl_pat.search(text):
            return path
    raise FileNotFoundError(f"method {recv}::{name} not found under {root}")
