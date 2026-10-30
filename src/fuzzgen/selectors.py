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
        return Selector(raw, "c", m.group(1), m.group(2))
    if "/" in raw or lang_hint == "go":
        seg = raw.rsplit(".", 1)
        if len(seg) == 2:
            return Selector(raw, "go", seg[0], seg[1])
        # pkg/path.Type.Method
        m2 = re.match(r"^(.+)\.([A-Z][A-Za-z0-9_]*)\.([A-Za-z_][A-Za-z0-9_]*)$", raw)
        if m2:
            return Selector(raw, "go", m2.group(1), m2.group(3), recv=m2.group(2))
        raise ValueError(f"unparseable go selector {raw!r}")
    raise ValueError(f"unparseable selector {raw!r}")


def go_package_dir(repo: Path, import_path: str) -> Path:
    """Resolve a go import path to a directory inside the worktree."""
    proc = run_bounded(
        ["go", "list", "-f", "{{.Dir}}", f"./{import_path}" if not import_path.startswith(".") else import_path],
        cwd=repo,
        timeout=60,
    )
    if proc.returncode != 0:
        proc = run_bounded(
            ["go", "list", "-f", "{{.Dir}}", import_path], cwd=repo, timeout=60
        )
    if proc.returncode != 0 or not proc.stdout.strip():
        raise FileNotFoundError(f"go list failed for {import_path}: {proc.stderr}")
    return Path(proc.stdout.strip().splitlines()[-1])


def rust_crate_dirs(repo: Path, crate: str) -> list[Path]:
    """candidate crate dirs from cargo metadata; ambiguity handled by caller."""
    proc = run_bounded(
        ["cargo", "metadata", "--format-version", "1", "--no-deps"],
        cwd=repo,
        timeout=120,
    )
    dirs: list[Path] = []
    if proc.returncode == 0 and proc.stdout.strip():
        try:
            meta = json.loads(proc.stdout)
            for pkg in meta.get("packages", []):
                name = pkg.get("name", "").replace("-", "_")
                if name == crate:
                    dirs.append(Path(pkg["manifest_path"]).parent)
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
