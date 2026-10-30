"""Worktree lifecycle (KTD2).

Detached throwaway worktrees under a dedicated work root, never /tmp and
never inside fuzzgen-out/. Submodule fetches pin protocol.file/ext.allow=never
(submodule URLs are attacker-chosen). A leftover state dir is a refusal,
never auto-cleanup.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
from pathlib import Path

from . import config

ACTIVE_MARKER = ".fuzzgen-active"


class GitError(Exception):
    pass


def _git(args: list[str], cwd: Path | None = None, check: bool = True) -> subprocess.CompletedProcess:
    proc = subprocess.run(
        ["git", *args], cwd=cwd, capture_output=True, text=True
    )
    if check and proc.returncode != 0:
        raise GitError(proc.stderr.strip() or f"git {' '.join(args)} failed")
    return proc


def head_sha(repo: Path) -> str:
    return _git(["rev-parse", "HEAD"], cwd=repo).stdout.strip()


def dirty(repo: Path) -> bool:
    return bool(_git(["status", "--porcelain"], cwd=repo).stdout.strip())


def leftover_worktrees(work_root: Path) -> list[Path]:
    """State dirs whose active markers remain (a killed run's residue)."""
    if not work_root.is_dir():
        return []
    return [
        d
        for d in work_root.iterdir()
        if d.is_dir() and (d / ACTIVE_MARKER).exists()
    ]


def worktree_add_detached(
    repo: Path,
    sha: str | None = None,
    work_root: Path | None = None,
) -> tuple[Path, list[str]]:
    """Add a detached worktree; returns (path, warnings).

    Caller must pass a work_root already checked for leftovers. The
    destination always sits under work_root (mkdtemp dir=), which itself is
    caller-constrained to the KTD2 locations.
    """
    repo = Path(repo).resolve()
    work_root = Path(work_root or config.work_root()).resolve()
    out_default = config.default_out_dir(repo).resolve()
    for forbidden in (out_default, Path("/tmp")):
        if str(work_root).startswith(str(forbidden)):
            raise GitError(f"work root {work_root} is forbidden (under {forbidden})")
    work_root.mkdir(parents=True, exist_ok=True)
    dest = Path(tempfile.mkdtemp(prefix="wt-", dir=work_root))
    dest.rmdir()  # git worktree add creates it

    warnings: list[str] = []
    sha = sha or head_sha(repo)
    if dirty(repo):
        warnings.append(f"fuzzing HEAD @ {sha[:12]} (checkout has uncommitted changes)")

    _git(["worktree", "prune"], cwd=repo)
    _git(["worktree", "add", "--detach", str(dest), sha], cwd=repo)
    (dest / ACTIVE_MARKER).write_text(f"repo={repo}\nsha={sha}\n")
    _git(
        [
            "-c", "protocol.file.allow=never",
            "-c", "protocol.ext.allow=never",
            "submodule", "update", "--init", "--recursive",
        ],
        cwd=dest,
    )
    return dest, warnings


def worktree_remove(repo: Path, worktree: Path) -> None:
    """Force-remove; a dirty tree is expected."""
    worktree = Path(worktree)
    if (worktree / ACTIVE_MARKER).exists():
        (worktree / ACTIVE_MARKER).unlink()
    try:
        _git(["worktree", "remove", "--force", str(worktree)], cwd=Path(repo))
    except GitError:
        shutil.rmtree(worktree, ignore_errors=True)
        _git(["worktree", "prune"], cwd=Path(repo), check=False)


def mark_inactive(worktree: Path) -> None:
    marker = Path(worktree) / ACTIVE_MARKER
    if marker.exists():
        marker.unlink()
