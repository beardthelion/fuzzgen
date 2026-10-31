"""Worktree lifecycle (KTD2).

Detached throwaway worktrees under a dedicated work root, never /tmp and
never inside fuzzgen-out/. Submodule fetches pin protocol.file/ext.allow=never,
credential helpers and interactive prompts are disabled, and repo hooks are
neutralized (submodule URLs are attacker-chosen). A leftover state dir is a
refusal, never auto-cleanup.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
from pathlib import Path

from . import config

ACTIVE_MARKER = ".fuzzgen-active"
GIT_TIMEOUT = 300


class GitError(Exception):
    pass


def _git(args: list[str], cwd: Path | None = None, check: bool = True) -> subprocess.CompletedProcess:
    env = dict(os.environ, GIT_TERMINAL_PROMPT="0")
    try:
        proc = subprocess.run(
            ["git", *args], cwd=cwd, capture_output=True, text=True,
            timeout=GIT_TIMEOUT, env=env,
        )
    except subprocess.TimeoutExpired:
        raise GitError(f"git {' '.join(args)} timed out after {GIT_TIMEOUT}s")
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


def _under(child: Path, parent: Path) -> bool:
    try:
        return os.path.commonpath([str(child), str(parent)]) == str(parent)
    except ValueError:
        return False


def worktree_add_detached(
    repo: Path,
    sha: str | None = None,
    work_root: Path | None = None,
    submodule_paths: list[str] | None = None,
) -> tuple[Path, list[str]]:
    """Add a detached worktree; returns (path, warnings).

    Caller must pass a work_root already checked for leftovers. The
    destination always sits under work_root (mkdtemp dir=), which itself is
    caller-constrained to the KTD2 locations.
    """
    repo = Path(repo).resolve()
    work_root = Path(work_root or config.work_root()).resolve()
    for forbidden in (config.default_out_dir(repo).resolve(), Path("/tmp")):
        if _under(work_root, forbidden) or work_root == forbidden:
            raise GitError(f"work root {work_root} is forbidden (under {forbidden})")
    work_root.mkdir(parents=True, exist_ok=True)
    dest = Path(tempfile.mkdtemp(prefix="wt-", dir=work_root))
    dest.rmdir()  # git worktree add creates it

    warnings: list[str] = []
    sha = sha or head_sha(repo)
    if dirty(repo):
        warnings.append(f"fuzzing HEAD @ {sha[:12]} (checkout has uncommitted changes)")

    try:
        _git(["worktree", "prune"], cwd=repo)
        _git(["-c", "core.hooksPath=/dev/null",
              "worktree", "add", "--detach", str(dest), sha], cwd=repo)
        if submodule_paths:
            # Init only the named submodules; a full recursive init can
            # clone large vendor trees the target never needs.
            _git(
                [
                    "-c", "protocol.file.allow=never",
                    "-c", "protocol.ext.allow=never",
                    "-c", "credential.helper=",
                    "-c", "core.hooksPath=/dev/null",
                    "submodule", "update", "--init", "--recursive", "--",
                    *submodule_paths,
                ],
                cwd=dest,
            )
        (dest / ACTIVE_MARKER).write_text(f"repo={repo}\nsha={sha}\n")
    except GitError:
        # Anything after `worktree add` must not leave refusing residue.
        shutil.rmtree(dest, ignore_errors=True)
        _git(["worktree", "prune"], cwd=repo, check=False)
        raise
    return dest, warnings


def worktree_remove(repo: Path, worktree: Path) -> None:
    """Force-remove; a dirty tree is expected."""
    worktree = Path(worktree)
    if (worktree / ACTIVE_MARKER).exists():
        (worktree / ACTIVE_MARKER).unlink()
    # nobody-rung processes can leave nobody-owned dirs the user cannot
    # traverse; best-effort reopen for traversal before removal.
    try:
        subprocess.run(
            ["chmod", "-R", "a+rwX", str(worktree)],
            capture_output=True, timeout=60, check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        pass
    try:
        _git(["worktree", "remove", "--force", str(worktree)], cwd=Path(repo))
    except GitError:
        shutil.rmtree(worktree, ignore_errors=True)
        _git(["worktree", "prune"], cwd=Path(repo), check=False)
    if worktree.exists():
        import sys
        sys.stderr.write(
            f"fuzzgen: warning: worktree residue at {worktree} "
            "(unremovable foreign-owned files)\n"
        )


def mark_inactive(worktree: Path) -> None:
    marker = Path(worktree) / ACTIVE_MARKER
    if marker.exists():
        marker.unlink()
