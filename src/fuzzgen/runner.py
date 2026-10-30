"""Bounded subprocess runner.

process_timeout is a wall-clock bound on the whole subprocess, separate
from any timeout the tool inside applies to itself (acl-guard-audit
runner.py precedent). Output capture is bounded; kill-tree teardown on
timeout; env is caller-supplied (containment scrubbing lives upstream).
"""

from __future__ import annotations

import os
import signal
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path

from .records import bound_text

DEFAULT_PROCESS_TIMEOUT = 900
CAPTURE_LIMIT = 1 << 20  # 1 MiB total captured output


@dataclass
class Result:
    argv: list[str]
    returncode: int | None
    stdout: str
    stderr: str
    timed_out: bool = False
    duration_s: float = 0.0
    error: str | None = None  # runner-level failure (missing binary, spawn error)

    @property
    def ok(self) -> bool:
        return self.error is None and not self.timed_out and self.returncode == 0


def run_bounded(
    argv: list[str],
    timeout: float = DEFAULT_PROCESS_TIMEOUT,
    env: dict | None = None,
    cwd: Path | None = None,
    input_bytes: bytes | None = None,
    capture_limit: int = CAPTURE_LIMIT,
) -> Result:
    """Run argv with a wall-clock bound and kill-tree teardown."""
    start = time.monotonic()
    res = Result(argv=list(argv), returncode=None, stdout="", stderr="")
    try:
        proc = subprocess.Popen(
            argv,
            cwd=cwd,
            env=env,
            stdin=subprocess.PIPE if input_bytes is not None else subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
        )
    except (FileNotFoundError, OSError) as exc:
        res.error = str(exc)
        return res

    try:
        out, err = proc.communicate(input=input_bytes, timeout=timeout)
        res.returncode = proc.returncode
    except subprocess.TimeoutExpired:
        res.timed_out = True
        _kill_tree(proc)
        out, err = proc.communicate()

    res.duration_s = time.monotonic() - start
    res.stdout = bound_text(out[:capture_limit].decode("utf-8", errors="replace"))
    res.stderr = bound_text(err[:capture_limit].decode("utf-8", errors="replace"))
    return res


def _kill_tree(proc: subprocess.Popen) -> None:
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError, OSError):
        try:
            proc.kill()
        except OSError:
            pass
