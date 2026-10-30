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
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path

from .records import bound_text

DEFAULT_PROCESS_TIMEOUT = 900
CAPTURE_LIMIT = 1 << 20  # 1 MiB total captured output
DRAIN_TIMEOUT = 30


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

    # Bounded capture: pump threads keep at most capture_limit bytes in
    # memory while still draining the pipe (a chatty child never blocks
    # on a full buffer, and never exhausts host memory).
    out_buf, err_buf = bytearray(), bytearray()
    pump_t = threading.Thread(target=_drain, args=(proc.stdout, out_buf, capture_limit), daemon=True)
    pump_e = threading.Thread(target=_drain, args=(proc.stderr, err_buf, capture_limit), daemon=True)
    pump_t.start()
    pump_e.start()
    if input_bytes is not None:
        try:
            proc.stdin.write(input_bytes)
            proc.stdin.close()
        except (BrokenPipeError, OSError):
            pass
    try:
        proc.wait(timeout=timeout)
        res.returncode = proc.returncode
    except subprocess.TimeoutExpired:
        res.timed_out = True
        _kill_tree(proc)
        try:
            proc.wait(timeout=DRAIN_TIMEOUT)
        except subprocess.TimeoutExpired:
            res.error = "child escaped kill"
            for stream in (proc.stdout, proc.stderr):
                try:
                    if stream:
                        stream.close()
                except OSError:
                    pass
    pump_t.join(timeout=DRAIN_TIMEOUT)
    pump_e.join(timeout=DRAIN_TIMEOUT)
    out, err = bytes(out_buf), bytes(err_buf)

    res.duration_s = time.monotonic() - start
    res.stdout = bound_text(out.decode("utf-8", errors="replace"))
    res.stderr = bound_text(err.decode("utf-8", errors="replace"))
    return res


def _drain(stream, buf: bytearray, limit: int) -> None:
    """Drain the stream; keep at most `limit` bytes, discard the rest."""
    if stream is None:
        return
    try:
        while True:
            chunk = stream.read(65536)
            if not chunk:
                break
            if len(buf) < limit:
                buf += chunk[: limit - len(buf)]
    except (OSError, ValueError):
        pass
    finally:
        try:
            stream.close()
        except OSError:
            pass


def _kill_tree(proc: subprocess.Popen) -> None:
    try:
        os.killpg(proc.pid, signal.SIGKILL)
        return
    except ProcessLookupError:
        return
    except PermissionError:
        pass
    except OSError:
        pass
    # EPERM on killpg: contained children run under another uid (nobody
    # rung). Escalate once via passwordless sudo to kill the group.
    try:
        subprocess.run(
            ["sudo", "-n", "kill", "-s", "KILL", "--", f"-{proc.pid}"],
            capture_output=True, timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired):
        pass
    try:
        proc.kill()
    except OSError:
        pass
