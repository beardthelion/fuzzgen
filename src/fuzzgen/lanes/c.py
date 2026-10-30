"""C/C++ libFuzzer lane (KTD8).

clang -g -O1 -fno-omit-frame-pointer -fsanitize=fuzzer,address,undefined
-fno-sanitize-recover=all (default UBSan recovery evaporates findings).
Single-TU v1; anything beyond that is NEEDS-HAND. clang absent on a
machine records TOOL-MISSING, honest and skip-safe.
"""

from __future__ import annotations

import shutil
from dataclasses import dataclass
from pathlib import Path

from .. import contain, runner
from ..probe import ProbeResult
from ..selectors import Selector

TMPL = Path(__file__).resolve().parents[1] / "templates" / "c_fuzzer.c.tmpl"


@dataclass
class CGenResult:
    status: str
    harness_path: Path | None = None
    binary: Path | None = None
    reason: str | None = None


def clang_available() -> bool:
    return shutil.which("clang") is not None


def gen_harness(sel: Selector, worktree: Path, cflags=None, ldflags=None,
                includes=None, work_dir: Path | None = None) -> CGenResult:
    src = worktree / sel.package
    if not src.is_file():
        return CGenResult("PROBE-FAIL", reason=f"{sel.package} missing")
    harness = src.parent / f"fuzzgen_{sel.name}.c"
    harness.write_text(TMPL.read_text().replace("{{.Func}}", sel.name))
    return CGenResult("OK", harness_path=harness)


def build(worktree: Path, gen: CGenResult, sel: Selector, work_dir: Path,
          mechanism: str, cflags=None, ldflags=None, includes=None) -> CGenResult:
    if not clang_available():
        return CGenResult("TOOL-MISSING", reason="clang absent")
    src = worktree / sel.package
    out = work_dir / f"fuzzgen_{sel.name}"
    cmd = ["clang", "-g", "-O1", "-fno-omit-frame-pointer",
           "-fsanitize=fuzzer,address,undefined", "-fno-sanitize-recover=all",
           str(gen.harness_path), str(src), "-o", str(out)]
    for inc in includes or []:
        cmd += ["-I", inc]
    if cflags:
        cmd += cflags.split()
    if ldflags:
        cmd += ldflags.split()
    argv = contain.contained_argv(mechanism, cmd, worktree, work_dir, env={"HOME": str(work_dir)})
    res = runner.run_bounded(argv, timeout=600, cwd=worktree)
    if res.returncode != 0:
        return CGenResult("BUILD-FAIL", reason=res.stderr)
    return CGenResult("OK", binary=out)


def run_argv(binary: Path, corpus: Path, stage: Path, seconds: int, jobs: int) -> list[str]:
    """-fork=<jobs> -ignore_crashes=1 keeps multi-crash alive (KTD5)."""
    return [str(binary), "-artifact_prefix", f"{stage}/",
            "-max_total_time", str(seconds),
            "-fork", str(jobs), "-ignore_crashes=1", "-ignore_ooms=1",
            "-ignore_timeouts=1", "-report_slow_units=10", str(corpus)]
