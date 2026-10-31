"""Go lane: harness generation, seed emission, build check (bytes mode first).

The generated *_fuzz_test.go lands beside the package in the worktree and
is mirrored into the record tree's harness/ dir. Build checks run under
the KTD3 rung, compiling a target is executing untrusted code.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from .. import config, contain, runner
from ..probe import ProbeResult
from ..selectors import Selector, go_package_dir

TMPL_DIR = Path(__file__).resolve().parents[1] / "templates"


@dataclass
class GenResult:
    status: str  # OK | BUILD-FAIL | PROBE-FAIL | NEEDS-HAND | TOOL-MISSING
    harness_path: Path | None = None
    fuzz_name: str = ""
    pkg_dir: Path | None = None
    reason: str | None = None
    warnings: list[str] = None


def fuzz_name(sel: Selector, pkg_dir: Path) -> str:
    """FuzzGen<Name>, with collision avoidance against existing FuzzX names."""
    base = sel.name if not sel.recv else f"{sel.recv}{sel.name}"
    candidate = f"Fuzz{base}"
    names = {f"Fuzz{base}", f"FuzzGen{base}"}
    src = ""
    for p in pkg_dir.glob("*.go"):
        src += p.read_text(errors="replace")
    existing = set(re.findall(r"func\s+(Fuzz\w+)\s*\(", src))
    for cand in (candidate, f"FuzzGen{base}"):
        if cand not in existing:
            return cand
    i = 2
    while f"FuzzGen{base}{i}" in existing:
        i += 1
    return f"FuzzGen{base}{i}"


# testing.F fuzz parameters: the only types f.Fuzz accepts.
FUZZABLE_TYPES = {
    "string", "[]byte", "int", "int8", "int16", "int32", "int64",
    "uint", "uint8", "uint16", "uint32", "uint64", "rune", "byte",
    "float32", "float64", "bool",
}


def _call_expr(sel: Selector, kind: str, args: list[str]) -> tuple[str, str]:
    """(arg_decl, call lines) for the probed signature."""
    recv = sel.name
    if kind == "bytes" and (not args or "[]byte" in (args[0] or "")):
        return "data []byte", f"\t\t_ , _ = {recv}(data)\n" if _returns_two(sel) else f"\t\t{recv}(data)\n"
    if kind == "bytes":
        return "data []byte", f"\t\t{recv}(data)\n"
    if kind == "string":
        return "s string", f"\t\t{recv}(s)\n"
    if kind == "io-reader":
        return "data []byte", f"\t\t{recv}(bytes.NewReader(data))\n"
    if kind == "multi":
        decls = ", ".join(f"a{i} {t}" for i, t in enumerate(args))
        callargs = ", ".join(f"a{i}" for i in range(len(args)))
        return decls, f"\t\t{recv}({callargs})\n"
    return "data []byte", f"\t\t{recv}(data)\n"


def _returns_two(sel: Selector) -> bool:
    return False  # keep calls simple: results discarded via assignment-free call


def _needs_extra_import(kind: str) -> str:
    return 'import (\n\t"bytes"\n\t"testing"\n)\n' if kind == "io-reader" else 'import "testing"\n'


def render(sel: Selector, probe_res: ProbeResult, pkg_name: str, fuzz: str) -> str:
    tmpl = (TMPL_DIR / "go_bytes_fuzz_test.go.tmpl").read_text()
    arg_decl, call = _call_expr(sel, probe_res.kind, probe_res.args)
    body = tmpl.replace("{{.Package}}", pkg_name)
    body = body.replace('import "testing"', _needs_extra_import(probe_res.kind).rstrip())
    body = body.replace("{{.FuzzName}}", fuzz)
    body = body.replace("{{.ArgDecl}}", arg_decl)
    body = body.replace("{{.Call}}", call)
    # One f.Add per corpus entry matching the full param arity.
    kinds = probe_res.args or ["[]byte"]
    vals = []
    for arg in kinds:
        vals.append('""' if arg in ("string", "rune")
                    else "0" if arg.startswith(("int", "uint", "float", "byte", "bool"))
                    else '[]byte("")' if arg == "[]byte" else '""')
    if arg == "bool":
        vals[-1] = "false"
    if len(kinds) == 1 and kinds[0] == "[]byte":
        adds = '\tf.Add([]byte("seed"))\n'
    else:
        adds = f"\tf.Add({', '.join(vals)})\n"
    return body.replace("{{.Adds}}", adds)


def pkg_name_of(worktree: Path, pkg_dir: Path) -> str | None:
    """Package name via `go list`; None when it cannot be determined.

    A silently wrong package name produces a "found packages" build
    error later, so callers must treat None as NEEDS-HAND rather than
    fall back to "main".
    """
    from ..selectors import _GOLIST_ENV
    import os

    env = dict(_GOLIST_ENV)
    env["PATH"] = os.environ.get("PATH", "/usr/bin:/bin")
    env["HOME"] = os.environ.get("HOME", "/")
    rel = pkg_dir.relative_to(worktree)
    res = runner.run_bounded(
        ["go", "list", "-f", "{{.Name}}", f"./{rel}"],
        cwd=worktree, timeout=60, env=env,
    )
    if res.returncode == 0 and res.stdout.strip():
        return res.stdout.strip().splitlines()[-1]
    for p in sorted(pkg_dir.glob("*.go")):
        if p.is_symlink() or p.name.endswith("_test.go"):
            continue
        m = re.match(r"package\s+(\w+)", p.read_text(errors="replace"))
        if m:
            return m.group(1)
    return None


def provision_writable(path: Path) -> None:
    """nobody rung cannot write user-owned trees; the worktree is throwaway.

    Symlinks are skipped everywhere: a committed link must never redirect
    a chmod onto a host path outside the worktree.
    """
    import os
    import stat

    for dirpath, dirnames, filenames in os.walk(path, followlinks=False):
        dirnames[:] = [d for d in dirnames
                       if not os.path.islink(os.path.join(dirpath, d))]
        if not os.path.islink(dirpath):
            try:
                os.chmod(dirpath, stat.S_IRWXU | stat.S_IRWXG | stat.S_IRWXO)
            except OSError:
                pass
        for f in filenames:
            p = os.path.join(dirpath, f)
            if os.path.islink(p):
                continue
            try:
                os.chmod(p, stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP | stat.S_IWGRP | stat.S_IROTH | stat.S_IWOTH)
            except OSError:
                pass


def _confined_pkg_dir(worktree: Path, pkg_dir: Path) -> bool:
    import os

    try:
        return os.path.commonpath(
            [str(worktree.resolve()), str(pkg_dir.resolve())]
        ) == str(worktree.resolve())
    except ValueError:
        return False


def gen_harness(sel: Selector, probe_res: ProbeResult, worktree: Path) -> GenResult:
    """Emit the harness file beside the package in the worktree."""
    if probe_res.status != "OK":
        return GenResult(probe_res.status, reason=probe_res.reason)
    if sel.recv:
        return GenResult(
            "NEEDS-HAND",
            reason="method selector: receiver construction is target-specific",
        )
    try:
        pkg_dir = go_package_dir(worktree, sel.package)
    except FileNotFoundError as exc:
        return GenResult("PROBE-FAIL", reason=str(exc))
    if not _confined_pkg_dir(worktree, pkg_dir):
        return GenResult(
            "PROBE-FAIL",
            reason=f"resolved package dir {pkg_dir} escapes the worktree",
        )
    if probe_res.args and any(a not in FUZZABLE_TYPES for a in probe_res.args):
        return GenResult(
            "NEEDS-HAND",
            reason=f"arg types {probe_res.args} outside testing.F's supported set",
        )
    pname = pkg_name_of(worktree, pkg_dir)
    if pname is None:
        return GenResult(
            "NEEDS-HAND",
            reason=f"cannot determine package name in {pkg_dir}",
        )
    fuzz = fuzz_name(sel, pkg_dir)
    src = render(sel, probe_res, pname, fuzz)
    harness = pkg_dir / f"{fuzz.lower()}_fuzz_test.go"
    harness.write_text(src)
    return GenResult("OK", harness_path=harness, fuzz_name=fuzz, pkg_dir=pkg_dir)


def provision_for_rung(mechanism: str, *paths: Path) -> None:
    """nobody rung cannot write user-owned trees; provision before contained runs."""
    if mechanism == contain.MECH_NOBODY:
        for p in paths:
            if Path(p).exists():
                provision_writable(Path(p))


def build_check(
    worktree: Path,
    pkg_dir: Path,
    mechanism: str,
    work_dir: Path,
    extra_env: dict | None = None,
) -> GenResult:
    """Compile the package with tests under the containment rung."""
    provision_for_rung(mechanism, worktree, work_dir)
    rel = pkg_dir.relative_to(worktree) if str(pkg_dir).startswith(str(worktree)) else Path(".")
    go_cmd = ["go", "test", "-run", "^$", "-count", "0", f"./{rel}" if str(rel) != "." else "./..."]
    env = {"GOCACHE": str(work_dir / "gocache"), "GOPATH": str(work_dir / "gopath"),
           "HOME": str(work_dir), **(extra_env or {})}
    argv = contain.contained_argv(mechanism, go_cmd, worktree, work_dir, env=env,
                                  rlimits=contain.default_rlimits())
    res = runner.run_bounded(argv, timeout=600, cwd=worktree)
    if res.timed_out or res.error:
        return GenResult("RUN-FAIL", reason=res.stderr or res.error or "build check timeout")
    if res.returncode != 0:
        return GenResult("BUILD-FAIL", reason=res.stderr or res.stdout)
    return GenResult("OK")


def _go_env(work_dir: Path, extra: dict | None = None) -> dict:
    env = {
        "GOCACHE": str(work_dir / "gocache"),
        "GOPATH": str(work_dir / "gopath"),
        "GOMODCACHE": str(work_dir / "gomodcache"),
        "HOME": str(work_dir),
    }
    env.update(extra or {})
    return env


def fetch_deps(worktree: Path, work_dir: Path, jobs: int = 4) -> bool:
    """Host-side `go mod download` into the rung's GOMODCACHE.

    Fetch is a network phase run on the host (networkDenied rungs cannot
    download); the populated cache is then bound read-only into the
    contained build/fuzz so deps resolve with no network.
    """
    import os

    env = dict(os.environ, GOMODCACHE=str(work_dir / "gomodcache"),
               GOFLAGS="-mod=mod")
    res = runner.run_bounded(
        ["go", "mod", "download"], cwd=worktree, timeout=600, env=env
    )
    return res.returncode == 0


def fuzz_round(
    worktree: Path,
    pkg_dir: Path,
    fuzz: str,
    seconds: int,
    mechanism: str,
    work_dir: Path,
    race: bool = False,
    jobs: int = 1,
    rss_limit_mb: int | None = None,
) -> "runner.Result":
    """One go test -fuzz round under the containment rung."""
    rel = f"./{pkg_dir.relative_to(worktree)}"
    cmd = ["go", "test", "-run", "^$", "-fuzz", f"^{fuzz}$",
           "-fuzztime", f"{seconds}s", "-count", "1",
           f"-parallel={jobs}", rel]
    if race:
        cmd += ["-race"]
    env = _go_env(work_dir)
    if rss_limit_mb:
        env["GOMEMLIMIT"] = f"{rss_limit_mb}MiB"
    argv = contain.contained_argv(
        mechanism, cmd, worktree, work_dir, env=env,
        rlimits=contain.default_rlimits(mem_mb=rss_limit_mb, cpu_s=seconds + 120),
    )
    return runner.run_bounded(argv, timeout=seconds + 120, cwd=worktree)


def _safe_file(p: Path) -> bool:
    """Not a symlink and a regular file; contained code can plant links."""
    try:
        return p.is_file() and not p.is_symlink()
    except OSError:
        return False


def testdata_files(pkg_dir: Path, fuzz: str) -> set[Path]:
    src = pkg_dir / "testdata" / "fuzz" / fuzz
    if not src.is_dir() or src.is_symlink():
        return set()
    return {p for p in src.iterdir() if _safe_file(p)}


def harvest_crashers(pkg_dir: Path, fuzz: str, stage: Path, before: set[Path] | None = None) -> list[Path]:
    """Relocate crashers added since ``before``; seeds and stale files stay.

    Our own write_go_testdata seeds live in the same dir, so only files
    the fuzzer wrote during the round count as crashers. Symlinks planted
    by contained code are rejected before any read.
    """
    src = pkg_dir / "testdata" / "fuzz" / fuzz
    if not src.is_dir() or src.is_symlink():
        return []
    stage.mkdir(parents=True, exist_ok=True)
    moved = []
    for p in sorted(src.iterdir()):
        if not _safe_file(p) or p.name == "README" or (before and p in before):
            continue
        dst = stage / p.name
        dst.write_bytes(p.read_bytes())
        p.unlink()
        moved.append(dst)
    return moved


def harvest_gocache(work_dir: Path, fuzz: str, corpus_out: Path) -> int:
    """Sweep the interesting-corpus cache under GOCACHE/fuzz into corpus_out."""
    gocache = work_dir / "gocache" / "fuzz"
    n = 0
    if not gocache.is_dir():
        return 0
    corpus_out.mkdir(parents=True, exist_ok=True)
    for p in gocache.rglob("*"):
        if _safe_file(p):
            (corpus_out / p.name).write_bytes(p.read_bytes())
            n += 1
    return n


def replay_once(
    worktree: Path,
    pkg_dir: Path,
    fuzz: str,
    crash_file: Path,
    mechanism: str,
    work_dir: Path,
) -> "runner.Result":
    """Replay one input in a fresh contained process for a clean stack.

    The corpus dir is cleared first so only the staged file can produce a
    panic, repro_verified must attest THIS input, not any corpus entry.
    """
    tdir = pkg_dir / "testdata" / "fuzz" / fuzz
    tdir.mkdir(parents=True, exist_ok=True)
    stash = work_dir / "replay-stash"
    stash.mkdir(exist_ok=True)
    for p in tdir.iterdir():
        if _safe_file(p):
            p.rename(stash / p.name)
    staged = tdir / crash_file.name
    staged.write_bytes(crash_file.read_bytes())
    rel = f"./{pkg_dir.relative_to(worktree)}"
    cmd = ["go", "test", "-run", f"^{fuzz}$", "-count", "1", rel]
    argv = contain.contained_argv(
        mechanism, cmd, worktree, work_dir, env=_go_env(work_dir),
        rlimits=contain.default_rlimits(),
    )
    res = runner.run_bounded(argv, timeout=300, cwd=worktree)
    staged.unlink(missing_ok=True)
    for p in stash.iterdir():
        try:
            p.rename(tdir / p.name)
        except OSError:
            pass
    return res


def crasher_input(crash_file: Path) -> bytes:
    """Extract the raw input bytes from a go test fuzz v1 crasher file."""
    import re

    text = crash_file.read_text(errors="replace")
    for pat in (r'\[\]byte\("((?:[^"\\]|\\.)*)"\)', r'string\("((?:[^"\\]|\\.)*)"\)'):
        m = re.search(pat, text)
        if m:
            try:
                return m.group(1).encode().decode("unicode_escape").encode("latin-1")
            except (UnicodeDecodeError, UnicodeEncodeError):
                break
    m = re.search(r"int\((-?\d+)\)", text)
    if m:
        return m.group(1).encode()
    return crash_file.read_bytes()
