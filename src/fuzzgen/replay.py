"""replay: rebuild the lane binary in a fresh worktree and re-run the input."""

from __future__ import annotations

import json
import shutil
import sys
import tempfile
from pathlib import Path

from . import config, contain, gitops, stackhash
from .cli import EXIT_OK, EXIT_PARTIAL, Stopped
from .probe import probe_signature
from .selectors import parse_selector


def run(args) -> int:
    record_dir = Path(args.record_dir).resolve()
    run_json = record_dir / "run.json"
    if not run_json.is_file():
        raise Stopped(f"{run_json} missing")
    try:
        rec = json.loads(run_json.read_text())
    except json.JSONDecodeError as exc:
        raise Stopped(f"{run_json} is not JSON: {exc}")
    if not rec.get("git_sha"):
        raise Stopped("record has no git_sha; cannot pin the replay revision")

    input_path = record_dir / "min.bin"
    if not input_path.is_file():
        input_path = record_dir / "input.bin"
    if not input_path.is_file():
        raise Stopped("record dir has no input.bin or min.bin")

    repo = Path(rec.get("repo_path") or "")
    if not repo.is_dir():
        raise Stopped(
            f"replay needs the repo at {repo} (run.json repo_path); "
            "records are portable across worktrees, not machines"
        )
    if rec.get("lang") != "go":
        raise Stopped(f"replay for {rec.get('lang')} lands with its lane")
    try:
        sel = parse_selector(rec["target"], "go")
    except (KeyError, ValueError) as exc:
        raise Stopped(f"malformed record target: {exc}")

    mech, denied, _ = contain.detect()
    if mech == contain.MECH_REFUSE:
        raise Stopped("no containment mechanism for the replay build")
    work_root = config.work_root(mechanism=mech)
    try:
        worktree, _ = gitops.worktree_add_detached(
            repo, sha=rec["git_sha"], work_root=work_root
        )
    except gitops.GitError as exc:
        raise Stopped(f"replay worktree add failed: {exc}")
    work_dir = Path(tempfile.mkdtemp(dir=work_root, prefix="replay-"))
    try:
        from .lanes import go as golane

        pres = probe_signature(sel, worktree)
        if pres.status != "OK":
            raise Stopped(f"replay probe failed: {pres.reason}")
        gen = golane.gen_harness(sel, pres, worktree)
        if gen.status != "OK":
            raise Stopped(f"replay gen failed: {gen.reason}")
        golane.provision_for_rung(mech, worktree, work_dir)
        from . import seeder

        staged = (
            gen.pkg_dir / "testdata" / "fuzz" / gen.fuzz_name / "replay-input"
        )
        staged.parent.mkdir(parents=True, exist_ok=True)
        golane.provision_for_rung(mech, staged.parent)
        arg_kind = "string" if (pres.args or [""])[0] == "string" else "bytes"
        staged.write_text(seeder.go_fuzz_v1(input_path.read_bytes(), kind=arg_kind))
        res = golane.replay_once(
            worktree, gen.pkg_dir, gen.fuzz_name, staged, mech, work_dir
        )
        if res.error or res.timed_out:
            raise Stopped(f"replay run failed: {res.error or 'timeout'}")
        stderr = res.stderr + res.stdout
        kind = stackhash.classify_kind("go", stderr, res.returncode)
        frames = stackhash.go_stack(stderr)
        reproduced = bool(frames) or "panic" in stderr or "fatal error" in stderr
        sys.stderr.write(
            f"fuzzgen: replay {rec['target']}: "
            f"{'reproduced' if reproduced else 'did not reproduce'} "
            f"(kind={kind}, mechanism={mech})\n"
        )
        if reproduced:
            sys.stderr.write(
                f"fuzzgen: top frames: {', '.join(frames[:3]) or 'none'}\n"
            )
        return EXIT_OK if reproduced else EXIT_PARTIAL
    finally:
        gitops.worktree_remove(repo, worktree)
        shutil.rmtree(work_dir, ignore_errors=True)
