"""gen stage: worktree -> probe -> emit harness -> contained build check."""

from __future__ import annotations

import os
import sys
from pathlib import Path

from . import config, contain, gitops, records
from .cli import EXIT_OK, EXIT_PARTIAL, Stopped
from .probe import probe_signature
from .selectors import parse_selector


def prepare(args, work_root: Path | None = None, sel=None):
    """Shared preamble: repo, selector, mechanism, worktree."""
    repo = Path(args.repo).resolve()
    if not (repo / ".git").exists():
        raise Stopped(f"{repo} is not a git checkout")
    if getattr(args, "no_containment", False):
        if not contain.allow_no_containment():
            raise Stopped(
                "--no-containment requires FUZZGEN_ALLOW_NO_CONTAINMENT=1"
            )
        mechanism, denied = contain.MECH_NONE, False
    else:
        mechanism, denied, note = contain.detect()
        if mechanism == contain.MECH_REFUSE:
            raise Stopped("no containment mechanism available; refusing to build target code")
    # Selector parses before any worktree exists: a bad selector must not
    # leave marked residue that refuses every later run.
    sel = sel or parse_selector(args.target, getattr(args, "lang", None))
    sha = gitops.head_sha(repo)
    warnings: list[str] = []
    work_root = work_root or config.work_root(mechanism=mechanism)
    leftovers = gitops.leftover_worktrees(work_root)
    if leftovers:
        raise Stopped(f"leftover worktree state at {leftovers[0]}; remove it manually")
    try:
        submodules = getattr(args, "submodules", None)
        paths = [p for p in submodules.split(",") if p] if submodules else None
        worktree, warns = gitops.worktree_add_detached(
            repo, sha=sha, work_root=work_root, submodule_paths=paths
        )
    except gitops.GitError as exc:
        raise Stopped(f"worktree add failed: {exc}")
    warnings += warns
    out_root = Path(args.out_dir).resolve() if args.out_dir else config.default_out_dir()
    return repo, sel, mechanism, denied, sha, worktree, out_root, warnings


def _mechanism_record(mechanism: str) -> str:
    return mechanism


def run(args) -> int:
    repo, sel, mechanism, denied, sha, worktree, out_root, warnings = prepare(args)
    status = "OK"
    reason = None
    work_dir = None
    try:
        if sel.lang != "go":
            status, reason = "NEEDS-HAND", f"gen for {sel.lang} lands with its lane (only go implemented)"
        else:
            from .lanes import go as golane

            probe_res = probe_signature(sel, worktree)
            if probe_res.status != "OK":
                status, reason = probe_res.status, probe_res.reason
            else:
                gen = golane.gen_harness(sel, probe_res, worktree)
                if gen.status != "OK":
                    status, reason = gen.status, gen.reason
                else:
                    work_dir = Path(
                        __import__("tempfile").mkdtemp(
                            dir=config.work_root(mechanism=mechanism), prefix="gen-"
                        )
                    )
                    chk = golane.build_check(worktree, gen.pkg_dir, mechanism, work_dir)
                    status, reason = chk.status, chk.reason
                    if status == "OK":
                        out = records.out_dir_for(out_root, "go", repo.name, sha, sel.raw)
                        harness_dst = out / "harness" / gen.harness_path.name
                        harness_dst.parent.mkdir(parents=True, exist_ok=True)
                        harness_dst.write_text(gen.harness_path.read_text())
    finally:
        row = records.target_row(
            sel.raw,
            status,
            lang=sel.lang,
            fuzz_name=locals().get("gen") and locals()["gen"].fuzz_name or "",
            notes=reason or ("; ".join(warnings) if warnings else ""),
        )
        doc = records.summary_doc(
            run_id=os.environ.get("FUZZGEN_RUN_ID", "gen-local"),
            repo_path=str(repo),
            git_sha=sha,
            targets=[row],
        )
        summary_ok = True
        try:
            out = records.out_dir_for(out_root, sel.lang, repo.name, sha, sel.raw)
            records.write_json(out / "summary.json", doc)
            records.atomic_write(out / "summary.md", records.summary_md(doc))
        except Exception as exc:
            summary_ok = False
            sys.stderr.write(f"fuzzgen: error: summary write failed: {exc}\n")
        if work_dir:
            import shutil
            shutil.rmtree(work_dir, ignore_errors=True)
        gitops.worktree_remove(repo, worktree)
        if status == "OK" and not summary_ok:
            status, reason = "RUN-FAIL", "summary write failed"
        for w in warnings:
            sys.stderr.write(f"fuzzgen: warning: {w}\n")
        if reason:
            sys.stderr.write(f"fuzzgen: {sel.raw}: {status}: {reason}\n")
    return EXIT_OK if status == "OK" else EXIT_PARTIAL
