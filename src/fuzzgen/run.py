"""run stage: compose gen+seed when absent, then fuzz, harvest, record."""

from __future__ import annotations

import os
import sys
import time
from pathlib import Path

from . import config, contain, dedup, gitops, records, runner, seeder, stackhash
from .cli import EXIT_OK, EXIT_PARTIAL, Stopped
from .gen import prepare
from .probe import probe_signature


def _run_fields(sel, repo, sha, mechanism, denied, worktree, out_dir, run_id):
    return dict(
        target=sel.raw,
        lang=sel.lang,
        mode=None,
        run_id=run_id,
        repo_path=str(repo),
        git_sha=sha,
        worktree_path=str(worktree),
        toolchain={},
        containment=mechanism,
        networkDenied=denied,
        repro=f"fuzzgen replay {out_dir}",
    )


def run(args) -> int:
    repo, sel, mechanism, denied, sha, worktree, out_root, warnings = prepare(args)
    status = "OK"
    reason = None
    n_crashes = 0
    run_id = os.environ.get("FUZZGEN_RUN_ID") or f"run-{int(time.time())}"
    out_dir = records.out_dir_for(out_root, sel.lang, repo.name, sha, sel.raw)
    work_dir = Path(
        __import__("tempfile").mkdtemp(
            dir=config.work_root(mechanism=mechanism), prefix="run-"
        )
    )
    if mechanism == contain.MECH_NOBODY:
        work_dir.chmod(0o777)
    try:
        if sel.lang != "go":
            raise Stopped(f"run for {sel.lang} lands with its lane (only go implemented)")
        from .lanes import go as golane

        probe_res = probe_signature(sel, worktree)
        if probe_res.status != "OK":
            status, reason = probe_res.status, probe_res.reason
        else:
            gen = golane.gen_harness(sel, probe_res, worktree)
            if gen.status != "OK":
                status, reason = gen.status, gen.reason
            else:
                fields = _run_fields(
                    sel, repo, sha, mechanism, denied, worktree, out_dir, run_id
                )
                fields["mode"] = probe_res.mode
                status, reason, n_crashes = _run_go(
                    args, golane, sel, gen, worktree, work_dir, mechanism,
                    out_dir, fields,
                )
    finally:
        gitops.worktree_remove(repo, worktree)
        for w in warnings:
            sys.stderr.write(f"fuzzgen: warning: {w}\n")
    row = records.target_row(sel.raw, status, lang=sel.lang,
                             crashes=n_crashes, notes=reason or "")
    doc = records.summary_doc(run_id, str(repo), sha, [row])
    try:
        records.write_json(out_dir / "summary.json", doc)
        records.atomic_write(out_dir / "summary.md", records.summary_md(doc))
    except OSError as exc:
        sys.stderr.write(f"fuzzgen: warning: summary write failed: {exc}\n")
    if reason:
        sys.stderr.write(f"fuzzgen: {sel.raw}: {status}: {reason}\n")
    return EXIT_OK if status == "OK" else EXIT_PARTIAL


def _run_go(args, golane, sel, gen, worktree, work_dir, mechanism, out_dir, fields):
    """Fuzz loop + harvest + replay + dedup + records for one target."""
    pkg_dir = gen.pkg_dir
    fuzz = gen.fuzz_name

    seeds = seeder.collect_seeds(worktree, max_len=getattr(args, "max_len", None))
    seeder.merge_mode_seeds(seeds, fields.get("mode"))
    seeder.write_corpus(seeds.seeds, out_dir / "corpus")
    if fields.get("mode") in ("bytes",) and len(probe_args(fields)) <= 1:
        seeder.write_go_testdata(seeds.seeds, pkg_dir, fuzz)

    # Provision only after all host-side writes: dirs created above would be
    # nobody-unwritable otherwise.
    golane.provision_for_rung(mechanism, worktree, work_dir)

    seconds = getattr(args, "seconds", config.DEFAULT_FUZZ_SECONDS)
    deadline = time.monotonic() + seconds
    deduper = dedup.Deduper()
    stage = work_dir / "stage"
    interrupted = False

    while True:
        remaining = int(deadline - time.monotonic())
        if remaining <= 0:
            break
        before = golane.testdata_files(pkg_dir, fuzz)
        res = golane.fuzz_round(
            worktree, pkg_dir, fuzz, remaining, mechanism, work_dir,
            race=getattr(args, "race", False),
        )
        crashers = golane.harvest_crashers(pkg_dir, fuzz, stage, before=before)
        golane.harvest_gocache(work_dir, fuzz, out_dir / "corpus")
        if res.timed_out:
            interrupted = True
            break
        for c in crashers:
            data = golane.crasher_input(c)
            rep = golane.replay_once(
                worktree, pkg_dir, fuzz, c, mechanism, work_dir
            )
            stderr = rep.stderr + rep.stdout
            kind = stackhash.classify_kind("go", stderr, rep.returncode)
            frames = stackhash.go_stack(stderr)
            verified = bool(frames) or "panic" in stderr or "fatal error" in stderr
            if not verified:
                continue  # engine artifacts that do not reproduce are not crashes
            shash = stackhash.stack_hash(kind, frames)
            rec = deduper.add(kind, shash, data, stderr)
            rec.repro_verified = True
        if not crashers:
            break  # engine finished its box without new crashers

    for rec in deduper.records.values():
        dedup.write_crash_record(out_dir, rec, fields)

    status = "INTERRUPTED" if interrupted else "OK"
    return status, None, len(deduper.records)


def probe_args(fields: dict) -> list:
    return fields.get("args") or []
