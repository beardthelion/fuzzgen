"""run stage: compose gen+seed when absent, then fuzz, harvest, record."""

from __future__ import annotations

import os
import shutil
import sys
import tempfile
import time
from pathlib import Path

from . import config, contain, dedup, gitops, records, runner, seeder, stackhash
from .cli import EXIT_OK, EXIT_PARTIAL, Stopped
from .gen import prepare
from .probe import probe_signature
from .selectors import parse_selector

MAX_REPLAYS = 256  # bound post-harvest replay work per run


def _run_fields(sel, repo, sha, mechanism, denied, worktree, out_dir, run_id,
                probe_res, reach_by):
    return dict(
        target=sel.raw,
        lang=sel.lang,
        mode=probe_res.mode,
        run_id=run_id,
        repo_path=str(repo),
        git_sha=sha,
        worktree_path=str(worktree),
        toolchain={"probe": probe_res.mode or "unknown"},
        containment=mechanism,
        networkDenied=denied,
        reach_by=reach_by or "unknown",
        args=probe_res.args or [],
    )


def run(args) -> int:
    # Parse the selector before any worktree exists: a bad selector must
    # not leak a marked worktree that refuses every later run.
    try:
        sel = parse_selector(args.target, getattr(args, "lang", None))
    except ValueError as exc:
        raise Stopped(str(exc))
    repo, sel, mechanism, denied, sha, worktree, out_root, warnings = prepare(args, sel=sel)
    status = "OK"
    reason = None
    n_crashes = 0
    run_id = os.environ.get("FUZZGEN_RUN_ID") or f"run-{int(time.time())}"
    out_dir = records.out_dir_for(out_root, sel.lang, repo.name, sha, sel.raw)
    work_dir = Path(
        tempfile.mkdtemp(dir=config.work_root(mechanism=mechanism), prefix="run-")
    )
    if mechanism == contain.MECH_NOBODY:
        work_dir.chmod(0o777)
    try:
        if sel.lang != "go":
            status, reason = "NEEDS-HAND", f"run for {sel.lang} lands with its lane"
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
                    fields = _run_fields(
                        sel, repo, sha, mechanism, denied, worktree, out_dir,
                        run_id, probe_res, getattr(args, "reach_by", None),
                    )
                    status, reason, n_crashes = _run_go(
                        args, golane, sel, gen, worktree, work_dir, mechanism,
                        out_dir, fields,
                    )
    finally:
        gitops.worktree_remove(repo, worktree)
        shutil.rmtree(work_dir, ignore_errors=True)
        for w in warnings:
            sys.stderr.write(f"fuzzgen: warning: {w}\n")
    row = records.target_row(sel.raw, status, lang=sel.lang,
                             crashes=n_crashes, notes=reason or "")
    doc = records.summary_doc(run_id, str(repo), sha, [row])
    try:
        records.write_json(out_dir / "summary.json", doc)
        records.atomic_write(out_dir / "summary.md", records.summary_md(doc))
    except OSError as exc:
        sys.stderr.write(f"fuzzgen: error: summary write failed: {exc}\n")
        # No canonical summary means no durable result; never report OK.
        return EXIT_PARTIAL
    if reason:
        sys.stderr.write(f"fuzzgen: {sel.raw}: {status}: {reason}\n")
    return EXIT_OK if status == "OK" else EXIT_PARTIAL


def _run_go(args, golane, sel, gen, worktree, work_dir, mechanism, out_dir, fields):
    """Fuzz loop + harvest + replay + dedup + records for one target."""
    pkg_dir = gen.pkg_dir
    fuzz = gen.fuzz_name

    seeds = seeder.collect_seeds(worktree, max_len=getattr(args, "max_len", None))
    seeder.merge_mode_seeds(seeds, fields.get("mode"))
    try:
        seeder.write_corpus(seeds.seeds, out_dir / "corpus")
        if fields.get("mode") == "bytes" and len(fields.get("args") or []) <= 1:
            kind = "string" if (fields.get("args") or [""])[0] == "string" else "bytes"
            seeder.write_go_testdata(seeds.seeds, pkg_dir, fuzz, kind=kind)
    except OSError as exc:
        return "DISK-CAP", f"corpus write failed: {exc}", 0

    # Provision only after all host-side writes: dirs created above would be
    # nobody-unwritable otherwise.
    golane.provision_for_rung(mechanism, worktree, work_dir)

    seconds = getattr(args, "seconds", config.DEFAULT_FUZZ_SECONDS)
    deadline = time.monotonic() + seconds
    deduper = dedup.Deduper()
    stage = work_dir / "stage"
    interrupted = False
    replayed = 0

    while True:
        remaining = int(deadline - time.monotonic())
        if remaining <= 0:
            break
        before = golane.testdata_files(pkg_dir, fuzz)
        res = golane.fuzz_round(
            worktree, pkg_dir, fuzz, remaining, mechanism, work_dir,
            race=getattr(args, "race", False),
            jobs=getattr(args, "jobs", 1) or 1,
            rss_limit_mb=getattr(args, "rss_limit_mb", None),
        )
        crashers = golane.harvest_crashers(pkg_dir, fuzz, stage, before=before)
        try:
            golane.harvest_gocache(work_dir, fuzz, out_dir / "corpus")
        except OSError as exc:
            return "DISK-CAP", f"corpus sweep failed: {exc}", len(deduper.records)
        # A nonzero exit is expected when the engine found a crasher; a
        # nonzero exit with no crasher is a failed run, not a clean one.
        if res.error or (res.returncode not in (0, 1) and not crashers):
            reason = res.error or (res.stderr or res.stdout or "fuzz round failed")[-400:]
            return "RUN-FAIL", reason, len(deduper.records)
        if res.returncode != 0 and not crashers and not res.timed_out:
            reason = (res.stderr or res.stdout or "fuzz round failed")[-400:]
            return "RUN-FAIL", reason, 0
        for c in crashers:
            if replayed >= MAX_REPLAYS or time.monotonic() > deadline + 120:
                break
            replayed += 1
            data = golane.crasher_input(c)
            rep = golane.replay_once(
                worktree, pkg_dir, fuzz, c, mechanism, work_dir
            )
            if rep.error or rep.timed_out:
                continue  # replay infra failure: no evidence, no record
            stderr = rep.stderr + rep.stdout
            kind = stackhash.classify_kind("go", stderr, rep.returncode)
            frames = stackhash.go_stack(stderr)
            verified = bool(frames) or "panic" in stderr or "fatal error" in stderr
            if not verified:
                continue  # engine artifacts that do not reproduce are not crashes
            shash = stackhash.stack_hash(kind, frames, stderr)
            rec = deduper.add(kind, shash, data, stderr)
            rec.repro_verified = True
        if res.timed_out:
            interrupted = True
            break
        if not crashers:
            break  # engine finished its box without new crashers

    try:
        for rec in deduper.records.values():
            dedup.write_crash_record(out_dir, rec, fields)
    except OSError as exc:
        return "DISK-CAP", f"record write failed: {exc}", len(deduper.records)

    _resource_records(args, golane, pkg_dir, fuzz, worktree, work_dir,
                      mechanism, out_dir, fields, deduper.records)

    status = "INTERRUPTED" if interrupted else "OK"
    return status, None, len(deduper.records)


RESOURCE_KINDS = {
    "out-of-memory", "allocation-size-too-big", "capacity-overflow",
    "timeout", "slow-unit",
}


def _resource_records(args, golane, pkg_dir, fuzz, worktree, work_dir,
                      mechanism, out_dir, fields, recs) -> None:
    """Measured replays for resource-class deaths -> resource/<id>/ records."""
    from . import resource as _res

    for i, (shash, rec) in enumerate(sorted(recs.items())):
        if rec.kind not in RESOURCE_KINDS or not rec.min_input:
            continue
        tdir = pkg_dir / "testdata" / "fuzz" / fuzz
        tdir.mkdir(parents=True, exist_ok=True)
        staged = tdir / f"resource-{shash}"
        arg_kind = "string" if (fields.get("args") or [""])[0] == "string" else "bytes"
        staged.write_text(seeder.go_fuzz_v1(rec.min_input, kind=arg_kind))
        rel = f"./{pkg_dir.relative_to(worktree)}"
        cmd = ["go", "test", "-run", f"^{fuzz}$", "-count", "1", rel]
        mem = getattr(args, "rss_limit_mb", None)
        env = {"GOMEMLIMIT": f"{mem}MiB"} if mem else {}
        argv = contain.contained_argv(
            mechanism, cmd, worktree, work_dir,
            env=golane._go_env(work_dir, env),
            rlimits=contain.default_rlimits(mem_mb=mem),
        )
        measure = _res.measure_replay(argv, cwd=worktree, env=None, mem_max_mb=mem)
        staged.unlink(missing_ok=True)
        fields_r = dict(fields, kind=rec.kind)
        try:
            _res.write_resource_record(
                out_dir, f"oom-{i}", fields_r, measure,
                fields.get("reach_by"), rec.min_input,
            )
        except OSError:
            pass
