"""seed stage: collect the corpus and emit engine-native seed dirs."""

from __future__ import annotations

import sys
from pathlib import Path

from . import contain, gitops, records, seeder
from .cli import EXIT_OK, EXIT_PARTIAL, Stopped
from .gen import prepare
from .probe import probe_signature


def run(args) -> int:
    repo, sel, mechanism, denied, sha, worktree, out_root, warnings = prepare(args)
    status = "OK"
    reason = None
    n_seeds = 0
    try:
        probe_res = probe_signature(sel, worktree)
        if probe_res.status != "OK":
            status, reason = probe_res.status, probe_res.reason
        else:
            res = seeder.collect_seeds(
                worktree, max_len=getattr(args, "max_len", None)
            )
            seeder.merge_mode_seeds(res, probe_res.mode)
            out = records.out_dir_for(out_root, sel.lang, repo.name, sha, sel.raw)
            n_seeds = seeder.write_corpus(res.seeds, out / "corpus")
            notes = []
            if probe_res.mode == "struct" or (probe_res.args and len(probe_res.args) > 1):
                notes.append(
                    "struct mode seeds raw with a low-yield note "
                    "(no serializer for arbitrary/Consumer encodings)"
                )
            elif sel.lang == "go" and probe_res.kind in ("bytes", "string"):
                from .lanes import go as golane
                from .selectors import go_package_dir

                pkg_dir = go_package_dir(worktree, sel.package)
                fuzz = golane.fuzz_name(sel, pkg_dir)
                seeder.write_go_testdata(res.seeds, pkg_dir, fuzz)
            if res.skipped_symlinks:
                notes.append(f"{res.skipped_symlinks} symlink(s) skipped")
            if res.skipped_undecodable:
                notes.append(f"{res.skipped_undecodable} undecodable literal(s) skipped")
            if res.skipped_oversize:
                notes.append(f"{res.skipped_oversize} oversize seed(s) skipped")
            reason = "; ".join(notes) if notes else None
    finally:
        gitops.worktree_remove(repo, worktree)
        for w in warnings:
            sys.stderr.write(f"fuzzgen: warning: {w}\n")
    if status == "OK":
        sys.stderr.write(f"fuzzgen: {sel.raw}: {n_seeds} seed(s)\n")
        if reason:
            sys.stderr.write(f"fuzzgen: {reason}\n")
        return EXIT_OK
    if reason:
        sys.stderr.write(f"fuzzgen: {sel.raw}: {status}: {reason}\n")
    return EXIT_PARTIAL
