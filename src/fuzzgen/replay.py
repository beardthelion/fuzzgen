"""replay: re-execute a crash or resource record dir's input."""

from __future__ import annotations

import json
import sys
from pathlib import Path

from . import config, contain, gitops, records
from .cli import EXIT_OK, EXIT_PARTIAL, Stopped


def run(args) -> int:
    record_dir = Path(args.record_dir).resolve()
    run_json = record_dir / "run.json"
    if not run_json.is_file():
        raise Stopped(f"{run_json} missing")
    try:
        rec = json.loads(run_json.read_text())
    except json.JSONDecodeError as exc:
        raise Stopped(f"{run_json} is not JSON: {exc}")

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
    sys.stderr.write(
        f"fuzzgen: replay {rec['target']} ({rec.get('kind')}) "
        f"input={input_path.stat().st_size}B in {record_dir}\n"
    )
    sys.stderr.write(
        "fuzzgen: replay rebuild is not implemented yet "
        "(fresh worktree + lane replay lands with each lane's run support)\n"
    )
    return EXIT_PARTIAL
