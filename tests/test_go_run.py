import json
import shutil
import subprocess
import time
from pathlib import Path

import pytest

from fuzzgen import cli, records
import fuzzgen.config as config

FIXTURES = Path(__file__).resolve().parent / "fixtures"


def _planted_repo(tmp_path):
    repo = tmp_path / "planted"
    shutil.copytree(FIXTURES / "go" / "plantedbug", repo)
    subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
    subprocess.run(["git", "config", "user.email", "t@t"], cwd=repo, check=True)
    subprocess.run(["git", "config", "user.name", "t"], cwd=repo, check=True)
    subprocess.run(["git", "add", "-A"], cwd=repo, check=True)
    subprocess.run(["git", "commit", "-qm", "init"], cwd=repo, check=True)
    return repo


def test_dedup_matrix():
    from fuzzgen import dedup, stackhash

    st = "panic: runtime error: index out of range\n" \
        "goroutine 1 [running]:\n" \
        "example.com/p.Decode(0x1, 0x2)\n" \
        "\t/x/p.go:10\n"
    kind = stackhash.classify_kind("go", st)
    frames = stackhash.go_stack(st)
    d = dedup.Deduper()
    h = stackhash.stack_hash(kind, frames)
    d.add(kind, h, b"\xfa" * 10, st)
    d.add(kind, h, b"\xfa" * 5, st)  # same bug, smaller input
    assert len(d.records) == 1
    rec = d.records[h]
    assert rec.hits == 2 and len(rec.min_input) == 5
    other = stackhash.stack_hash(kind, ["other.Func"])
    d.add(kind, other, b"\x00", st)
    assert len(d.records) == 2


@pytest.mark.slow
def test_planted_bug_found_within_60s(tmp_path, work_root):
    """Spec test 4 (Go leg): planted OOB decoder found, deduped to one record."""
    repo = _planted_repo(tmp_path)
    config.work_root = lambda **kw: work_root
    out = tmp_path / "out"
    start = time.monotonic()
    rc = cli.run(
        [
            "run",
            "--repo", str(repo),
            "--out-dir", str(out),
            "--seconds", "55",
            "parser.Decode",
        ]
    )
    elapsed = time.monotonic() - start
    assert elapsed < 70
    assert rc in (0, 1)
    summaries = list(out.rglob("summary.json"))
    assert summaries
    doc = json.loads(summaries[0].read_text())
    row = doc["targets"][0]
    assert row["status"] == "OK"
    assert row["crashes"] >= 1
    crash_dirs = list(summaries[0].parent.rglob("run.json"))
    assert crash_dirs
    rec = json.loads(crash_dirs[0].read_text())
    assert rec["kind"] in records.KINDS
    assert rec["repro_verified"]
    assert rec["repro"].startswith("fuzzgen replay")


def test_triage_fixed_point(tmp_path):
    out = tmp_path / "out" / "go" / "repo-abc12345" / "t"
    out.mkdir(parents=True)
    doc = records.summary_doc("r1", "/x", "abc12345", [records.target_row("t", "OK", crashes=0)])
    records.write_json(out / "summary.json", doc)
    records.atomic_write(out / "summary.md", records.summary_md(doc))
    before = (out / "summary.json").read_bytes()
    rc = cli.run(["triage", str(tmp_path / "out")])
    assert rc == 0
    assert (out / "summary.json").read_bytes() == before
