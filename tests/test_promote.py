import json
import subprocess
from pathlib import Path

import pytest

from fuzzgen import cli, promote, records


def _record_tree(tmp_path, repo):
    out = tmp_path / "out" / "go" / f"{repo.name}-abc12345" / "t"
    d = out / "crashes" / "deadbeef" 
    d.mkdir(parents=True)
    (d / "stack.txt").write_text("panic: x\n\t/x/parser.go:42\n")
    (d / "min.bin").write_bytes(b"\xfa")
    rec = records.run_record(
        target="parser.Decode", lang="go", kind="panic",
        stack_hash="deadbeefcafe1234", repro_verified=True,
        run_id="run-1", repo_path=str(repo),
    )
    records.write_json(d / "run.json", rec)
    return tmp_path / "out"


def _repo(tmp_path):
    repo = tmp_path / "target"
    (repo / "x").mkdir(parents=True)
    (repo / "x" / "parser.go").write_text("package x\n")
    return repo


def test_promote_writes_schema_row(tmp_path):
    repo = _repo(tmp_path)
    out = _record_tree(tmp_path, repo)
    rc = cli.run(["promote", str(out), "--repo", str(repo)])
    assert rc == 0
    rows = list((repo / ".clawpatch" / "findings").glob("fnd_*.json"))
    assert len(rows) == 1
    row = json.loads(rows[0].read_text())
    assert tuple(sorted(row.keys())) == tuple(sorted(promote.SCHEMA_FIELDS))
    assert row["findingId"].startswith("fnd_fuzzgen_")
    assert row["category"] == "fuzz"
    assert row["severity"] == "low"
    assert row["confidence"] == "high"  # repro_verified
    assert row["createdByRunId"] == "run-1"


def test_promote_dedups_on_key(tmp_path):
    repo = _repo(tmp_path)
    out = _record_tree(tmp_path, repo)
    assert cli.run(["promote", str(out), "--repo", str(repo)]) == 0
    assert cli.run(["promote", str(out), "--repo", str(repo)]) == 0
    rows = list((repo / ".clawpatch" / "findings").glob("fnd_*.json"))
    assert len(rows) == 1


def test_promote_resource_severity_and_confidence(tmp_path):
    repo = _repo(tmp_path)
    out = _record_tree(tmp_path, repo)
    d = tmp_path / "out" / "go" / f"{repo.name}-abc12345" / "t" / "resource" / "r1"
    d.mkdir(parents=True)
    rec = records.run_record(
        target="parser.Decode", lang="go", kind="out-of-memory",
        stack_hash="feedface12345678", ratio="RATIO: 10x",
        repro_verified=True, run_id="run-2", repo_path=str(repo),
    )
    records.write_json(d / "run.json", rec)
    rc = cli.run(["promote", str(out), "--repo", str(repo)])
    assert rc == 0
    rows = {json.loads(p.read_text())["severity"] for p in (repo / ".clawpatch" / "findings").glob("fnd_*.json")}
    assert "medium" in rows


def test_untrusted_stack_path_degrades(tmp_path):
    repo = _repo(tmp_path)
    out = _record_tree(tmp_path, repo)
    d = tmp_path / "out" / "go" / f"{repo.name}-abc12345" / "t" / "crashes" / "deadbeef"
    (d / "stack.txt").write_text("panic: x\n\t../../etc/passwd:1\n")
    rc = cli.run(["promote", str(out), "--repo", str(repo)])
    assert rc == 0
    row = json.loads(
        next((repo / ".clawpatch" / "findings").glob("fnd_*.json")).read_text()
    )
    assert row["evidence"]["startLine"] == 0
    assert "unsymbolized" in row["evidence"]["note"]
