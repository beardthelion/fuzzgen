import json
from pathlib import Path

from fuzzgen import cli, records, stackhash, triage


def _crash_dir(root: Path, name: str, stack: str, min_bin: bytes, hits: int = 1):
    d = root / name
    d.mkdir(parents=True)
    (d / "stack.txt").write_text(stack)
    (d / "min.bin").write_bytes(min_bin)
    (d / "input.bin").write_bytes(min_bin * 2)
    rec = records.run_record(
        target="p.Decode", lang="go", kind="panic",
        stack_hash=name, hits=hits, repo_path="/r", git_sha="abc",
    )
    records.write_json(d / "run.json", rec)
    return d


def test_triage_merges_colliding_hashes(tmp_path):
    stack = "panic: x\ngoroutine 1 [running]:\np.Decode(0x1)\n\t/x/p.go:1\n"
    target = tmp_path / "out" / "go" / "r-abc" / "t"
    _crash_dir(target / "crashes", "h1", stack, b"\x01" * 9)
    _crash_dir(target / "crashes", "h2", stack, b"\x01" * 3, hits=2)
    doc = records.summary_doc("r", "/r", "abc", [records.target_row("t", "OK", crashes=2)])
    records.write_json(target / "summary.json", doc)
    records.atomic_write(target / "summary.md", records.summary_md(doc))

    rc = cli.run(["triage", str(tmp_path / "out")])
    assert rc == 0
    dirs = [d.name for d in (target / "crashes").iterdir() if d.is_dir()]
    assert len(dirs) == 1  # two dirs collapsed to the recomputed hash
    real = stackhash.stack_hash(
        stackhash.classify_kind("go", stack), stackhash.go_stack(stack), stack)
    assert dirs[0] == real
    rec = json.loads((target / "crashes" / real / "run.json").read_text())
    assert rec["hits"] == 3
    doc2 = json.loads((target / "summary.json").read_text())
    assert doc2["targets"][0]["crashes"] == 1
    # Fixed point: a second triage leaves the tree identical.
    snapshot = sorted(p.name for p in (target / "crashes").iterdir())
    assert cli.run(["triage", str(tmp_path / "out")]) == 0
    assert sorted(p.name for p in (target / "crashes").iterdir()) == snapshot


def test_triage_counts_corrupt(tmp_path):
    target = tmp_path / "out" / "go" / "r-abc" / "t"
    target.mkdir(parents=True)
    (target / "summary.json").write_text("{not json")
    assert cli.run(["triage", str(tmp_path / "out")]) == cli.EXIT_PARTIAL


def test_resource_records_for_oom_kind(tmp_path):
    """Resource kinds get a measured resource/<id>/ record written."""
    import subprocess
    from fuzzgen import resource, run as runmod

    # Sanity on the record writer alone: measured replay + RATIO line.
    m = resource._getrusage_measure(
        ["python3", "-c", "x=b'0'*5_000_000"], tmp_path, {}, None
    )
    d = resource.write_resource_record(
        tmp_path / "out", "oom-0",
        dict(target="t", lang="go", reach_by="HTTP"), m, "HTTP", b"\x01"
    )
    rec = json.loads((d / "run.json").read_text())
    assert "RATIO:" in rec["ratio"]
    assert rec["reach_by"].startswith("REACH_BY:")
    assert rec["capped"] is False
    assert rec["measure_source"] == "getrusage"
