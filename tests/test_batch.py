import json
import shutil
import subprocess
from pathlib import Path

import pytest

from fuzzgen import cli, records, scope
import fuzzgen.config as config

FIXTURES = Path(__file__).resolve().parent / "fixtures"


def test_scope_grammar(tmp_path):
    f = tmp_path / "scope-boundary.md"
    f.write_text(
        "- parser.Decode TAINT: yes entry=HTTP\n"
        "- parser.Old TAINT: no\n"
        "- OUT-OF-SURFACE anything\n"
        "- parser.Other\n"
        "# comment\n"
    )
    res = scope.parse_scope(f)
    assert [(t.selector, t.entry) for t in res.targets] == [
        ("parser.Decode", "HTTP"),
        ("parser.Other", None),
    ]
    assert len(res.skipped) == 2


def _go_repo(tmp_path):
    repo = tmp_path / "go-target"
    shutil.copytree(FIXTURES / "go" / "basic", repo)
    subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
    subprocess.run(["git", "config", "user.email", "t@t"], cwd=repo, check=True)
    subprocess.run(["git", "config", "user.name", "t"], cwd=repo, check=True)
    subprocess.run(["git", "add", "-A"], cwd=repo, check=True)
    subprocess.run(["git", "commit", "-qm", "init"], cwd=repo, check=True)
    return repo


def test_all_over_two_targets(tmp_path, work_root, monkeypatch):
    repo = _go_repo(tmp_path)
    monkeypatch.setattr(config, "work_root", lambda **kw: work_root)
    out = tmp_path / "out"
    rc = cli.run(
        [
            "all", "--repo", str(repo), "--out-dir", str(out),
            "--seconds", "3",
            "codec.Nothing", "codec.Absent",  # NEEDS-HAND and PROBE-FAIL
        ]
    )
    doc = json.loads((out / "summary.json").read_text())
    statuses = {r["target"]: r["status"] for r in doc["targets"]}
    assert statuses["codec.Nothing"] == "NEEDS-HAND"
    assert statuses["codec.Absent"] == "PROBE-FAIL"
    assert rc == cli.EXIT_PARTIAL


def test_all_disk_cap(tmp_path, work_root, monkeypatch):
    repo = _go_repo(tmp_path)
    monkeypatch.setattr(config, "work_root", lambda **kw: work_root)
    out = tmp_path / "out"
    (out / "filler").mkdir(parents=True)
    (out / "filler" / "big.bin").write_bytes(b"x" * (3 << 20))
    rc = cli.run(
        [
            "all", "--repo", str(repo), "--out-dir", str(out),
            "--cap-mb", "1", "codec.Decode",
        ]
    )
    doc = json.loads((out / "summary.json").read_text())
    assert doc["targets"][0]["status"] == "DISK-CAP"


def test_all_empty_list_stops(tmp_path, work_root, monkeypatch):
    repo = _go_repo(tmp_path)
    monkeypatch.setattr(config, "work_root", lambda **kw: work_root)
    rc = cli.run(["all", "--repo", str(repo), "--out-dir", str(tmp_path / "o")])
    assert rc == cli.EXIT_ENV
