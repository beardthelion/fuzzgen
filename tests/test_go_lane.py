import shutil
import subprocess
from pathlib import Path

import pytest

from fuzzgen import cli, contain, records
from fuzzgen.lanes import go as golane
from fuzzgen.probe import probe_signature
from fuzzgen.selectors import Selector, parse_selector

FIXTURES = Path(__file__).resolve().parent / "fixtures"


def _go_repo(tmp_path):
    repo = tmp_path / "go-target"
    shutil.copytree(FIXTURES / "go" / "basic", repo)
    subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
    subprocess.run(["git", "config", "user.email", "t@t"], cwd=repo, check=True)
    subprocess.run(["git", "config", "user.name", "t"], cwd=repo, check=True)
    subprocess.run(["git", "add", "-A"], cwd=repo, check=True)
    subprocess.run(["git", "commit", "-qm", "init"], cwd=repo, check=True)
    return repo


def test_fuzz_name_collision(tmp_path):
    pkg = tmp_path / "pkg"
    pkg.mkdir()
    (pkg / "x.go").write_text("package pkg\nfunc FuzzDecode(f *testing.F) {}\n")
    sel = parse_selector("pkg.Decode", "go")
    assert golane.fuzz_name(sel, pkg) == "FuzzGenDecode"


def test_render_bytes(tmp_path):
    sel = parse_selector("codec.Decode", "go")
    res = probe_signature(sel, _go_repo(tmp_path))
    src = golane.render(sel, res, "codec", "FuzzGenDecode")
    assert "func FuzzGenDecode(f *testing.F)" in src
    assert "f.Fuzz(func(t *testing.T, data []byte)" in src
    assert "Decode(data)" in src


def test_gen_and_build_check_end_to_end(tmp_path, work_root, monkeypatch):
    """gen emits a compiling harness inside the contained build check."""
    repo = _go_repo(tmp_path)
    worktree, _ = __import__("fuzzgen.gitops", fromlist=["x"]).worktree_add_detached(
        repo, work_root=work_root
    )
    sel = parse_selector("codec.Decode", "go")
    pres = probe_signature(sel, worktree)
    gen = golane.gen_harness(sel, pres, worktree)
    assert gen.status == "OK"
    mech, denied, _ = contain.detect()
    if mech == contain.MECH_REFUSE:
        pytest.skip("no containment available")
    work_dir = work_root / "gen-check"
    work_dir.mkdir()
    chk = golane.build_check(worktree, gen.pkg_dir, mech, work_dir)
    assert chk.status == "OK", chk.reason


def test_cli_gen_writes_record(tmp_path, work_root, monkeypatch):
    repo = _go_repo(tmp_path)
    import fuzzgen.config as config

    # Point the default work root at the fixture-safe location by patching
    # config.work_root for this test process.
    monkeypatch.setattr(config, "work_root", lambda **kw: work_root)
    rc = cli.run(
        [
            "gen",
            "--repo", str(repo),
            "--out-dir", str(tmp_path / "out"),
            "codec.Decode",
        ]
    )
    assert rc == 0
    out_dirs = list((tmp_path / "out" / "go").rglob("summary.json"))
    assert out_dirs, "summary.json missing"
    harnesses = list((tmp_path / "out").rglob("*_fuzz_test.go"))
    assert harnesses, "harness not copied to record tree"
