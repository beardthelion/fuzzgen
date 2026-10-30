import subprocess
from pathlib import Path

import pytest

from fuzzgen import gitops


def test_worktree_add_read_remove(fixture_repo, work_root):
    wt, warnings = gitops.worktree_add_detached(fixture_repo, work_root=work_root)
    assert wt.is_dir()
    assert str(wt).startswith(str(work_root.resolve()))
    assert (wt / "README.md").read_text() == "target\n"
    assert not warnings  # clean checkout, no dirty warning
    (wt / "scratch.txt").write_text("dirty")
    gitops.worktree_remove(fixture_repo, wt)
    assert not wt.exists()


def test_dirty_checkout_warns(fixture_repo, work_root):
    (fixture_repo / "README.md").write_text("locally modified\n")
    wt, warnings = gitops.worktree_add_detached(fixture_repo, work_root=work_root)
    assert warnings and "fuzzing HEAD @" in warnings[0]
    gitops.worktree_remove(fixture_repo, wt)


def test_stale_entry_recovered_by_prune(fixture_repo, work_root):
    wt, _ = gitops.worktree_add_detached(fixture_repo, work_root=work_root)
    import shutil

    gitops.mark_inactive(wt)
    shutil.rmtree(wt)
    wt2, _ = gitops.worktree_add_detached(fixture_repo, work_root=work_root)
    assert wt2.is_dir()
    gitops.worktree_remove(fixture_repo, wt2)


def test_leftover_state_dir_detected(fixture_repo, work_root):
    wt, _ = gitops.worktree_add_detached(fixture_repo, work_root=work_root)
    leftover = gitops.leftover_worktrees(work_root)
    assert leftover == [wt]
    gitops.worktree_remove(fixture_repo, wt)
    assert gitops.leftover_worktrees(work_root) == []


def test_work_root_rejects_tmp_and_out_dir(fixture_repo):
    with pytest.raises(gitops.GitError):
        gitops.worktree_add_detached(fixture_repo, work_root=Path("/tmp/x"))
    with pytest.raises(gitops.GitError):
        gitops.worktree_add_detached(
            fixture_repo, work_root=fixture_repo / "fuzzgen-out" / "w"
        )


def test_submodule_file_protocol_refused(fixture_repo, work_root, tmp_path):
    sub_src = tmp_path / "sub-src"
    sub_src.mkdir()
    subprocess.run(["git", "init", "-q"], cwd=sub_src, check=True)
    subprocess.run(["git", "config", "user.email", "t@t"], cwd=sub_src, check=True)
    subprocess.run(["git", "config", "user.name", "t"], cwd=sub_src, check=True)
    (sub_src / "s.txt").write_text("s")
    subprocess.run(["git", "add", "-A"], cwd=sub_src, check=True)
    subprocess.run(["git", "commit", "-qm", "s"], cwd=sub_src, check=True)

    (fixture_repo / ".gitmodules").write_text(
        f'[submodule "sub"]\n\tpath = sub\n\turl = file://{sub_src}\n'
    )
    subprocess.run(["git", "add", ".gitmodules"], cwd=fixture_repo, check=True)
    subprocess.run(["git", "commit", "-qm", "add submodule"], cwd=fixture_repo, check=True)

    wt, _ = gitops.worktree_add_detached(fixture_repo, work_root=work_root)
    assert not (wt / "sub" / "s.txt").exists()  # file:// fetch denied
    gitops.worktree_remove(fixture_repo, wt)
