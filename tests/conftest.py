import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import pytest


@pytest.fixture
def work_root(tmp_path_factory):
    """A work root under the real KTD2 location ($XDG_CACHE_HOME), not /tmp."""
    import os
    import shutil
    import uuid

    xdg = Path(os.environ.get("XDG_CACHE_HOME", Path.home() / ".cache"))
    root = xdg / "fuzzgen-test" / uuid.uuid4().hex[:12]
    root.mkdir(parents=True)
    yield root
    shutil.rmtree(root, ignore_errors=True)


@pytest.fixture
def fixture_repo(tmp_path):
    """Minimal git repo a unit can treat as a fuzz target."""
    import subprocess

    repo = tmp_path / "target-repo"
    repo.mkdir()
    subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
    subprocess.run(["git", "config", "user.email", "t@t"], cwd=repo, check=True)
    subprocess.run(["git", "config", "user.name", "t"], cwd=repo, check=True)
    (repo / "README.md").write_text("target\n")
    subprocess.run(["git", "add", "-A"], cwd=repo, check=True)
    subprocess.run(["git", "commit", "-qm", "init"], cwd=repo, check=True)
    return repo
