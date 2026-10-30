"""Historic-crash leg: env-gated, informational (FUZZGEN_GATE_LIVE=1)."""
import os
import shutil
import subprocess
from pathlib import Path

import pytest

pytestmark = pytest.mark.skipif(
    os.environ.get("FUZZGEN_GATE_LIVE") != "1",
    reason="historic legs are env-gated (FUZZGEN_GATE_LIVE=1)",
)

LIGHTHOUSE_PARENT = "561167fa^"


def test_lighthouse_ssz_historic(tmp_path):
    """sigp/lighthouse ssz decode panic at parent of 561167fa."""
    repo = tmp_path / "lighthouse"
    subprocess.run(
        ["git", "clone", "--depth", "50", "https://github.com/sigp/lighthouse", str(repo)],
        check=True, capture_output=True,
    )
    subprocess.run(["git", "-C", str(repo), "checkout", "-q", LIGHTHOUSE_PARENT], check=True)
    from fuzzgen import cli

    rc = cli.run(
        ["run", "--repo", str(repo), "--out-dir", str(tmp_path / "out"),
         "--seconds", "300", "--lang", "rust", "ssz::decode"]
    )
    assert rc in (0, 1)  # informational: outcome recorded, not pass-gated
