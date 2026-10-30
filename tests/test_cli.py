import subprocess
import sys

import pytest

from fuzzgen import cli


def test_help_lists_all_subcommands(capsys):
    with pytest.raises(SystemExit) as exc:
        cli.build_parser().parse_args(["--help"])
    assert exc.value.code == 0
    out = capsys.readouterr().out
    for cmd in ("gen", "seed", "run", "all", "triage", "replay", "promote"):
        assert cmd in out


def test_missing_required_repo_is_usage():
    with pytest.raises(SystemExit) as exc:
        cli.run(["gen", "pkg.Decode"])
    assert exc.value.code == cli.EXIT_USAGE


def test_module_help():
    proc = subprocess.run(
        [sys.executable, "-m", "fuzzgen", "--help"],
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0
    assert "replay" in proc.stdout


def test_stubbed_command_stops_with_env(capsys):
    rc = cli.run(["gen", "--repo", "/tmp/nonexistent-repo-xyz", "pkg.Decode"])
    assert rc == cli.EXIT_ENV
    assert "fuzzgen: stopped:" in capsys.readouterr().err
