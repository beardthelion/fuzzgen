from fuzzgen import contain


def make_probe(answers):
    """answers: frozenset of argv tuples that return success."""
    def probe(argv, timeout=20):
        return tuple(argv) in answers
    return probe


def test_ladder_prefers_docker():
    probe = make_probe({("docker", "version"), ("sudo", "-n", "docker", "version")})
    mech, denied, _ = contain.detect(probe=probe, image_present=True)
    assert mech == contain.MECH_DOCKER and denied


def test_ladder_falls_to_sudo_docker():
    probe = make_probe({("sudo", "-n", "docker", "version")})
    mech, denied, _ = contain.detect(probe=probe, image_present=True)
    assert mech == contain.MECH_SUDO_DOCKER and denied


def test_ladder_falls_to_bwrap():
    probe = make_probe({("bwrap", "--unshare-all", "--ro-bind", "/", "/", "true")})
    mech, denied, _ = contain.detect(probe=probe, image_present=True)
    assert mech == contain.MECH_BWRAP and denied


def test_ladder_unshare_is_not_selected():
    # Bare unshare shares the host mount namespace with mapped root:
    # less containment than nobody, so detect() never selects it.
    probe = make_probe({("unshare", "--user", "--map-root-user", "--net", "true")})
    mech, denied, _ = contain.detect(probe=probe, image_present=True)
    assert mech == contain.MECH_REFUSE and not denied


def test_ladder_nobody_is_bounded_not_contained():
    probe = make_probe({("sudo", "-n", "-u", "nobody", "true")})
    mech, denied, note = contain.detect(probe=probe, image_present=True)
    assert mech == contain.MECH_NOBODY
    assert not denied  # honest: nobody rung cannot deny the network
    assert "bounded" in mech


def test_ladder_refuses():
    probe = make_probe(set())
    mech, denied, _ = contain.detect(probe=probe, image_present=True)
    assert mech == contain.MECH_REFUSE and not denied


def test_no_image_skips_docker_rungs():
    probe = make_probe({("sudo", "-n", "-u", "nobody", "true"), ("docker", "version")})
    mech, _, _ = contain.detect(probe=probe, image_present=False)
    assert mech == contain.MECH_NOBODY


def test_scrub_env_strips_credentials():
    env = {
        "PATH": "/usr/bin",
        "GITHUB_TOKEN": "secret",
        "AWS_SECRET_ACCESS_KEY": "secret",
        "GIT_SSH_COMMAND": "ssh -i key",
        "GOMEMLIMIT": "1GiB",
        "FUZZGEN_RUST_PROBE": "/x",
    }
    clean = contain.scrub_env(env)
    # FUZZGEN_* is host-local state (probe paths); it never crosses either.
    assert clean == {"PATH": "/usr/bin", "GOMEMLIMIT": "1GiB"}


def test_credential_free_mounts():
    from pathlib import Path

    cargo = contain.credential_free_mounts(Path("/home/u/.cargo"), "cargo")
    assert Path("/home/u/.cargo/registry") in cargo
    assert Path("/home/u/.cargo/credentials.toml") not in cargo
    go = contain.credential_free_mounts(Path("/home/u/go"), "go")
    assert Path("/home/u/go/pkg/mod") in go


def test_no_containment_flag_requires_env():
    assert not contain.allow_no_containment({})
    assert contain.allow_no_containment({"FUZZGEN_ALLOW_NO_CONTAINMENT": "1"})


def test_contained_argv_docker(tmp_path):
    wt = tmp_path / "wt"
    wt.mkdir()
    argv = contain.contained_argv(
        contain.MECH_DOCKER, ["go", "test"], wt, tmp_path / "wd",
        env={"PATH": "/usr/bin", "HOME": "/home/fuzzgen"},
    )
    assert "--network" in argv and "none" in argv
    assert "--memory" in argv
    assert argv[-2:] == ["go", "test"]
    assert argv[0] == "docker"


def test_contained_argv_nobody(tmp_path):
    argv = contain.contained_argv(
        contain.MECH_NOBODY, ["go", "test"], tmp_path, tmp_path,
        rlimits={"as": "4G", "cpu": "3600"},
    )
    assert argv[:4] == ["sudo", "-n", "-u", "nobody"]
    assert "prlimit" in argv


def test_contained_argv_none(tmp_path):
    argv = contain.contained_argv(
        contain.MECH_NONE, ["go", "test"], tmp_path, tmp_path, env={"PATH": "/x"}
    )
    assert argv[0] == "env" and argv[-2:] == ["go", "test"]


def test_bwrap_rung_executes_go_version(tmp_path):
    """Forced bwrap rung: toolchain binds + PATH let contained go exec."""
    import shutil
    import subprocess

    if not shutil.which("bwrap") or not shutil.which("go"):
        import pytest
        pytest.skip("bwrap or go absent")
    # Same capability gate detect() applies: kernels without unprivileged
    # user namespaces fail the probe and the nobody rung is selected.
    probe = subprocess.run(
        ["bwrap", "--unshare-all", "--ro-bind", "/", "/", "true"],
        capture_output=True, timeout=20,
    )
    if probe.returncode != 0:
        import pytest
        pytest.skip(f"bwrap namespaces unavailable: {probe.stderr.decode().strip()}")
    wt = tmp_path / "wt"
    wd = tmp_path / "wd"
    wt.mkdir(); wd.mkdir()
    argv = contain.contained_argv(
        contain.MECH_BWRAP, ["go", "version"], wt, wd,
        env={"GOCACHE": str(wd / "gocache")},
    )
    assert "--proc" in argv and "--dev" in argv and "--tmpfs" in argv
    assert any(a == "PATH" or a.startswith("PATH=") for a in argv)
    proc = subprocess.run(argv, capture_output=True, text=True, timeout=60)
    assert proc.returncode == 0, proc.stderr
    assert "go version" in proc.stdout


def test_unshare_rung_rejected(tmp_path):
    import pytest

    with pytest.raises(ValueError):
        contain.contained_argv(
            contain.MECH_UNSHARE, ["true"], tmp_path, tmp_path
        )
