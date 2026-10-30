import shutil
import subprocess
from pathlib import Path

import pytest

from fuzzgen import probe, selectors

FIXTURES = Path(__file__).resolve().parent / "fixtures"
BIN = Path(__file__).resolve().parents[1] / "bin"


def _go_repo(tmp_path):
    repo = tmp_path / "go-target"
    shutil.copytree(FIXTURES / "go" / "basic", repo)
    subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
    return repo


def _rust_repo(tmp_path):
    repo = tmp_path / "rust-target"
    shutil.copytree(FIXTURES / "rust" / "basic", repo)
    subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
    return repo


go_probe = pytest.mark.skipif(
    not (BIN / "go-probe").is_file(), reason="go-probe not built"
)
rust_probe = pytest.mark.skipif(
    not (BIN / "rust-probe").is_file(), reason="rust-probe not built"
)


@go_probe
@pytest.mark.parametrize(
    "name,kind,mode",
    [
        ("Decode", "bytes", "bytes"),
        ("DecodeStr", "string", "bytes"),
        ("DecodeReader", "io-reader", "bytes"),
        ("DecodeParts", "multi", "struct"),
    ],
)
def test_go_classification(name, kind, mode, tmp_path):
    repo = _go_repo(tmp_path)
    sel = selectors.parse_selector(f"codec.{name}", "go")
    res = probe.probe_signature(sel, repo)
    assert res.status == "OK", res.reason
    assert res.kind == kind and res.mode == mode


@go_probe
def test_go_needs_hand_nullary(tmp_path):
    repo = _go_repo(tmp_path)
    sel = selectors.parse_selector("codec.Nothing", "go")
    res = probe.probe_signature(sel, repo)
    assert res.status == "NEEDS-HAND"


@go_probe
def test_go_missing_func_probe_fail(tmp_path):
    repo = _go_repo(tmp_path)
    sel = selectors.parse_selector("codec.Absent", "go")
    res = probe.probe_signature(sel, repo)
    assert res.status == "PROBE-FAIL"


@go_probe
def test_go_method_markers(tmp_path):
    repo = _go_repo(tmp_path)
    sel = selectors.Selector("codec.Header.UnmarshalSSZ", "go", "codec", "UnmarshalSSZ", "Header")
    res = probe.probe_signature(sel, repo)
    assert res.status == "OK"
    assert res.mode == "bytes"  # single []byte arg
    assert "ssz" in res.markers


@rust_probe
@pytest.mark.parametrize(
    "name,kind,mode",
    [
        ("decode", "bytes", "bytes"),
        ("decode_str", "string", "bytes"),
        ("decode_vec", "bytes", "bytes"),
        ("decode_two", "multi", "struct"),
        ("decode_bounded", "ssz", "ssz"),
        ("decode_arb", "struct", "struct"),
    ],
)
def test_rust_classification(name, kind, mode, tmp_path):
    repo = _rust_repo(tmp_path)
    sel = selectors.parse_selector(f"basic::{name}")
    res = probe.probe_signature(sel, repo)
    assert res.status == "OK", res.reason
    assert res.kind == kind and res.mode == mode


@rust_probe
def test_rust_needs_hand(tmp_path):
    repo = _rust_repo(tmp_path)
    sel = selectors.parse_selector("basic::decode_weird")
    res = probe.probe_signature(sel, repo)
    assert res.status == "NEEDS-HAND"


@rust_probe
def test_rust_method(tmp_path):
    repo = _rust_repo(tmp_path)
    sel = selectors.parse_selector("basic::Reader::read_from")
    res = probe.probe_signature(sel, repo)
    assert res.status == "OK" and res.mode == "bytes"


def test_c_bytes_signature(tmp_path):
    repo = tmp_path / "c-target"
    shutil.copytree(FIXTURES / "c", repo)
    sel = selectors.parse_selector("parser.c:parse")
    res = probe.probe_signature(sel, repo)
    assert res.status == "OK" and res.mode == "bytes"


def test_c_needs_hand_and_missing(tmp_path):
    repo = tmp_path / "c-target"
    shutil.copytree(FIXTURES / "c", repo)
    assert probe.probe_signature(
        selectors.parse_selector("parser.c:parse_weird"), repo
    ).status == "NEEDS-HAND"
    assert probe.probe_signature(
        selectors.parse_selector("parser.c:absent"), repo
    ).status == "PROBE-FAIL"
