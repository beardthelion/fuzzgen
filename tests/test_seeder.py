import os
import subprocess
from pathlib import Path

import pytest

from fuzzgen import seeder


def _corpus_repo(tmp_path):
    repo = tmp_path / "corpus-repo"
    (repo / "testdata").mkdir(parents=True)
    (repo / "tests" / "vectors").mkdir(parents=True)
    (repo / "codec").mkdir()
    (repo / "testdata" / "a.ssz").write_bytes(b"\x01\x02\x03")
    (repo / "tests" / "vectors" / "b.rlp").write_bytes(b"\x04\x05")
    (repo / "codec" / "codec_test.go").write_text(
        'package codec\nvar a = hexutil.MustDecode("0xdeadbeef")\n'
        'var b = common.FromHex("0x" + "cafe")\n'
        'var c = hexutil.MustDecode("0xzz")\n'
    )
    (repo / "misc.bin").write_bytes(b"\x06")
    subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
    return repo


def test_collects_blobs_and_literals(tmp_path):
    repo = _corpus_repo(tmp_path)
    res = seeder.collect_seeds(repo)
    datas = {s.data for s in res.seeds}
    assert b"\x01\x02\x03" in datas
    assert b"\x04\x05" in datas
    assert b"\x06" in datas
    assert bytes.fromhex("deadbeef") in datas
    assert bytes.fromhex("cafe") in datas
    assert res.skipped_undecodable >= 1  # 0xzz is not hex


def test_symlinks_skipped(tmp_path):
    repo = _corpus_repo(tmp_path)
    outside = tmp_path / "outside.bin"
    outside.write_bytes(b"\x07" * 10)
    os.symlink(outside, repo / "testdata" / "link.ssz")
    res = seeder.collect_seeds(repo)
    assert res.skipped_symlinks >= 1
    assert all(s.data != b"\x07" * 10 for s in res.seeds)


def test_content_dedup(tmp_path):
    repo = _corpus_repo(tmp_path)
    (repo / "testdata" / "dup.ssz").write_bytes(b"\x01\x02\x03")
    res = seeder.collect_seeds(repo)
    assert res.deduped >= 1


def test_oversize_dropped(tmp_path):
    repo = _corpus_repo(tmp_path)
    res = seeder.collect_seeds(repo, max_len=2)
    assert all(len(s.data) <= 2 for s in res.seeds)
    assert res.skipped_oversize >= 1


def test_snappy_decompress(tmp_path):
    cramjam = pytest.importorskip("cramjam")
    repo = _corpus_repo(tmp_path)
    payload = b"\x08" * 64
    (repo / "testdata" / "s.ssz_snappy").write_bytes(
        bytes(cramjam.snappy.compress(payload))
    )
    res = seeder.collect_seeds(repo, expects_raw=True)
    assert payload in {s.data for s in res.seeds}


def test_snappy_passthrough_when_framed(tmp_path):
    cramjam = pytest.importorskip("cramjam")
    repo = _corpus_repo(tmp_path)
    payload = b"\x09" * 64
    framed = bytes(cramjam.snappy.compress(payload))
    (repo / "testdata" / "s.ssz_snappy").write_bytes(framed)
    res = seeder.collect_seeds(repo, expects_raw=False)
    assert framed in {s.data for s in res.seeds}


def test_fuzz_v1_format():
    text = seeder.go_fuzz_v1(b'\x00abc\xff')
    assert text.startswith("go test fuzz v1\n[]byte(")
    assert "\\x00" in text and "\\xff" in text


def test_write_go_testdata(tmp_path):
    pkg = tmp_path / "pkg"
    seeds = [seeder.Seed(b"\x01", "a"), seeder.Seed(b"\x02", "b")]
    n = seeder.write_go_testdata(seeds, pkg, "FuzzGenX")
    assert n == 2
    out = (pkg / "testdata" / "fuzz" / "FuzzGenX" / "seed0").read_text()
    assert "go test fuzz v1" in out
