import json
import os

import pytest

from fuzzgen import records


def test_slug_separator_collision_free():
    a = records.target_slug("a::b")
    b = records.target_slug("a/b")
    c = records.target_slug("a-b")
    assert len({a, b, c}) == 3


def test_slug_stable_and_strict():
    s = records.target_slug("ssz::Decode[Foo]")
    assert s == records.target_slug("ssz::Decode[Foo]")
    assert s[0].isalnum()
    assert all(c in "abcdefghijklmnopqrstuvwxyz0123456789._-" for c in s)
    assert ".." not in s


def test_slug_long_input_capped_and_unique():
    long_a = records.target_slug("x" * 200)
    long_b = records.target_slug("y" * 200)
    assert len(long_a) <= 80 and len(long_b) <= 80
    assert long_a != long_b


def test_slug_leading_dash_escaped():
    s = records.target_slug("--weird")
    assert s[0].isalnum()


def test_run_record_validates_kind():
    rec = records.run_record(target="t", lang="go", kind="panic")
    assert rec["schema_version"] == 1
    assert rec["kind"] == "panic"
    with pytest.raises(ValueError):
        records.run_record(target="t", lang="go", kind="bogus")


def test_target_row_validates_status():
    records.target_row("t", "OK")
    with pytest.raises(ValueError):
        records.target_row("t", "FINE")


def test_atomic_write_leaves_no_tmp(tmp_path):
    p = tmp_path / "summary.json"
    records.write_json(p, {"a": 1})
    assert json.loads(p.read_text()) == {"a": 1}
    assert not list(tmp_path.glob(".tmp-*"))


def test_atomic_write_failure_cleans_tmp(tmp_path, monkeypatch):
    p = tmp_path / "x.json"
    orig = os.replace

    def boom(src, dst):
        raise OSError("forced")

    monkeypatch.setattr(os, "replace", boom)
    with pytest.raises(OSError):
        records.write_json(p, {"a": 1})
    monkeypatch.setattr(os, "replace", orig)
    assert not p.exists()
    assert not list(tmp_path.glob(".tmp-*"))


def test_summary_md_byte_stable():
    doc = records.summary_doc(
        "run1",
        "/repo",
        "abcdef0123",
        [records.target_row("a::b", "OK", crashes=0)],
    )
    assert records.summary_md(doc) == records.summary_md(doc)


def test_confined_rejects_escape(tmp_path):
    with pytest.raises(ValueError):
        records.confined(tmp_path, "..", "evil")


def test_out_dir_for_layout(tmp_path):
    d = records.out_dir_for(tmp_path, "go", "myrepo", "abcdef0123", "pkg.Decode")
    assert d.match("*/go/myrepo-abcdef01/*")
    assert str(d).startswith(str(tmp_path.resolve()))


def test_bound_text_strips_and_tails():
    nasty = "a" * 9000 + "\x1b[31m\x07END"
    out = records.bound_text(nasty, 512)
    assert out.endswith("END")
    assert "\x1b" not in out and "\x07" not in out
    assert len(out.encode()) <= 512
