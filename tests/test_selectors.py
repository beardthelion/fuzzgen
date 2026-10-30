import pytest

from fuzzgen import selectors


def test_parse_rust_fn():
    s = selectors.parse_selector("mycrate::sub::decode")
    assert (s.lang, s.package, s.name, s.recv) == ("rust", "mycrate", "decode", None)


def test_parse_rust_method():
    s = selectors.parse_selector("mycrate::Type::decode")
    assert (s.lang, s.recv, s.name) == ("rust", "Type", "decode")


def test_parse_go_fn():
    s = selectors.parse_selector("codec/inner.Decode")
    assert (s.lang, s.package, s.name) == ("go", "codec/inner", "Decode")


def test_parse_c():
    s = selectors.parse_selector("src/parser.c:parse")
    assert (s.lang, s.package, s.name) == ("c", "src/parser.c", "parse")


def test_parse_unparseable():
    with pytest.raises(ValueError):
        selectors.parse_selector("plainname")
