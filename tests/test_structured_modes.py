import struct

from fuzzgen import rlpgen, sszgen


def test_ssz_valid_envelope_decodes_shape():
    m = sszgen.SszModel(fixed_widths=(8, 4), list_limit=4)
    blob = sszgen.valid_container(m, 2)
    offset = struct.unpack("<I", blob[12:16])[0]
    # fixed region (8+4) + two offset entries (list + bitlist) = 20
    assert offset == 20
    seeds = sszgen.generate(m)
    kinds = {k for _, k in seeds}
    assert "valid" in kinds
    assert "offset-out-of-order" in kinds
    assert "list-at-limit" in kinds
    assert "list-past-limit" in kinds
    assert "bitlist-no-terminator" in kinds


def test_ssz_limits_unknown_omits_limit_mutations():
    seeds = sszgen.generate(limits_known=False)
    kinds = {k for _, k in seeds}
    assert "list-at-limit" not in kinds
    assert "offset-oversized" in kinds


def test_rlp_canonical_roundtrip():
    assert rlpgen.rlp_str(b"dog") == bytes([0x83]) + b"dog"
    assert rlpgen.rlp_str(b"") == bytes([0x80])
    assert rlpgen.rlp_str(b"\x7f") == b"\x7f"
    lst = rlpgen.rlp_list([rlpgen.rlp_str(b"cat")])
    assert lst[0] == 0xC0 + 4


def test_rlp_violation_classes():
    seeds = rlpgen.generate()
    kinds = {k for _, k in seeds}
    for k in (
        "len-exceeds-buffer",
        "longform-short-payload",
        "encoded-single-byte",
        "nonminimal-lenoflen",
        "int-leading-zero",
        "nested-at-cap",
        "nested-past-cap",
    ):
        assert k in kinds, k


def test_rlp_nesting_bounded():
    blobs = {k: b for b, k in rlpgen.generate()}
    # each level wraps the prior blob; deep nests encode as long-form lists
    assert blobs["nested-past-cap"][0] == 0xF8
    assert len(blobs["nested-past-cap"]) > len(blobs["nested-at-cap"])


def test_mode_seed_integration():
    from fuzzgen import seeder

    extra = seeder.mode_seeds("ssz")
    assert any(k == "valid" for _, k in extra)
    extra = seeder.mode_seeds("rlp")
    assert extra
    assert seeder.mode_seeds("bytes") == []
