"""RLP structure-aware seed generation (KTD10).

Valid encodings plus deliberate violations: non-canonical forms
(long-form on short payloads, non-minimal length-of-length, integer
leading zeros), length prefixes exceeding the buffer, bounded deep
nesting for recursive decoders.
"""

from __future__ import annotations


def rlp_str(data: bytes) -> bytes:
    """Canonical RLP encoding of a byte string."""
    if len(data) == 1 and data[0] < 0x80:
        return data
    if len(data) <= 55:
        return bytes([0x80 + len(data)]) + data
    ll = len(data).to_bytes((len(data).bit_length() + 7) // 8, "big")
    return bytes([0xB7 + len(ll)]) + ll + data


def rlp_list(items: list[bytes]) -> bytes:
    payload = b"".join(items)
    if len(payload) <= 55:
        return bytes([0xC0 + len(payload)]) + payload
    ll = len(payload).to_bytes((len(payload).bit_length() + 7) // 8, "big")
    return bytes([0xF7 + len(ll)]) + ll + payload


def nest(depth: int) -> bytes:
    """Nested lists to exactly ``depth`` levels of wrapping."""
    out = rlp_str(b"")
    for _ in range(depth):
        out = rlp_list([out])
    return out


def generate(depth_cap: int = 64) -> list[tuple[bytes, str]]:
    seeds: list[tuple[bytes, str]] = []
    # Valid shapes.
    seeds.append((rlp_str(b"dog"), "valid-str"))
    seeds.append((rlp_list([rlp_str(b"cat"), rlp_str(b"dog")]), "valid-list"))
    seeds.append((rlp_str(b"\x00" * 60), "valid-long-str"))
    seeds.append((nest(8), "valid-nested"))

    # Length prefix exceeding the buffer.
    seeds.append((bytes([0xB8, 0x40]) + b"\x01\x02", "len-exceeds-buffer"))
    seeds.append((bytes([0xF8, 0x60]) + b"\x01\x02", "listlen-exceeds-buffer"))

    # Non-canonical: long form on a short payload.
    seeds.append((bytes([0xB8, 0x03]) + b"dog", "longform-short-payload"))
    # Single byte < 0x80 must be literal, not string-encoded.
    seeds.append((bytes([0x81, 0x7F]), "encoded-single-byte"))
    # Non-minimal length-of-length.
    seeds.append((bytes([0xB9, 0x00, 0x38]) + b"\x00" * 56, "nonminimal-lenoflen"))
    # Integer with leading zeros.
    seeds.append((bytes([0x82, 0x00, 0x01]), "int-leading-zero"))
    # Truncated prefix.
    seeds.append((bytes([0xF7]), "truncated-prefix"))
    # Deep nesting at cap and just past a typical decoder recursion floor.
    seeds.append((nest(depth_cap), "nested-at-cap"))
    seeds.append((nest(depth_cap * 2), "nested-past-cap"))
    return seeds
