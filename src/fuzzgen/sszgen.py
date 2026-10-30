"""SSZ structure-aware seed generation (KTD10).

Emits valid container envelopes plus deliberate violations:
out-of-order/oversized offsets, list lengths at and past declared
limits, missing bitlist terminators, out-of-range union selectors.
A tiny schema model drives the shapes; real limits come from the probe
when available, else the caller's declared bound.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass


def u32(n: int) -> bytes:
    return struct.pack("<I", n)


@dataclass
class SszModel:
    """Minimal container model: fixed field widths + one variable list."""
    fixed_widths: tuple[int, ...] = (8, 4)
    list_elem_width: int = 1
    list_limit: int = 16
    bitlist: bool = True
    union_selector: int | None = None


def valid_container(m: SszModel, list_len: int = 3) -> bytes:
    """Canonical container: fixed region, offset table, variable tails."""
    fixed = b"".join(bytes(w) for w in m.fixed_widths)
    n_offsets = 1 + (1 if m.bitlist else 0) + (1 if m.union_selector is not None else 0)
    offset_base = len(fixed) + 4 * n_offsets
    list_payload = bytes(list_len * m.list_elem_width)
    parts = [fixed]
    cursor = offset_base
    parts.append(u32(cursor))
    cursor += len(list_payload)
    if m.bitlist:
        parts.append(u32(cursor))
    if m.union_selector is not None:
        parts.append(u32(cursor))
    parts.append(list_payload)
    if m.bitlist:
        parts.append(b"\x01")  # terminator bit set
    if m.union_selector is not None:
        parts.append(bytes([m.union_selector]) + b"\x00" * 7)
    return b"".join(parts)


def generate(m: SszModel | None = None, limits_known: bool = True) -> list[tuple[bytes, str]]:
    """Return (seed_bytes, violation_class) pairs; empty class = valid."""
    m = m or SszModel()
    seeds: list[tuple[bytes, str]] = [(valid_container(m), "valid")]

    valid = valid_container(m)
    fixed_end = len(m.fixed_widths and b"".join(bytes(w) for w in m.fixed_widths))
    offset_pos = sum(m.fixed_widths)

    # Offset interleave: first offset points into the fixed region.
    bad = bytearray(valid)
    bad[offset_pos:offset_pos + 4] = u32(fixed_end - 1)
    seeds.append((bytes(bad), "offset-into-fixed"))

    # Out-of-order offsets: second offset precedes the first.
    if m.bitlist or m.union_selector is not None:
        bad = bytearray(valid)
        first = struct.unpack("<I", valid[offset_pos:offset_pos + 4])[0]
        bad[offset_pos + 4:offset_pos + 8] = u32(first - 1)
        seeds.append((bytes(bad), "offset-out-of-order"))

    # Oversized offset: past end of buffer.
    bad = bytearray(valid)
    bad[offset_pos:offset_pos + 4] = u32(len(valid) + 0x400)
    seeds.append((bytes(bad), "offset-oversized"))

    if limits_known:
        # List at limit and past limit.
        seeds.append((valid_container(m, m.list_limit), "list-at-limit"))
        seeds.append((valid_container(m, m.list_limit + 1), "list-past-limit"))
    # else caller records a `limits: unknown` note instead.

    if m.bitlist:
        # Missing bitlist terminator (zero last byte).
        bad = bytearray(valid_container(m, 2))
        idx = len(bad) - 1 if m.union_selector is None else len(bad) - 8 - 1
        bad[idx] = 0x00
        seeds.append((bytes(bad), "bitlist-no-terminator"))

    if m.union_selector is not None:
        bad = bytearray(valid)
        sel_off = len(valid) - 8
        bad[sel_off] = 0xFF  # out-of-range selector
        seeds.append((bytes(bad), "union-selector-out-of-range"))

    # Truncation.
    seeds.append((valid[:-3], "truncated"))
    return seeds
