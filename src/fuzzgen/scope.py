"""Scope-boundary file parsing (KTD12).

Grammar per exposure.py: `- path:func TAINT: yes [entry=<route>] [tags]`.
Also accepts bare selector lines. TAINT: no and OUT-OF-SURFACE lines are
skipped with a note; entry= fills reach_by.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

_LINE = re.compile(
    r"^\s*-\s*(?P<sel>\S+?)\s+TAINT:\s*(?P<taint>\S+)(?:\s+entry=(?P<entry>\S+))?"
)
_BARE = re.compile(r"^\s*-?\s*(?P<sel>[\w:./-]+\.\w+|[\w:./-]+::[\w:]+|\S+\.[ch]:\w+)\s*$")


@dataclass
class ScopeTarget:
    selector: str
    entry: str | None = None


@dataclass
class ScopeResult:
    targets: list[ScopeTarget] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)


def parse_scope(path: Path) -> ScopeResult:
    res = ScopeResult()
    for line in Path(path).read_text(errors="replace").splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if "OUT-OF-SURFACE" in line:
            res.skipped.append(f"out-of-surface: {line.strip()[:60]}")
            continue
        m = _LINE.match(line)
        if m:
            if m.group("taint").lower() == "no":
                res.skipped.append(f"taint-no: {m.group('sel')}")
                continue
            res.targets.append(
                ScopeTarget(m.group("sel"), entry=m.group("entry"))
            )
            continue
        b = _BARE.match(line)
        if b:
            res.targets.append(ScopeTarget(b.group("sel")))
            continue
        res.skipped.append(f"malformed: {line.strip()[:60]}")
    return res
