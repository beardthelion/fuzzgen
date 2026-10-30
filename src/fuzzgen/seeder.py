"""Corpus seeder (R8, KTD5).

Walks the target's own fixtures: testdata/, tests/, fixtures/,
test_vectors/ subtrees; *.ssz / *.ssz_snappy / *.rlp blobs; hex literals in
test sources (hex!(...), hexutil.MustDecode("0x..."), common.FromHex).
Snappy block-decompresses when the lane expects raw. Dedups by content
hash, size-bounds against the lane max_len. Every host-side read of
worktree content lstats and rejects symlinks and verifies the resolved
real path stays under the repo root.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from pathlib import Path

try:
    import cramjam
except ImportError:  # pragma: no cover
    cramjam = None

from . import config

FIXTURE_DIRS = (
    "testdata",
    "tests",
    "fixtures",
    "test_vectors",
    "vectors",
    "spec-tests",
    "spec_tests",
    "corpus",
    "fuzz",
)
BLOB_EXTS = {".ssz", ".ssz_snappy", ".rlp", ".bin", ".raw", ".dat", ".gz"}
TEST_SRC_EXTS = {".go", ".rs"}

_HEX_PATTERNS = (
    re.compile(r'hex!\(\s*"((?:[0-9a-fA-F]+|"\s*\+\s*"[0-9a-fA-F]+)+)"\s*\)'),
    re.compile(r'hex!\("([^"]+)"\)'),
    re.compile(r'hexutil\.MustDecode\(\s*"0x?([^"]+)"\s*\)'),
    re.compile(r'common\.FromHex\(\s*"0x?([^"]+)"\s*\)'),
    re.compile(r'0x([0-9a-fA-F]{16,})'),
)


@dataclass
class Seed:
    data: bytes
    source: str


@dataclass
class SeedResult:
    seeds: list[Seed] = field(default_factory=list)
    skipped_symlinks: int = 0
    skipped_undecodable: int = 0
    skipped_oversize: int = 0
    skipped_snappy: int = 0
    deduped: int = 0


def _real_under(root: Path, p: Path) -> Path | None:
    try:
        if p.is_symlink():
            return None
        real = p.resolve()
        root_real = root.resolve()
        import os

        if os.path.commonpath([str(root_real), str(real)]) != str(root_real):
            return None
        return real
    except OSError:
        return None


def _is_fixture_path(root: Path, p: Path) -> bool:
    rel = p.relative_to(root)
    parts = rel.parts
    if ".git" in parts:
        return False
    for d in FIXTURE_DIRS:
        if d in parts:
            return True
    return p.suffix.lower() in BLOB_EXTS and "vendor" not in parts


def _decode_snappy(raw: bytes) -> bytes | None:
    if cramjam is None:
        return None
    try:
        return bytes(cramjam.snappy.decompress(raw))
    except Exception:
        try:
            return bytes(cramjam.snappy.decompress_raw(raw))
        except Exception:
            return None


def _hex_literals(text: str) -> tuple[list[bytes], int]:
    seeds: list[bytes] = []
    skipped = 0
    # Handle concatenated "abc" + "def" forms first, then single literals.
    for m in re.finditer(
        r'(?:hex!|MustDecode|FromHex|FromHexOrPanic)\(\s*((?:"(?:0x)?[0-9a-fA-F]*"\s*\+?\s*)+)\)',
        text,
    ):
        chunks = re.findall(r'"(?:0x)?([0-9a-fA-F]*)"', m.group(1))
        joined = "".join(chunks)
        try:
            seeds.append(bytes.fromhex(joined))
        except ValueError:
            skipped += 1
    for pat in _HEX_PATTERNS:
        for m in pat.finditer(text):
            raw = m.group(1).replace('"', "").replace("+", "").replace(" ", "")
            try:
                seeds.append(bytes.fromhex(raw))
            except ValueError:
                skipped += 1
    return seeds, skipped


def collect_seeds(
    worktree: Path,
    max_len: int | None = None,
    expects_raw: bool = True,
    file_cap: int = config.MAX_SEED_FILE_BYTES,
) -> SeedResult:
    """Harvest seeds from fixture dirs, blob extensions, and hex literals."""
    root = Path(worktree).resolve()
    res = SeedResult()
    seen: set[str] = set()

    def add(data: bytes, source: str) -> None:
        if not data:
            return
        if max_len is not None and len(data) > max_len:
            res.skipped_oversize += 1
            return
        h = hashlib.sha1(data).hexdigest()
        if h in seen:
            res.deduped += 1
            return
        seen.add(h)
        res.seeds.append(Seed(data, source))

    # os.walk with followlinks=False: rglob on <=3.12 recurses into
    # symlinked dirs, so a committed `ln -s . loop` hangs before the
    # file-level confinement checks ever run.
    import os as _os

    files: list[Path] = []
    for dirpath, dirnames, filenames in _os.walk(root, followlinks=False):
        dirnames[:] = [
            d for d in dirnames
            if not _os.path.islink(_os.path.join(dirpath, d)) and d != ".git"
        ]
        for f in filenames:
            files.append(Path(dirpath) / f)
    for p in sorted(files):
        if not p.is_file():
            continue
        if p.is_symlink():
            res.skipped_symlinks += 1
            continue
        if _real_under(root, p) is None:
            res.skipped_symlinks += 1
            continue
        ext = p.suffix.lower()
        if _is_fixture_path(root, p) and ext in BLOB_EXTS:
            try:
                if p.stat().st_size > file_cap:
                    res.skipped_oversize += 1
                    continue
                raw = p.read_bytes()
            except OSError:
                continue
            if ext == ".ssz_snappy" and expects_raw:
                decompressed = _decode_snappy(raw)
                if decompressed is None:
                    res.skipped_snappy += 1
                    continue
                raw = decompressed
            add(raw, str(p.relative_to(root)))
        elif ext in TEST_SRC_EXTS:
            try:
                if p.stat().st_size > file_cap:
                    continue
                text = p.read_text(errors="replace")
            except OSError:
                continue
            lits, skipped = _hex_literals(text)
            res.skipped_undecodable += skipped
            for i, data in enumerate(lits):
                add(data, f"{p.relative_to(root)}#{i}")
    return res


def go_fuzz_v1(seed: bytes, kind: str = "bytes") -> str:
    """Encode a raw seed as a go test fuzz v1 corpus file."""
    escaped = "".join(
        chr(b) if 32 <= b < 127 and chr(b) not in '"\\' else f"\\x{b:02x}"
        for b in seed
    )
    typ = "string" if kind == "string" else "[]byte"
    return f'go test fuzz v1\n{typ}("{escaped}")\n'


def mode_seeds(mode: str | None) -> list[tuple[bytes, str]]:
    """Structure-aware generated seeds for ssz/rlp modes (KTD10)."""
    if mode == "ssz":
        from . import sszgen

        return sszgen.generate()
    if mode == "rlp":
        from . import rlpgen

        return rlpgen.generate()
    return []


def merge_mode_seeds(res: SeedResult, mode: str | None) -> None:
    import hashlib

    seen = {hashlib.sha1(s.data).hexdigest() for s in res.seeds}
    for data, klass in mode_seeds(mode):
        h = hashlib.sha1(data).hexdigest()
        if h not in seen:
            seen.add(h)
            res.seeds.append(Seed(data, f"generated:{klass}"))


def write_corpus(seeds: list[Seed], corpus_dir: Path) -> int:
    corpus_dir.mkdir(parents=True, exist_ok=True)
    for i, s in enumerate(seeds):
        name = hashlib.sha1(s.data).hexdigest()[:16]
        (corpus_dir / f"{i:05d}-{name}").write_bytes(s.data)
    return len(seeds)


def write_go_testdata(seeds: list[Seed], pkg_dir: Path, fuzz_name: str,
                      kind: str = "bytes") -> int:
    """Emit go test fuzz v1 files into testdata/fuzz/<FuzzName>/ (single-arg only)."""
    out = pkg_dir / "testdata" / "fuzz" / fuzz_name
    out.mkdir(parents=True, exist_ok=True)
    for i, s in enumerate(seeds):
        (out / f"seed{i}").write_text(go_fuzz_v1(s.data, kind=kind))
    return len(seeds)
