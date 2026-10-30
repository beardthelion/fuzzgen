"""Shared configuration constants for fuzzgen."""

from pathlib import Path

OUT_DIR_NAME = "fuzzgen-out"
WORK_DIR_NAME = "fuzzgen-work"
BIN_DIR_NAME = "bin"

SCHEMA_VERSION = 1

DEFAULT_FUZZ_SECONDS = 60
DEFAULT_JOBS = 1
DEFAULT_RSS_LIMIT_MB = 0  # pass -rss_limit_mb=0 explicitly; libFuzzer defaults to 2048

# Host-side reads of worktree content are bounded; target-derived text in
# records is bounded and control bytes stripped (KTD4).
MAX_SEED_FILE_BYTES = 4 * 1024 * 1024
STDERR_TAIL_BYTES = 8192
STACK_MAX_LINES = 200

# Snappy block decompression for *.ssz_snappy seeds (R8) uses cramjam.


def default_out_dir(cwd: Path | None = None) -> Path:
    return (cwd or Path.cwd()) / OUT_DIR_NAME


def work_root(cwd: Path | None = None) -> Path:
    import os

    xdg = os.environ.get("XDG_CACHE_HOME")
    base = Path(xdg) if xdg else (cwd or Path.cwd())
    return base / WORK_DIR_NAME
