"""Stack parsing, kind classification, and stack_hash (KTD6).

hash = sha1 of crash kind + top 5 non-runtime frames, function names
only, after the per-language ignore lists. UAF-class deaths hash the
use-site access stack. Equivalence is scoped to recorded toolchain
versions: drift splits rather than merges.
"""

from __future__ import annotations

import hashlib
import re

GO_IGNORE = (
    "runtime.",
    "testing.",
    "internal/fuzz.",
    "created by",
    "main.main",
    "os.Exit",
    "reflect.",
)

RUST_IGNORE = (
    "core::",
    "std::",
    "panicking",
    "libfuzzer_sys",
    "rust_begin_unwind",
    "__rust",
)

C_IGNORE = (
    "fuzzer::",
    "LLVMFuzzerTestOneInput",
    "__sanitizer",
    "interceptor",
    "__asan",
    "__ubsan",
)


def go_stack(stderr: str) -> list[str]:
    """Top frames from a Go panic/fatal stack, functions only."""
    frames: list[str] = []
    in_stack = False
    for line in stderr.splitlines():
        s = line.strip()
        if s.startswith("goroutine"):
            if in_stack or frames:
                break  # only the crashing goroutine's frames hash
            in_stack = True
            continue
        if not in_stack:
            continue
        m = re.match(r"^([\w./-]+(?:\(\*?\w+\))?\.[\w.<>]+)\s*\(", s)
        if m:
            fn = m.group(1)
            if not fn.startswith(GO_IGNORE):
                frames.append(fn)
        elif s.startswith("/") or s.endswith(".go") or s.startswith("created by"):
            continue
        elif s == "":
            in_stack = False
    return frames


def rust_stack(stderr: str) -> list[str]:
    frames: list[str] = []
    for m in re.finditer(r"^\s*\d+:\s*(?:0x[0-9a-f]+\s*-\s*)?([\w:<>]+)", stderr, re.M):
        fn = m.group(1)
        if not fn.startswith(RUST_IGNORE):
            frames.append(fn)
    return frames


def c_stack(stderr: str) -> list[str]:
    frames: list[str] = []
    for m in re.finditer(r"#\d+\s+0x[0-9a-f]+\s+in\s+([\w:<>~.]+)", stderr):
        fn = m.group(1)
        if not fn.startswith(C_IGNORE):
            frames.append(fn)
    return frames


STACK_FNS = {"go": go_stack, "rust": rust_stack, "c": c_stack}


def classify_kind(lang: str, stderr: str, exit_code: int | None = None) -> str:
    """Map lane output to the closed kind enum."""
    s = stderr
    if lang == "go":
        if "fatal error: out of memory" in s or "runtime: out of memory" in s:
            return "out-of-memory"
        if "fatal error: stack overflow" in s or "goroutine stack exceeds" in s:
            return "stack-overflow"
        if "WARNING: DATA RACE" in s:
            return "data-race"
        if "panic:" in s:
            if "index out of range" in s or "slice bounds out of range" in s:
                return "panic"
            if "makeslice" in s and ("too big" in s or "out of range" in s):
                return "allocation-size-too-big"
            if "capacity overflow" in s.lower():
                return "capacity-overflow"
            return "panic"
        if exit_code == 70:
            return "timeout"
        if exit_code == 71:
            return "out-of-memory"
        return "fatal-error"
    # sanitizer-era kinds (rust/c share ASan/UBSan vocabulary)
    table = [
        ("heap-buffer-overflow", "heap-buffer-overflow"),
        ("stack-buffer-overflow", "stack-buffer-overflow"),
        ("stack-overflow", "stack-overflow"),
        ("global-buffer-overflow", "global-buffer-overflow"),
        ("heap-use-after-free", "heap-use-after-free"),
        ("double-free", "double-free"),
        ("allocation-size-too-big", "allocation-size-too-big"),
        ("capacity overflow", "capacity-overflow"),
        ("SEGV on unknown address", "deadly-signal"),
        ("data race", "data-race"),
        ("runtime error:", "undefined-behavior"),
        ("assert", "assert-failure"),
    ]
    for needle, kind in table:
        if needle in s:
            return kind
    if "panic" in s:
        return "panic"
    if exit_code == 70:
        return "timeout"
    if exit_code == 71:
        return "out-of-memory"
    return "fatal-error"


def stack_hash(kind: str, frames: list[str], stderr: str = "") -> str:
    top = frames[:5]
    if not top:
        # No symbolized frames: mix the crash headline so distinct
        # failures split rather than collapse into sha1(kind + "|").
        for line in stderr.splitlines():
            s = line.strip()
            if s.startswith(("panic:", "fatal error:", "==ERROR==", "runtime error:")):
                top = [s[:200]]
                break
        if not top:
            top = [stderr.strip().splitlines()[0][:200]] if stderr.strip() else []
    return hashlib.sha1((kind + "|" + "|".join(top)).encode()).hexdigest()[:16]
