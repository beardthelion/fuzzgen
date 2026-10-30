"""Schema-v1 record shapes and atomic writers (KTD4).

summary.json is canonical; summary.md is derived from it byte-deterministically.
Raw target-derived text is bounded and control-stripped before it lands in a
record. Only fuzzgen-generated fields may emit RATIO:/REACH_BY: lines.
"""

from __future__ import annotations

import json
import os
import re
import tempfile
from pathlib import Path

SCHEMA_VERSION = 1

KINDS = frozenset(
    {
        "panic",
        "heap-buffer-overflow",
        "stack-buffer-overflow",
        "stack-overflow",
        "global-buffer-overflow",
        "heap-use-after-free",
        "double-free",
        "allocation-size-too-big",
        "out-of-memory",
        "capacity-overflow",
        "timeout",
        "deadly-signal",
        "data-race",
        "fatal-error",
        "undefined-behavior",
        "slow-unit",
        "assert-failure",
    }
)

STATUSES = frozenset(
    {
        "OK",
        "BUILD-FAIL",
        "NEEDS-HAND",
        "TOOL-MISSING",
        "PROBE-FAIL",
        "RUN-FAIL",
        "INTERRUPTED",
        "DISK-CAP",
    }
)

STDERR_TAIL_BYTES = 8192
STACK_MAX_LINES = 200
SLUG_MAX = 80

_SLUG_OK = re.compile(r"^[a-z0-9][a-z0-9._-]*$")
_HEX_ESCAPE = re.compile(r"-x([0-9a-f]{2})-")
_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def _escape_component(text: str) -> str:
    """Injective mangle: '-' and every disallowed char encode as -xNN-.

    No raw input can produce -xNN- since '-' never survives unescaped, so
    a::b, a/b and a-b slug to distinct values.
    """
    out = []
    for ch in text.lower():
        if ch in "abcdefghijklmnopqrstuvwxyz0123456789._":
            out.append(ch)
        else:
            out.append(f"-x{ord(ch):02x}-")
    return "".join(out)


def slug(raw: str) -> str:
    """Deterministic selector/repo slug over the strict charset.

    Strict charset [a-z0-9][a-z0-9._-]*, no '..' segments, length-capped.
    """
    escaped = _escape_component(raw).strip(".")
    escaped = re.sub(r"\.{2,}", "-x2e-", escaped)
    if escaped and escaped[0] == "-":
        escaped = "s" + escaped
    if len(escaped) > SLUG_MAX or not escaped:
        import hashlib

        digest = hashlib.sha1(raw.encode()).hexdigest()[:12]
        escaped = (escaped[: SLUG_MAX - 13].rstrip(".-_") + "-" + digest) if escaped else "s" + digest
    if not _SLUG_OK.match(escaped):
        raise ValueError(f"slug escaped the charset: {raw!r} -> {escaped!r}")
    return escaped


target_slug = slug
repo_slug = slug


def strip_control(text: str) -> str:
    return _CONTROL.sub("", text)


def bound_text(text: str, max_bytes: int = STDERR_TAIL_BYTES) -> str:
    """Strip control bytes and keep the tail (crashes live at the end)."""
    clean = strip_control(text)
    encoded = clean.encode("utf-8", errors="replace")
    if len(encoded) > max_bytes:
        encoded = encoded[-max_bytes:]
        return encoded.decode("utf-8", errors="replace")
    return clean


def bound_stack(text: str, max_lines: int = STACK_MAX_LINES) -> str:
    lines = strip_control(text).splitlines()
    return "\n".join(lines[:max_lines])


def confined(root: Path, *parts: str) -> Path:
    """Resolve a record path and assert it stays under root before any write."""
    root_res = root.resolve()
    candidate = root_res.joinpath(*parts).resolve()
    if os.path.commonpath([root_res, candidate]) != str(root_res):
        raise ValueError(f"path escapes out-dir root: {candidate}")
    return candidate


def out_dir_for(
    out_root: Path, lang: str, repo_name: str, git_sha: str, target: str
) -> Path:
    return confined(
        out_root, lang, f"{repo_slug(repo_name)}-{git_sha[:8]}", target_slug(target)
    )


def atomic_write(path: Path, data: str) -> None:
    """Write tmp in the same dir then os.replace; no .tmp survives."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".tmp-", suffix=path.name)
    try:
        with os.fdopen(fd, "w") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def write_json(path: Path, obj: dict) -> None:
    atomic_write(path, json.dumps(obj, indent=2, sort_keys=True) + "\n")


def run_record(**fields) -> dict:
    """run.json shape per KTD4. Callers pass only the fields they observed."""
    rec = {
        "schema_version": SCHEMA_VERSION,
        "target": fields["target"],
        "lang": fields["lang"],
        "mode": fields.get("mode"),
        "kind": fields.get("kind"),
        "stack_hash": fields.get("stack_hash"),
        "hits": fields.get("hits", 1),
        "input_bytes": fields.get("input_bytes"),
        "min_bytes": fields.get("min_bytes"),
        "stack_top": fields.get("stack_top"),
        "repro": fields.get("repro"),
        "peak_rss_kb": fields.get("peak_rss_kb"),
        "ratio": fields.get("ratio"),
        "reach_by": fields.get("reach_by"),
        "git_sha": fields.get("git_sha"),
        "run_id": fields.get("run_id"),
        "repo_path": fields.get("repo_path"),
        "worktree_path": fields.get("worktree_path"),
        "toolchain": fields.get("toolchain", {}),
        "containment": fields.get("containment"),
        "networkDenied": fields.get("networkDenied"),
        "repro_verified": fields.get("repro_verified", False),
        "min_broke": fields.get("min_broke", False),
        "incomplete": fields.get("incomplete", False),
        "incomplete_reason": fields.get("incomplete_reason"),
        "started_at": fields.get("started_at"),
        "finished_at": fields.get("finished_at"),
    }
    if rec["kind"] is not None and rec["kind"] not in KINDS:
        raise ValueError(f"kind outside closed enum: {rec['kind']}")
    return rec


def target_row(target: str, status: str, **fields) -> dict:
    if status not in STATUSES:
        raise ValueError(f"status outside closed enum: {status}")
    return {"target": target, "status": status, **fields}


def summary_doc(run_id: str, repo_path: str, git_sha: str, targets: list[dict]) -> dict:
    return {
        "schema_version": SCHEMA_VERSION,
        "run_id": run_id,
        "repo_path": repo_path,
        "git_sha": git_sha,
        "targets": targets,
    }


def summary_md(doc: dict) -> str:
    """Deterministic derivation from summary.json; byte-stable on repeat."""
    lines = [
        "# fuzzgen summary",
        "",
        f"run_id: {doc['run_id']}",
        f"repo: {doc['repo_path']}",
        f"git_sha: {doc['git_sha']}",
        "",
        "| target | status | crashes | notes |",
        "|---|---|---|---|",
    ]
    for row in doc.get("targets", []):
        crashes = row.get("crashes", "")
        notes = row.get("notes", "")
        lines.append(f"| {row['target']} | {row['status']} | {crashes} | {notes} |")
    lines.append("")
    return "\n".join(lines)
