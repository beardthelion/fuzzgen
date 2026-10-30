#!/usr/bin/env python3
"""Validation gate: fixture legs pass-gate; live legs env-gated (KTD13)."""
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PY = sys.executable


def leg(name, argv, pass_gated=True):
    proc = subprocess.run(argv, cwd=ROOT, capture_output=True, text=True)
    ok = proc.returncode == 0
    tag = "PASS" if ok else ("FAIL" if pass_gated else "SKIP")
    print(f"{tag} {name}")
    return ok


def main() -> int:
    rc = 0
    legs = [
        ("records/cli/gitops/contain/seeder/probe/scope/resource",
         [PY, "-m", "pytest", "-x", "-q",
          "tests/test_records.py", "tests/test_cli.py", "tests/test_gitops.py",
          "tests/test_contain.py", "tests/test_runner.py", "tests/test_seeder.py",
          "tests/test_probe.py", "tests/test_selectors.py", "tests/test_batch.py",
          "tests/test_resource.py", "tests/test_structured_modes.py",
          "tests/test_promote.py", "tests/test_go_lane.py",
          "tests/test_lanes_env.py", "-k", "not slow"]),
        ("dedup matrix", [PY, "-m", "pytest", "-x", "-q",
                          "tests/test_go_run.py", "-k", "not slow"]),
    ]
    for name, argv in legs:
        rc |= 0 if leg(name, argv) else 1
    # Planted-bug leg: pass-gated but slow; always runs.
    rc |= 0 if leg("planted-bug Go leg (60s box)",
                   [PY, "-m", "pytest", "-x", "-q",
                    "tests/test_go_run.py::test_planted_bug_found_within_60s"]) else 1
    if os.environ.get("FUZZGEN_GATE_LIVE") == "1":
        leg("historic-crash leg (env-gated informational)",
            [PY, "-m", "pytest", "-x", "-q", "tests/test_historic.py"],
            pass_gated=False)
    else:
        print("SKIP historic-crash leg (FUZZGEN_GATE_LIVE unset)")
    return rc


if __name__ == "__main__":
    sys.exit(main())
