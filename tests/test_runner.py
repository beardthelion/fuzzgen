import sys
import time

from fuzzgen import runner


def test_clean_exit():
    res = runner.run_bounded([sys.executable, "-c", "print('hi')"], timeout=10)
    assert res.ok and res.stdout.strip() == "hi" and not res.timed_out


def test_timeout_kills_and_reports():
    start = time.monotonic()
    res = runner.run_bounded(
        [sys.executable, "-c", "import time; time.sleep(60)"], timeout=1
    )
    assert res.timed_out
    assert res.returncode != 0
    assert time.monotonic() - start < 10


def test_timeout_kills_children():
    # Child spawns a grandchild in the same process group; kill-tree must reap it.
    res = runner.run_bounded(
        [
            sys.executable,
            "-c",
            "import subprocess,time; subprocess.Popen(['sleep','60']); time.sleep(60)",
        ],
        timeout=1,
    )
    assert res.timed_out


def test_missing_binary_is_runner_error():
    res = runner.run_bounded(["/nonexistent-bin-xyz"], timeout=5)
    assert res.error is not None
    assert not res.ok


def test_output_is_bounded():
    res = runner.run_bounded(
        [sys.executable, "-c", "print('x'*9000)"], timeout=10
    )
    assert len(res.stdout.encode()) <= 8192
