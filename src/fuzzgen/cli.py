"""Command line entry point: gen, seed, run, all, triage, replay, promote."""

import argparse
import sys

from . import config

EXIT_OK = 0
EXIT_PARTIAL = 1
EXIT_ENV = 2
EXIT_USAGE = 64

EXIT_HELP = (
    "exit codes: 0 OK, 1 partial (per-target results exist, some non-OK), "
    "2 env (environment failure prevented results), 64 usage"
)


class Stopped(Exception):
    """Refusal or environment stop; prints 'fuzzgen: stopped: <msg>'."""


class _Parser(argparse.ArgumentParser):
    def error(self, message):
        self.print_usage(sys.stderr)
        sys.stderr.write(f"fuzzgen: error: {message}\n")
        sys.exit(EXIT_USAGE)


def _common(p: argparse.ArgumentParser) -> None:
    p.add_argument("--repo", required=True, help="path to the target repository")
    p.add_argument(
        "--out-dir",
        default=None,
        help="record root (default: <cwd>/fuzzgen-out)",
    )
    p.add_argument(
        "--jobs", type=int, default=config.DEFAULT_JOBS,
        help="parallel selectors under all / fuzzer workers under run",
    )
    p.add_argument(
        "--no-containment", action="store_true",
        help="run target code uncontained; requires FUZZGEN_ALLOW_NO_CONTAINMENT=1",
    )


def _lane_flags(p: argparse.ArgumentParser) -> None:
    p.add_argument("--lang", choices=["go", "rust", "c"], default=None)
    p.add_argument(
        "--mode", choices=["bytes", "struct", "ssz", "rlp"], default=None
    )


def build_parser() -> argparse.ArgumentParser:
    parser = _Parser(
        prog="fuzzgen",
        description="Emit a compiling fuzz harness for a target parser entry point, seed a corpus, and run it contained.",
        epilog=EXIT_HELP,
    )
    sub = parser.add_subparsers(dest="command", required=True)

    gen = sub.add_parser("gen", help="probe selector, write harness, build-check")
    _common(gen)
    _lane_flags(gen)
    gen.add_argument("target", help="selector, e.g. pkg.Decode or crate::decode")
    gen.add_argument("--cflags", default=None, help="extra C compiler flags")
    gen.add_argument("--ldflags", default=None, help="extra C linker flags")
    gen.add_argument("--includes", action="append", default=[], help="extra -I dir (repeatable)")

    seed = sub.add_parser("seed", help="build corpus only")
    _common(seed)
    _lane_flags(seed)
    seed.add_argument("target")

    run = sub.add_parser("run", help="build + fuzz + harvest + records")
    _common(run)
    _lane_flags(run)
    run.add_argument("target")
    run.add_argument("--seconds", type=int, default=config.DEFAULT_FUZZ_SECONDS)
    run.add_argument("--rss-limit-mb", type=int, default=config.DEFAULT_RSS_LIMIT_MB)
    run.add_argument("--max-len", type=int, default=None)
    run.add_argument("--cap-mb", type=int, default=None, help="out-dir disk cap")
    run.add_argument("--reach-by", default=None, help="REACH_BY entry hint for resource records")
    run.add_argument("--race", action="store_true", help="Go lane: add -race")

    allp = sub.add_parser("all", help="sequential composition over a target list")
    _common(allp)
    _lane_flags(allp)
    allp.add_argument("targets", nargs="*", help="selectors (or use --from-scope)")
    allp.add_argument("--from-scope", default=None, help="parse .clawpatch/scope-boundary.md")
    allp.add_argument("--seconds", type=int, default=config.DEFAULT_FUZZ_SECONDS)
    allp.add_argument("--cap-mb", type=int, default=None)

    triage = sub.add_parser("triage", help="re-dedup and rebuild summary from an out-dir")
    triage.add_argument("out_dir", help="fuzzgen-out tree to rebuild")
    triage.add_argument("--repo", default=None, help="rebuild worktree for re-minimize")

    replay = sub.add_parser("replay", help="replay a crash or resource record dir")
    replay.add_argument("record_dir", help="crashes/<hash> or resource/<id> dir")

    promote = sub.add_parser("promote", help="write candidate fnd_*.json rows into .clawpatch/findings")
    promote.add_argument("out_dir", help="fuzzgen-out tree to promote from")
    promote.add_argument("--repo", default=None, help="target checkout (default: run.json repo_path)")

    return parser


def run(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return _dispatch(args)
    except Stopped as exc:
        sys.stderr.write(f"fuzzgen: stopped: {exc}\n")
        return EXIT_ENV
    except ValueError as exc:
        sys.stderr.write(f"fuzzgen: stopped: {exc}\n")
        return EXIT_USAGE


def _dispatch(args: argparse.Namespace) -> int:
    if args.command == "gen":
        from . import gen as _gen

        return _gen.run(args)
    if args.command == "seed":
        from . import seed as _seed

        return _seed.run(args)
    if args.command == "run":
        from . import run as _run

        return _run.run(args)
    if args.command == "all":
        from . import batch as _batch

        return _batch.run(args)
    if args.command == "triage":
        from . import triage as _triage

        return _triage.run(args)
    if args.command == "replay":
        from . import replay as _replay

        return _replay.run(args)
    if args.command == "promote":
        from . import promote as _promote

        return _promote.run(args)
    raise Stopped(f"unknown command {args.command!r}")


def main() -> int:
    return run()
