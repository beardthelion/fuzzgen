# fuzzgen

Generates a fuzz harness for one parser entry point in a target repo, seeds a corpus from the repo's own test data, runs it time-boxed inside a sandbox, and writes deduplicated crash records you can replay.

## Why

Writing fuzz harnesses by hand for every decoder in an audit is slow, corpora end up ad hoc, and the same crash gets triaged many times. fuzzgen turns "fuzz `pkg.Decode`" into one command with a fixed output layout, stack-hash dedup, minimized inputs, and a replay command per crash. It does not decide whether a crash is a vulnerability.

## What works today

| Lane | `gen` | `run` | Notes |
|---|---|---|---|
| Go | yes | yes | Native `func FuzzX(f *testing.F)` harness, `go test -fuzz`, optional `--race`. Resource (memory or time blowup) records are written on this lane. |
| Rust | via `run` | yes | cargo-fuzz (libFuzzer) target with AddressSanitizer. Handles workspaces, crate-root re-exports, methods and associated functions. Needs nightly, `rust-src`, `cargo-fuzz`, and a C/C++ compiler. |
| C | no | no | A libFuzzer template and generator exist in `src/fuzzgen/lanes/c.py` and are covered by tests, but the CLI reports `NEEDS-HAND` for C targets. |

Corpus seeding walks `testdata/`, `tests/`, `fixtures/`, `test_vectors/`, `*.ssz`, `*.ssz_snappy` (decompressed), `*.rlp`, and hex blobs in test sources, deduplicated by content hash. `--mode ssz` and `--mode rlp` add generated seeds that hit length-limit and nesting edge cases.

Target code always runs in a git worktree, never in your checkout. Containment is picked automatically, in this order:

1. Docker with the `fuzzgen-toolchain` image (build it from `images/fuzzgen-toolchain/Dockerfile`)
2. Docker through `sudo -n`
3. bubblewrap (user, network and mount namespaces, network denied)
4. `nobody` user with resource limits only, recorded as `bounded-not-contained`
5. refuse

`--no-containment` runs target code directly and only works with `FUZZGEN_ALLOW_NO_CONTAINMENT=1` set. Only an allowlist of environment variables (toolchain paths and caches) crosses into the sandbox; tokens and cloud credentials do not.

## Install

Python 3.10 or newer.

```bash
git clone https://github.com/beardthelion/fuzzgen
cd fuzzgen
pip install -e '.[test]'
fuzzgen --help
```

You also need the toolchain for each lane you use: `go` for Go; `cargo +nightly`, `rust-src`, `cargo-fuzz` and a C/C++ compiler for Rust. `bwrap` or Docker is needed for a contained run.

## Usage

```bash
# Fuzz a Go function for 30 seconds
fuzzgen run --repo ../somerepo --lang go --seconds 30 github.com/org/somerepo/parser.Decode

# Fuzz a Rust function (crate::path::fn)
fuzzgen run --repo ../somecrate --lang rust --seconds 60 somecrate::parse_chunk_size

# Only write and build-check a Go harness
fuzzgen gen --repo ../somerepo --lang go github.com/org/somerepo/parser.Decode

# Build the seed corpus only
fuzzgen seed --repo ../somerepo --lang go github.com/org/somerepo/parser.Decode

# Several targets, or every TAINT: yes line from a scope file
fuzzgen all --repo ../somerepo --lang go pkg.A pkg.B
fuzzgen all --repo ../somerepo --from-scope .clawpatch/scope-boundary.md

# Re-dedup an output tree, replay one crash, or export findings
fuzzgen triage fuzzgen-out/
fuzzgen replay fuzzgen-out/go/<repo>-<sha>/<target>/crashes/<hash>
fuzzgen promote fuzzgen-out/
```

Useful `run` options: `--seconds` (default 60), `--jobs`, `--rss-limit-mb`, `--max-len`, `--cap-mb` (disk cap for the output tree), `--reach-by` (how an outsider reaches the parser, copied into resource records), `--submodules` (submodules to init in the worktree; none by default).

Example, run against the planted-bug fixture in this repo (copied into its own git repo first):

```
$ fuzzgen run --repo pb --out-dir fzout --lang go --seconds 30 example.com/plantedbug/parser.Decode
$ cat fzout/go/pb-*/*/summary.md
| target | status | crashes | notes |
|---|---|---|---|
| example.com/plantedbug/parser.Decode | OK | 1 |  |
```

The crash record from that run shows `"containment": "bwrap"`, `"networkDenied": true`, `"kind": "panic"`, a 51-byte input minimized to 1 byte, and `"repro_verified": true`.

Exit codes: `0` OK, `1` partial (some targets not OK), `2` environment failure, `64` usage error.

## Output

Per target, under `fuzzgen-out/<lang>/<repo>-<sha>/<target>/`:

- `harness/`: the generated harness source
- `corpus/`: seeds plus inputs found while fuzzing
- `crashes/<stackhash>/`: `input.bin`, `min.bin`, `stack.txt`, `run.json` (kind, hits, sizes, containment rung, replay command, whether the replay reproduced)
- `resource/<id>/`: Go lane resource findings with fresh-process peak RSS, attempted allocation size, a `RATIO: <in> -> <resource>` line and `REACH_BY`
- `summary.json` and `summary.md`: per-target status (`OK`, `BUILD-FAIL`, `NEEDS-HAND`, `TOOL-MISSING`, ...), exec count, crash count

Crash dedup hashes the top frames by function name plus the crash kind, after dropping fuzzer, sanitizer and harness frames. If a minimized input no longer reproduces the same hash, the original is kept and the record is marked `min_broke`.

`promote` is opt-in and writes candidate `fnd_*.json` rows into `<repo>/.clawpatch/findings/`. It is the only write outside the output and work directories.

## Tests

```bash
pytest -q -m 'not slow'
```

Rust lane tests need a working nightly cargo-fuzz build, including a C/C++ compiler; they fail without one. `scripts/run_gate.py` runs the validation gate, and `docs/validation.md` records real-repo runs.

## Limitations

- Go and Rust only from the CLI. C, Python and JavaScript targets are not run.
- Structure-aware input generation is seed-side only and exists for SSZ and RLP. `struct` mode seeds with raw bytes and notes the low yield.
- Resource records come from the Go lane only.
- `gen` writes Go harnesses only; Rust harnesses are generated as part of `run`.
- A local, time-boxed tool. It is not continuous fuzzing infrastructure.
- Without Docker or bubblewrap, the best available rung has open network access and shares your user ID.

Design notes: [docs/SPEC.md](docs/SPEC.md).

## Related tools

- [autocatalytic-harness](https://github.com/beardthelion/autocatalytic-harness): the audit harness whose hunt stages call for fuzzing and consume these records
- [release-surface-diff](https://github.com/beardthelion/release-surface-diff): picks newly exposed entry points worth fuzzing
- [cve-variant-sweep](https://github.com/beardthelion/cve-variant-sweep): static rules from past fixes, for the bug classes fuzzing does not reach
