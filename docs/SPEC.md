# fuzzgen: spec

## Problem

The audit harness already tells the hunter when to fuzz: `audit/skills/one-class-hunt/SKILL.md` (around line 310) and `audit/skills/differential-hunt/SKILL.md` (line 115) allow a libFuzzer, cargo-fuzz, or go-fuzz harness when a paste says `fuzz: on`, and `audit/skills/one-class-hunt/parser-resource-shapes.md` defines the resource shapes (`amplify`, `length-field`, `cyclic`, `dispatch=`) and the resource PROVEN rule. All of that is text. Every harness is written by hand, corpora are ad hoc, and duplicate crashes are triaged one by one.

## Goals

- Given a target repo and an entry point (or a list from scope), generate a compiling harness for:
  - Rust: cargo-fuzz (libFuzzer) with `arbitrary` where the input type supports it.
  - Go: native `func FuzzX(f *testing.F)`.
  - C/C++: libFuzzer `LLVMFuzzerTestOneInput`.
- Seed corpora from the repo's own test fixtures and test vectors.
- Sanitizers on by default (ASan + UBSan for Rust nightly and C/C++, `-race` optional for Go).
- Structure-aware mode for SSZ and RLP inputs.
- Crash dedup by stack hash, plus minimization.
- Resource mode: detect and record memory or time blowups in the format the resource PROVEN rule requires (fresh process, peak RSS or attempted allocation size, `RATIO: <in> -> <resource>`, `REACH_BY:`).

## Non-goals

- Deciding if a crash is a vulnerability. Output goes to the harness kill-before-debug step.
- Long-running fuzz infrastructure (OSS-Fuzz, ClusterFuzz). This is a local, time-boxed tool.
- Python and JS fuzzing in v1.
- Any program-specific rules. Program rules stay in each target's program file.

## Inputs

- `--repo <path>`
- `--target <selector>`: Rust `crate::path::fn`, Go `pkg/path.Func`, C `file.c:func`. Or `--from-scope <file>` with one selector per line.
- `--mode bytes|struct|ssz|rlp` (default: autodetect from signature).
- `--time <dur>` per harness (default 10m), `--jobs N`.
- `--rss-limit-mb` (default 2048), `--timeout-s` per input (default 10).

## Outputs

Per target, under `fuzzgen-out/<lang>/<target-slug>/`:

- `harness/` generated source (also written into the repo's standard location: `fuzz/fuzz_targets/` for Rust, `*_fuzz_test.go` beside the package for Go, `fuzz/` for C).
- `corpus/` seeds plus discoveries.
- `crashes/<stackhash>/` one dir per unique crash: `input.bin`, `min.bin`, `stack.txt`, `run.json`.
- `resource/<id>/` for resource findings: `input.bin`, `run.json` with `peak_rss_kb`, `alloc_attempt_bytes`, `wall_ms`, `ratio`, `reach_by`.
- `summary.json` and `summary.md`.

## Architecture

```
selector ─► signature probe ─► template pick ─► harness write ─► build (sanitizers)
                                                                   │
test fixtures ─► corpus seeder ─────────────────────────────────► run (time box)
                                                                   │
                                     crashes ─► symbolize ─► stack hash ─► dedup ─► minimize
                                     slow/oom ─► fresh-process replay ─► RSS + ratio ─► resource record
```

### Signature probe

- Rust: `syn` parse of the target fn. Input kinds: `&[u8]`, `&str`, `Vec<u8>`, `T: Decode/Deserialize/ssz::Decode/rlp::Decodable/arbitrary::Arbitrary`, `impl Read`.
- Go: `go/types` for the func. Input kinds: `[]byte`, `string`, `io.Reader`, a type with `UnmarshalSSZ`, `DecodeRLP`, `UnmarshalBinary`, `UnmarshalJSON`, or a fastssz `UnmarshalSSZ` method.
- C: function prototype with `(const uint8_t*, size_t)` or `(const char*, size_t)`.
- If the probe cannot map the signature, emit a stub harness with a TODO block and mark it `NEEDS-HAND` in the summary. Never guess silently.

### Templates

- bytes: feed raw input to the decoder, then for round-trip-capable types re-encode and assert equality (differential within one implementation).
- struct: `arbitrary` (Rust) or `fuzz.Consumer`-style split of the byte slice (Go) into the argument tuple.
- ssz: generate from the SSZ type schema (container fields, list limits, bitlists) so most inputs pass the length prefix checks; mutate lengths at and past declared limits on purpose (feeds the `length-field` shape).
- rlp: nested list/string generator with depth and length controls; include inputs with length prefixes larger than the remaining buffer and deep nesting (feeds `amplify` and `cyclic`).

### Corpus seeder

Walk `testdata/`, `tests/`, `fixtures/`, `test_vectors/`, `*.ssz`, `*.ssz_snappy`, `*.rlp`, hex blobs in test sources (`hex!("...")`, `hexutil.MustDecode("0x...")`, `common.FromHex`). Decompress snappy where the target expects raw. Dedup by content hash. Consensus spec test vectors are a first class source when present.

### Sanitizers and build

- Rust: `cargo +nightly fuzz build -s address` (and `-s undefined` variant if supported), `--debug-assertions`.
- Go: `go test -fuzz=FuzzX -fuzztime=<t>`, with `-race` behind a flag. Go has no ASan in this mode; panics and OOM are the signals.
- C/C++: `clang -fsanitize=fuzzer,address,undefined`.

### Crash dedup

- Symbolize the stack, drop frames from the fuzzer runtime, sanitizer, std panic machinery, and the generated harness.
- Stack hash = sha1 of the top 5 remaining frames as `function` names only (no addresses, no line numbers) plus the crash kind (`panic`, `heap-buffer-overflow`, `oom`, `timeout`, ...).
- Same hash: keep the smallest input only, count hits.
- Minimize with `cargo fuzz tmin`, libFuzzer `-minimize_crash=1`, or Go's built in minimization; verify the minimized input reproduces the same hash, else keep the original and mark `MIN-BROKE`.

### Resource mode

Matches the harness resource PROVEN rule:

- Replay each slow or OOM input in a fresh process (no in-process fuzzer state), under `/usr/bin/time -v` or a cgroup, and record peak RSS.
- When the allocator refuses, record the attempted allocation size from the sanitizer or panic message.
- `ratio` = resource / input size, printed as `RATIO: <in bytes> -> <peak RSS or alloc bytes>`.
- `reach_by` = how an outsider gets those bytes to the parser (filled from the scope file's entry point when present, else `REACH_BY: unknown` and the record is flagged incomplete).
- Run the replay three times; report the min, so one noisy run cannot inflate the ratio.

## Data formats

`run.json`:

```json
{"target":"crate::ssz::decode_block","lang":"rust","mode":"ssz","kind":"heap-buffer-overflow",
 "stack_hash":"3f1c...","hits":12,"input_bytes":341,"min_bytes":37,
 "stack_top":["ssz::decode::list","ssz::decode::container","..."],
 "repro":"cargo +nightly fuzz run decode_block crashes/3f1c/min.bin",
 "peak_rss_kb":null,"ratio":null,"reach_by":null,"git_sha":"..."}
```

`summary.json`: list of targets with build status (`OK|BUILD-FAIL|NEEDS-HAND`), exec count, coverage edges if available, unique crash count, resource findings.

## CLI

```
fuzzgen gen   --repo ../grandine --target 'ssz::decode::decode_block' [--mode ssz]
fuzzgen seed  --repo ../grandine --target ...            # build corpus only
fuzzgen run   --repo ../grandine --target ... --time 15m --jobs 4
fuzzgen all   --repo ../reth --from-scope scope.txt --time 10m
fuzzgen triage fuzzgen-out/                               # re-dedup, re-minimize, rebuild summary
fuzzgen replay fuzzgen-out/rust/<slug>/resource/<id>      # fresh-process RSS replay
```

## Implementation notes

- Python 3.11 orchestrator. Small Rust (`syn`) and Go (`go/types`) helper binaries for signature probes, each emitting JSON.
- Generated files carry a header comment naming the generator so they are easy to find and remove. Never modify existing target files other than adding `fuzz/` entries (Rust needs `fuzz/Cargo.toml`; create it with `cargo fuzz init` if missing).
- Work in a git worktree of the target, not the user's checkout.
- Hard caps on disk use for corpora and crash dirs.

## Test plan

1. Unit: signature probe on fixture crates and packages covering every input kind above. Golden harness output.
2. Build: generated harness compiles for a small fixture Rust crate, Go module, and C file in CI.
3. Dedup: three inputs hitting the same panic via different paths in the harness produce one stack hash; two different panics produce two.
4. Known-bug validation target: a decoder with a planted out-of-bounds length read in a fixture crate must be found within 60 seconds from seeds, minimized, and deduped to one record.
5. Real validation target: a historic, already-public SSZ or RLP decoding crash in a Go or Rust Ethereum client (pick one with a public fix commit). Check out the parent of the fix, run `fuzzgen all` on the decoder for 30 minutes, and confirm the crash is rediscovered with the expected stack. Then run on the fix commit and confirm silence for the same time box.
6. Resource: fixture decoder that allocates `length_prefix * 1024` bytes. Resource mode must emit a record with fresh-process peak RSS, a `RATIO:` line, and the attempted allocation size.

## Milestones

1. M1: Go native fuzz generator (bytes mode), corpus seeder, run, crash dedup. Fixture tests.
2. M2: Rust cargo-fuzz generator (bytes and arbitrary modes), ASan build, minimization.
3. M3: resource mode with fresh-process RSS, RATIO, REACH_BY.
4. M4: SSZ and RLP structure-aware modes. Real validation target.
5. M5: libFuzzer C/C++ template, `all --from-scope`, triage command.
