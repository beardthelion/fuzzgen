# fuzzgen validation

## Fixture legs (pass-gated, `scripts/run_gate.py`)

- Unit suite: records/cli/gitops/contain/runner/seeder/probe/selectors/batch/
  resource/structured-modes/promote/go-lane/rust-lane (105 tests at last run).
- Dedup matrix: three inputs one hash; two distinct sites two records.
- Planted-bug fixture: `tests/fixtures/go/plantedbug` decoder with an
  off-by-one OOB read; rediscovered within 60s under the detected
  containment rung (bounded-not-contained on this machine), deduped to
  one record with `repro_verified: true`.
- Structure-mode fixtures: SSZ/RLP generator violation classes.

## Live legs

### gjson (Go, real repo, this machine)

`fuzzgen run --repo /var/tmp/gjson --out-dir out --lang go --seconds 30
github.com/tidwall/gjson.Parse` ->

```json
{"status":"OK","target":"github.com/tidwall/gjson.Parse","lang":"go",
 "crashes":0,"execs":3571013,"notes":""}
```

`fuzzgen-out/go/gjson-690362d6/.../harness/fuzzparse_fuzz_test.go` written;
3.57M execs in 30s under the bounded-not-contained rung with the
host-fetched GOMODCACHE bound in.

### httparse (Rust, real crate, this machine)

`fuzzgen run --repo /var/tmp/httparse --out-dir out --lang rust --seconds
60 httparse::parse_chunk_size` -> summary.json:

```json
{
  "git_sha": "a0fa552e4e0fa9a5914a736ef3a556748fef709b",
  "repo_path": "/var/tmp/httparse",
  "run_id": "run-1793420347",
  "schema_version": 1,
  "targets": [
    {
      "crashes": 0,
      "execs": 19573430,
      "lang": "rust",
      "notes": "",
      "status": "OK",
      "target": "httparse::parse_chunk_size"
    }
  ]
}
```

19.57M execs in 60s under the bounded-not-contained rung: the lane
stages the nightly toolchain into the work dir (nobody cannot traverse
$HOME), builds `cargo fuzz build -s address`, and runs `-fork=1
-ignore_crashes=1` with artifacts swept. harness/ holds
fuzzgen_parse_chunk_size.rs plus the generated fuzz/Cargo.toml. On a
pre-existing manifest, gen appends only its own [[bin]] entry (verified:
git diff on httparse is additions-only and `cargo fuzz list` shows the
6 original targets plus the generated one).

### Historic crash leg (lighthouse ssz, commit 561167fa1)

sigp/lighthouse `561167fa1 Fix panic in ssz decode` (2018) changes one
line in `beacon_chain/utils/ssz/src/decode.rs`:

```diff
-    if bytes.len() < length_bytes {
+    if bytes.len() < index + length_bytes {
         return Err(DecodeError::TooShort);
```

The 2018 workspace manifest is unparseable by modern cargo, so the leg
ran against a standalone checkout of the real `ssz` crate at `561167fa1^`
(same source, minimal manifest), harness `decode_length(data, 1, 4)`.

**Pre-fix (561167fa1^), rediscovered in seconds:**

```
MS: 4 CrossOver-ChangeByte-CopyPart-InsertByte-;
0x40,0xa,0x2,0x2,
artifact_prefix='.../artifacts/fuzz_decode_length/'; Test unit written
to .../crash-a6babc4f167c3528f2a1e17a75a946e742b26832
Failing input: [64, 10, 2, 2]
Error: Fuzz target exited with exit status: 77
```

4 bytes `[64,10,2,2]` panics `decode_length` out of bounds, the exact
class the commit fixed. **Post-fix (fix applied), clean:**

```
#17335006  DONE   cov: 26 ft: 27 corp: 3/14b lim: 4096 exec/s: 284180
Done 17335006 runs in 61 second(s)
```

17.3M runs, no crash. The bug was rediscovered at its pre-fix commit
and confirmed absent after the fix.

## Lane status on this machine

- go: validated end-to-end (probe, harness, contained fuzz, dedup,
  records, promote shape) on gjson and the planted-bug fixture.
- rust: validated end-to-end on httparse via `fuzzgen run` (19.57M
  execs, cargo-fuzz under the nobody rung with a staged toolchain).
- c: generator + build + run_argv wired; `unvalidated` because clang is
  absent on this machine. The lane test exercises clane.gen_harness,
  clane.build, and clane.run_argv when clang exists.
- bwrap rung: code correct (proc/dev/tmpfs + resolved toolchain PATH);
  unverifiable on this host since the kernel disables unprivileged user
  namespaces. On hosts with userns it is selected and works; the
  forced-rung test proves `go version` executes inside it there and
  skips here.
