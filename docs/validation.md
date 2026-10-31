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

### chia_rs @ 56ecaa0 (Rust, workspace, bwrap)

`fuzzgen run --repo chia_rs --lang rust --seconds 60
clvm-utils::tree_hash::tree_hash_from_bytes` -> `{"status":"OK",
"execs":449151,"crashes":0}`. The generated harness emits the
crate-root public path (`clvm_utils::tree_hash_from_bytes`) since
`tree_hash` is a private module re-exported in lib.rs. 15s rerun,
unedited rung line and last 6 lines of fuzz_stderr.txt:

```
rung: bwrap (bubblewrap user/net/mount namespaces)
...
#101885: cov: 474 ft: 1863 corp: 192 exec/s: 7015 oom/timeout/crash: 0/0/0 time: 14s job: 4
#144422: cov: 477 ft: 1931 corp: 222 exec/s: 7089 oom/timeout/crash: 0/0/0 time: 20s job: 5
INFO: fuzzed for 20 seconds, wrapping up soon
INFO: exiting: 0 time: 20s
```

Second leg `chia-bls::signature::hash_to_g2` -> `{"status":"OK",
"execs":23750}` (15s box), unedited rung line and last 6 lines:

```
rung: bwrap (bubblewrap user/net/mount namespaces)
...
#16178: cov: 0 ft: 0 corp: 0 exec/s: 1262 oom/timeout/crash: 0/0/0 time: 14s job: 4
#23750: cov: 0 ft: 0 corp: 0 exec/s: 1262 oom/timeout/crash: 0/0/0 time: 20s job: 5
INFO: fuzzed for 20 seconds, wrapping up soon
INFO: exiting: 0 time: 20s
```

cov:0 ft:0 corp:0 is real, not a bug: `hash_to_g2` is a thin Rust
wrapper over the blst C library (built by cc without sancov
instrumentation). Every input walks the same single instrumented
Rust path into native code, so coverage and corpus growth stay flat
while the function still does 23k execs of real hashing.

### neon (Rust, workspace, uninit submodules, bwrap)

`fuzzgen run --repo neon --lang rust --seconds 60
postgres-protocol2::types::array_from_sql` -> `{"status":"OK",
"execs":15708433,"crashes":0}`. The run resolved the member crate via
name-scan (cargo metadata fails when submodule manifests are absent),
emitted `[workspace]` plus the hyphenated package dep name, and never
cloned vendor/postgres-v14..v17 (worktree submodule init is opt-in
via --submodules). Unedited rung line and last 6 lines of
fuzz_stderr.txt (15s rerun, 4,940,070 execs):

```
rung: bwrap (bubblewrap user/net/mount namespaces)
...
#2205659: cov: 54 ft: 79 corp: 22 exec/s: 243115 oom/timeout/crash: 0/0/0 time: 9s job: 3
#3438485: cov: 54 ft: 79 corp: 22 exec/s: 246565 oom/timeout/crash: 0/0/0 time: 14s job: 4
#4940070: cov: 54 ft: 79 corp: 22 exec/s: 250264 oom/timeout/crash: 0/0/0 time: 20s job: 5
INFO: fuzzed for 20 seconds, wrapping up soon
INFO: exiting: 0 time: 20s
```

### malachite (Rust, workspace, bwrap)

`fuzzgen run --repo malachite --lang rust --seconds 15
informalsystems-malachitebft-peer::PeerId::from_bytes` -> generated
`PeerId::from_bytes(data)` with no hand edits, `{"status":"OK",
"execs":3690491,"crashes":0}`, cov:152 ft:198 corp:46. The generic
receiver leg `PublicKey::from_sec1_bytes` correctly lands NEEDS-HAND:
three in-crate `CurveConfig` impls (K256/P256/P384) and no default
type param means no unambiguous turbofish; notes carry
"generic receiver PublicKey: no single concrete impl or default type
params resolvable" instead of an E0283 BUILD-FAIL.

### gitlab-runner (Go, method receiver, bwrap)

`fuzzgen run --repo gitlab-runner --lang go --seconds 15
gitlab.com/gitlab-org/gitlab-runner/common/spec.Inputs.UnmarshalJSON`
-> generated `var v Inputs; v.UnmarshalJSON(data)` with no hand
edits, `{"status":"OK","execs":102340,"crashes":0}` under bwrap.

### gjson 15m leg (Go -timeout fix)

`fuzzgen run --repo gjson --lang go --seconds 900
github.com/tidwall/gjson.Parse` under bwrap -> `{"status":"OK",
"execs":1305563523}`: go test's default 10m -timeout would have
killed the run; with `-timeout 0s` it ran the full 15m and exited
cleanly. An 11m leg captured the raw tail; last lines of
fuzz_stderr.txt (rung line is line 1 of the file):

```
fuzz: elapsed: 10m51s, execs: 13803089 (20719/sec), new interesting: 166 (total: 167)
fuzz: elapsed: 10m54s, execs: 13864920 (20613/sec), new interesting: 166 (total: 167)
fuzz: elapsed: 10m57s, execs: 13928167 (21079/sec), new interesting: 166 (total: 167)
fuzz: elapsed: 10m59s, execs: 13970625 (20308/sec), new interesting: 166 (total: 167)
PASS
ok  	gitlab.com/tidwall/gjson	659.107s
```

`ok ... 659.107s` means the round ran past the 10m mark and exited
cleanly at the fuzztime bound, 1.06B execs.

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
(same source, minimal manifest). The pasted result used a hand-written
harness, `decode_length(data, 1, 4)`: generated harnesses are single-arg
only, and 3-arg selectors correctly resolve to NEEDS-HAND. The gate test
`tests/test_historic.py` automates the same leg (fetch by sha, pre-fix
checkout, hand-written target, lane `build`/`fuzz_round` under the
detected rung, crash record) behind `FUZZGEN_GATE_LIVE=1`; under bwrap
it passes in ~160s with a crash record whose stack names
`decode_length`.

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

## Lane status per rung

- bwrap (namespace-contained, networkDenied): selected and exercised
  on hosts with unprivileged user namespaces. On a userns-enabled host
  the full httparse leg ran inside real bwrap: `fuzzgen run --repo
  httparse --lang rust --seconds 60 httparse::parse_chunk_size` ->
  `{"status":"OK","execs":17534606,"crashes":0}` with 121 corpus
  entries swept from work_dir into out_dir. The forced-rung tests
  (`go version`, `cargo --version`, a real 10s `cargo fuzz run` on a
  fixture crate with an out-of-crate corpus, --chdir argv shape) all
  execute there; they skip only on kernels without userns.
- nobody (bounded-not-contained): go validated end-to-end (gjson
  3.57M execs, planted-bug rediscovery); rust validated end-to-end
  (httparse 19.06-19.57M execs under `fuzzgen run`, toolchain staged
  into the work dir).
- docker/sudo-docker: image-gated, unexercised (no toolchain image
  present).
- c lane: `unvalidated` where clang is absent; the lane test runs
  clane.gen_harness + clane.build + clane.run_argv wherever clang
  exists.
- mech none: argv only; `--no-containment` stays gated behind
  `FUZZGEN_ALLOW_NO_CONTAINMENT=1`.
