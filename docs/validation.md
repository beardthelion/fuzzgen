# fuzzgen validation

## Fixture legs (pass-gated, `scripts/run_gate.py`)

- Unit suite: records/cli/gitops/contain/runner/seeder/probe/selectors/batch/
  resource/structured-modes/promote/go-lane.
- Dedup matrix: three inputs one hash; two distinct sites two records.
- Planted-bug fixture: `tests/fixtures/go/plantedbug` decoder with an
  off-by-one OOB read; rediscovered within 60s under the detected
  containment rung (bounded-not-contained on this machine), deduped to
  one record with `repro_verified: true`.
- Structure-mode fixtures: SSZ/RLP generator violation classes; the
  differential efficacy leg (ssz/rlp mode finds a nested-structure bug
  that bytes mode does not within the box) is part of the gate leg list.

## Live legs (env-gated, `FUZZGEN_GATE_LIVE=1`, informational only)

- Historic crash: sigp/lighthouse `ssz` at parent of `561167fa`,
  fallback go-ethereum `rlp` at parent of `dd49c8e`. Requires nightly +
  cargo-fuzz (Rust) or vintage GOPATH-mode Go (geth); absent here, so
  the leg is unexecuted on this machine.

## Lane status on this machine

- go: validated end-to-end (probe -> harness -> contained fuzz -> dedup
  -> records -> promote shape).
- rust: `unvalidated` — no nightly/cargo-fuzz installed; gen and argv
  construction tested, builds never executed.
- c: `unvalidated` — no clang installed; template and argv tested.
