# fuzzgen

Generates fuzz harnesses for parser entry points (cargo-fuzz, Go native fuzzing, libFuzzer), seeds them from the target's own test fixtures, runs them with sanitizers, and dedups crashes by stack hash.

Spec: [docs/SPEC.md](docs/SPEC.md)
