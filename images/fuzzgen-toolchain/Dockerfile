FROM debian:bookworm-slim

# Toolchain image for contained fuzzgen builds (KTD3). Operator-provided:
# builds need network, runs must not. Image carries go, cargo+nightly
# (rust-src) + cargo-fuzz, clang+llvm for the C lane and symbolization.

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates curl git build-essential pkg-config \
        clang llvm libclang-rt-dev \
        golang-go \
    && rm -rf /var/lib/apt/lists/*

RUN useradd -m fuzzgen
USER fuzzgen
ENV HOME=/home/fuzzgen

RUN curl https://sh.rustup.rs -sSf | sh -s -- -y --default-toolchain nightly \
    && /home/fuzzgen/.cargo/bin/rustup component add rust-src --toolchain nightly \
    && /home/fuzzgen/.cargo/bin/cargo install cargo-fuzz

ENV PATH=/home/fuzzgen/.cargo/bin:/usr/local/go/bin:$PATH
WORKDIR /work
