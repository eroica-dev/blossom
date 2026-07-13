FROM rust:1.88-slim-bookworm AS build

ARG BLOSSOM_SIM_FEATURES=

WORKDIR /workspace
COPY Cargo.toml Cargo.lock ./
COPY benches ./benches
COPY src ./src
COPY crates/blossom-sim ./crates/blossom-sim

RUN if [ -n "$BLOSSOM_SIM_FEATURES" ]; then \
      cargo build --release --locked -p blossom-sim --bins --features "$BLOSSOM_SIM_FEATURES"; \
    else \
      cargo build --release --locked -p blossom-sim --bins; \
    fi

FROM debian:bookworm-slim AS runtime

RUN groupadd --system --gid 10001 blossom \
  && useradd --system --uid 10001 --gid blossom --home-dir /nonexistent --shell /usr/sbin/nologin blossom \
  && mkdir -p /workspace/benchmarks/results \
  && chown -R blossom:blossom /workspace

WORKDIR /workspace
COPY --from=build /workspace/target/release/blossom-sim-chaos /usr/local/bin/blossom-sim-chaos
COPY --from=build /workspace/target/release/blossom-sim-epoch-chaos /usr/local/bin/blossom-sim-epoch-chaos
COPY --from=build /workspace/target/release/blossom-sim-fuzz /usr/local/bin/blossom-sim-fuzz
COPY --from=build /workspace/target/release/blossom-sim-hermetic /usr/local/bin/blossom-sim-hermetic
COPY crates/blossom-sim/container/entrypoint.sh /usr/local/bin/blossom-sim-container
RUN chmod 755 /usr/local/bin/blossom-sim-container

USER blossom
ENV RESULTS_DIR=/workspace/benchmarks/results
ENV RUST_BACKTRACE=1

ENTRYPOINT ["blossom-sim-container"]
CMD ["sim"]
