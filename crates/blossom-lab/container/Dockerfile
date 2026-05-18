FROM rust:1.88-slim-bookworm AS build

ARG BLOSSOM_LAB_FEATURES=

WORKDIR /workspace
COPY Cargo.toml Cargo.lock ./
COPY benches ./benches
COPY src ./src
COPY crates/blossom-lab ./crates/blossom-lab

RUN if [ -n "$BLOSSOM_LAB_FEATURES" ]; then \
      cargo build --release --locked -p blossom-lab --bins --features "$BLOSSOM_LAB_FEATURES"; \
    else \
      cargo build --release --locked -p blossom-lab --bins; \
    fi

FROM debian:bookworm-slim AS runtime

RUN groupadd --system --gid 10001 blossom \
  && useradd --system --uid 10001 --gid blossom --home-dir /nonexistent --shell /usr/sbin/nologin blossom \
  && mkdir -p /workspace/benchmarks/results \
  && chown -R blossom:blossom /workspace

WORKDIR /workspace
COPY --from=build /workspace/target/release/blossom-lab-chaos /usr/local/bin/blossom-lab-chaos
COPY --from=build /workspace/target/release/blossom-lab-epoch-chaos /usr/local/bin/blossom-lab-epoch-chaos
COPY --from=build /workspace/target/release/blossom-lab-fuzz /usr/local/bin/blossom-lab-fuzz
COPY --from=build /workspace/target/release/blossom-lab-sim /usr/local/bin/blossom-lab-sim
COPY crates/blossom-lab/container/entrypoint.sh /usr/local/bin/blossom-lab-container
RUN chmod 755 /usr/local/bin/blossom-lab-container

USER blossom
ENV RESULTS_DIR=/workspace/benchmarks/results
ENV RUST_BACKTRACE=1

ENTRYPOINT ["blossom-lab-container"]
CMD ["sim"]
