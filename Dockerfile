FROM rust:1.89-bookworm AS builder
WORKDIR /src
COPY . .
RUN cargo build --locked --release -p agentguard-server

FROM debian:bookworm-slim
RUN groupadd --system --gid 10001 agentguard \
  && useradd --system --uid 10001 --gid 10001 --home-dir /nonexistent --shell /usr/sbin/nologin agentguard \
  && mkdir -p /var/lib/agentguard/policies /var/lib/agentguard/audit \
  && chown -R agentguard:agentguard /var/lib/agentguard
COPY --from=builder /src/target/release/agentguard-server /usr/local/bin/agentguard-server
USER agentguard
ENV AGENTGUARD_LISTEN=tcp://0.0.0.0:8443 \
    AGENTGUARD_STORE=/var/lib/agentguard/policies \
    AGENTGUARD_AUDIT=/var/lib/agentguard/audit/decisions.jsonl \
    AGENTGUARD_AUTH=disabled
EXPOSE 8443
STOPSIGNAL SIGTERM
ENTRYPOINT ["/usr/local/bin/agentguard-server"]
