# Kavach pilot image — kavach-api (console embedded) + kavach-batch + kavach-evidence
# Build: docker build -f deploy/Dockerfile -t kavach:pilot .
#
# Supply chain: base images are pinned by digest (Dependabot does not track
# Dockerfiles here; bump them deliberately), the builder matches the pinned
# toolchain (rust-toolchain.toml), and the build uses Cargo.lock (--locked).

FROM node:22-bookworm-slim@sha256:43ac6c60b8f89723f746e8a92ce91abd5017e627ce1ddfe4238355d3a30b772c AS console
WORKDIR /build/console
COPY console/package.json console/package-lock.json ./
RUN npm ci
COPY console/ ./
RUN npm run build

FROM rust:1.98.0-bookworm@sha256:82150a52ec202c1b14d7817e14516c392bb7f5cfebd88f1ed531cb37ebd39922 AS builder
WORKDIR /build
COPY . .
COPY --from=console /build/console/dist ./console/dist
RUN cargo build --release --locked -p kavach-api -p kavach-batch -p kavach-evidence-cli

FROM debian:bookworm-slim@sha256:3783cc01769c7b2b1b83a5c5ad96c815348e28ed7da68e2e3687004faa906251 AS runtime
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 10001 --create-home kavach
WORKDIR /app
COPY --from=builder /build/target/release/kavach-api /usr/local/bin/
COPY --from=builder /build/target/release/kavach-batch /usr/local/bin/
COPY --from=builder /build/target/release/kavach-evidence /usr/local/bin/
COPY packs/ packs/
COPY models/ models/
COPY tools/ tools/
COPY partner/ partner/
COPY schemas/ schemas/
COPY crates/kavach-auth/policies/ crates/kavach-auth/policies/
USER kavach
EXPOSE 8080 50051
# Liveness over plain HTTP on the operator listener, with bash's /dev/tcp (no
# curl in the image): any HTTP status line means the server is up. (`/health`
# itself requires an authorised principal, so an unauthenticated probe gets
# 401, which still proves liveness.) With --tls, probe from the orchestrator.
HEALTHCHECK --interval=15s --timeout=5s --start-period=30s --retries=3 \
  CMD ["bash", "-c", "exec 3<>/dev/tcp/127.0.0.1/8080 && printf 'GET /health HTTP/1.0\\r\\nHost: localhost\\r\\n\\r\\n' >&3 && head -n 1 <&3 | grep -q '^HTTP/1\\.[01] [0-9][0-9][0-9]'"]
ENTRYPOINT ["kavach-api"]
# Access control is Cedar by default; policy, entities and OIDC settings come
# from the environment (KAVACH_CEDAR_POLICY, KAVACH_CEDAR_ENTITIES,
# KAVACH_OIDC_*). No example principals are baked into the default command.
CMD ["--listen", "0.0.0.0:8080", "--grpc-listen", "0.0.0.0:50051", "--pack", "packs/finance/v0.yaml", "--model", "models/finance/credit-underwriting-v1.yaml", "--evidence-store", "postgres"]
