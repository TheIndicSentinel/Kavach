# Kavach pilot image — kavach-api (console embedded) + kavach-batch + kavach-evidence
# Build: docker build -f deploy/Dockerfile -t kavach:pilot .

FROM node:22-bookworm-slim AS console
WORKDIR /build/console
COPY console/package.json console/package-lock.json ./
RUN npm ci
COPY console/ ./
RUN npm run build

FROM rust:bookworm AS builder
WORKDIR /build
COPY . .
COPY --from=console /build/console/dist ./console/dist
RUN cargo build --release -p kavach-api -p kavach-batch -p kavach-evidence

FROM debian:bookworm-slim AS runtime
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
COPY partner/ partner/
COPY schemas/ schemas/
COPY crates/kavach-auth/policies/ crates/kavach-auth/policies/
USER kavach
EXPOSE 8080 50051
ENTRYPOINT ["kavach-api"]
CMD ["--listen", "0.0.0.0:8080", "--grpc-listen", "0.0.0.0:50051", "--pack", "packs/finance/v0.yaml", "--model", "models/finance/credit-underwriting-v1.yaml", "--evidence-store", "postgres", "--access-control", "cedar", "--cedar-policy", "crates/kavach-auth/policies/kavach.cedar", "--cedar-entities", "crates/kavach-auth/policies/entities.example.json"]
