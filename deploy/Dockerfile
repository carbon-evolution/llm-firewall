# Base images are pinned by multi-arch index digest; Dependabot (docker, /deploy)
# proposes digest and minor bumps, major Rust/Debian jumps are deliberate.

# Build
FROM rust:1.96@sha256:1f0dbad1df66647807e6952d1db85d0b2bda7606cb2139d82517e4f009967376 AS build
WORKDIR /src
COPY . .
RUN cargo build --release -p llm-firewall

# Runtime
FROM debian:bookworm-slim@sha256:7c7b2c966bc9ee8cedfeef67e0e279108992c77681fa595db4a9d65c06ccc587
RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=build /src/target/release/llm-firewall /usr/local/bin/llm-firewall
# Preserve the config layout the app expects: firewall.yaml resolves
# policy_file "policies/default.yaml" relative to WORKDIR (/app).
COPY firewall.yaml ./
COPY policies/ ./policies/
EXPOSE 8080
ENTRYPOINT ["llm-firewall"]
