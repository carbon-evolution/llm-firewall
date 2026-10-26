# Base images are pinned by multi-arch index digest; Dependabot (docker, /deploy)
# proposes digest and minor bumps, major Rust/Debian jumps are deliberate.

# Build
FROM rust:1.99@sha256:931c2c0531a8b143e044f0f3914dfe802f15bb3d1955f0b657e9359327ac2ffc AS build
WORKDIR /src
COPY . .
RUN cargo build --release -p llm-firewall

# Runtime
FROM debian:bookworm-slim@sha256:7ff6ba31527b9e336162fa061746c366c4b2032f4d2cff2078bea43f78efe3f8
RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=build /src/target/release/llm-firewall /usr/local/bin/llm-firewall
# Preserve the config layout the app expects: firewall.yaml resolves
# policy_file "policies/default.yaml" relative to WORKDIR (/app).
COPY firewall.yaml ./
COPY policies/ ./policies/
EXPOSE 8080
ENTRYPOINT ["llm-firewall"]
