# Build
FROM rust:1.96 AS build
WORKDIR /src
COPY . .
RUN cargo build --release -p llm-firewall

# Runtime
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=build /src/target/release/llm-firewall /usr/local/bin/llm-firewall
# Preserve the config layout the app expects: firewall.yaml resolves
# policy_file "policies/default.yaml" relative to WORKDIR (/app).
COPY firewall.yaml ./
COPY policies/ ./policies/
EXPOSE 8080
ENTRYPOINT ["llm-firewall"]
