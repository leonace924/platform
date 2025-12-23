# ============================================================================
# Platform Chain - Optimized Multi-stage Docker Build with Dependency Caching
# ============================================================================

# Stage 1: Chef - prepare recipe for dependency caching
FROM rust:slim-trixie AS chef
RUN cargo install cargo-chef --locked
WORKDIR /app

# Stage 2: Planner - analyze dependencies
FROM chef AS planner
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
COPY bins ./bins
COPY tests ./tests
RUN cargo chef prepare --recipe-path recipe.json

# Stage 3: Builder - build with cached dependencies
FROM chef AS builder

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config \
    libssl-dev \
    protobuf-compiler \
    clang \
    libclang-dev \
    && rm -rf /var/lib/apt/lists/*

# Build dependencies first (this layer is cached if dependencies don't change)
COPY --from=planner /app/recipe.json recipe.json
RUN cargo chef cook --release --recipe-path recipe.json

# Copy source code and build
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
COPY bins ./bins
COPY tests ./tests

# Build release binaries (only source changes trigger this)
RUN cargo build --release --bin validator-node --bin csudo

# Strip binaries for smaller size
RUN strip /app/target/release/validator-node /app/target/release/csudo

# Stage 4: Runtime - Minimal production image
FROM debian:trixie-slim AS runtime

# Install runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    libssl3t64 \
    curl \
    tini \
    && rm -rf /var/lib/apt/lists/* \
    && useradd -r -u 1000 -m platform

WORKDIR /app

# Copy binaries from builder
COPY --from=builder /app/target/release/validator-node /usr/local/bin/
COPY --from=builder /app/target/release/csudo /usr/local/bin/

# Create data directory
RUN mkdir -p /data

# Environment
ENV RUST_LOG=info,platform_chain=debug
ENV DATA_DIR=/data

# Expose ports (RPC: 8080, P2P: 9000)
EXPOSE 8080 9000

# Use tini as init system
ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["validator-node", "--data-dir", "/data"]

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -sf http://localhost:8080/health || exit 1

# Labels
LABEL org.opencontainers.image.source="https://github.com/PlatformNetwork/platform"
LABEL org.opencontainers.image.description="Platform Chain Validator Node"
LABEL org.opencontainers.image.licenses="MIT"
