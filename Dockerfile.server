# ============================================================================
# Platform Server - Optimized Multi-stage Docker Build
# ============================================================================
# Central API Server for Platform Network (Single Source of Truth)
# Run by subnet owner only
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
    libpq-dev \
    protobuf-compiler \
    clang \
    libclang-dev \
    && rm -rf /var/lib/apt/lists/*

# Build dependencies first (cached if dependencies don't change)
COPY --from=planner /app/recipe.json recipe.json
RUN cargo chef cook --release --recipe-path recipe.json -p platform-server

# Copy source code and build
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
COPY bins ./bins
COPY tests ./tests

# Build release binary
RUN cargo build --release -p platform-server

# Strip binary for smaller size
RUN strip /app/target/release/platform-server

# Stage 4: Runtime - Minimal production image
FROM debian:trixie-slim AS runtime

# Install runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    libssl3t64 \
    libpq5 \
    curl \
    tini \
    && rm -rf /var/lib/apt/lists/* \
    && useradd -r -u 1000 -m platform

WORKDIR /app

# Copy binary from builder
COPY --from=builder /app/target/release/platform-server /usr/local/bin/

# Environment defaults
ENV RUST_LOG=info,platform_server=debug
ENV PORT=8080
ENV HOST=0.0.0.0

# Expose port
EXPOSE 8080

# Use tini as init system
ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["platform-server"]

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
    CMD curl -sf http://localhost:8080/health || exit 1

# Labels
LABEL org.opencontainers.image.source="https://github.com/PlatformNetwork/platform"
LABEL org.opencontainers.image.description="Platform Server - Central API"
LABEL org.opencontainers.image.licenses="MIT"
