# ==============================================================================
# RustGuard: Rust-Native Sub-Millisecond LLM Security Gateway
# Multi-Stage Production Dockerfile
# ==============================================================================

# Stage 1: Build & Compilation
FROM rust:1.88-slim-bookworm AS builder

WORKDIR /usr/src/rustguard

# Install required build tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config \
    libssl-dev \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Copy workspace dependency manifests for dependency caching
COPY Cargo.toml Cargo.lock ./
COPY gateway-core/Cargo.toml gateway-core/
COPY gateway-server/Cargo.toml gateway-server/

# Create stub source files to pre-compile dependencies
RUN mkdir -p gateway-core/src gateway-server/src gateway-server/src/bin && \
    echo "pub fn dummy() {}" > gateway-core/src/lib.rs && \
    echo "pub fn dummy() {}" > gateway-server/src/lib.rs && \
    echo "fn main() {}" > gateway-server/src/main.rs && \
    echo "fn main() {}" > gateway-server/src/bin/ingest.rs && \
    echo "fn main() {}" > gateway-server/src/bin/benchmark.rs

# Build dependencies only (cached layer)
RUN cargo build --release --workspace

# Remove stub code
RUN rm -rf gateway-core/src gateway-server/src

# Copy real project sources and configs
COPY gateway-core/ gateway-core/
COPY gateway-server/ gateway-server/
COPY config.toml ./

# Touch main files to invalidate compiler stub cache and build final release binaries
RUN touch gateway-core/src/lib.rs gateway-server/src/lib.rs gateway-server/src/main.rs && \
    cargo build --release --workspace --bins

# ==============================================================================
# Stage 2: Minimal Distroless / Slim Runtime
# ==============================================================================
FROM debian:bookworm-slim AS runtime

# Install runtime dependencies (OpenSSL & CA certificates for outbound HTTPS LLM APIs)
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    libssl3 \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Create non-privileged security user
RUN groupadd -g 10001 rustguard && \
    useradd -u 10001 -g rustguard -s /bin/false -M rustguard

WORKDIR /app

# Copy compiled binaries from builder stage
COPY --from=builder /usr/src/rustguard/target/release/gateway-server /app/gateway-server
COPY --from=builder /usr/src/rustguard/target/release/ingest /app/ingest
COPY --from=builder /usr/src/rustguard/target/release/benchmark /app/benchmark
COPY --from=builder /usr/src/rustguard/config.toml /app/config.toml

# Set secure ownership and permissions
RUN chown -R rustguard:rustguard /app

USER rustguard:rustguard

# Default environment configuration
ENV SERVER_HOST=0.0.0.0 \
    SERVER_PORT=3000 \
    RUST_LOG=info

EXPOSE 3000

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD curl -f http://127.0.0.1:3000/health || exit 1

ENTRYPOINT ["/app/gateway-server"]
