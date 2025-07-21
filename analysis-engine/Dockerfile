# Build stage
FROM rust:latest as builder

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy manifests
COPY Cargo.toml Cargo.lock ./

# Copy source code
COPY src ./src

# Build the application
RUN cargo build --release

# Runtime stage
FROM debian:bookworm-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy the binary from builder stage
COPY --from=builder /app/target/release/analysis-engine /app/analysis-engine

# Create necessary directories
RUN mkdir -p /app/analysis /app/configs /var/log/packet-analyzer

# Set executable permissions
RUN chmod +x /app/analysis-engine

# Set up a non-root user
RUN useradd -r -s /bin/false appuser
RUN chown -R appuser:appuser /app /var/log/packet-analyzer

USER appuser

EXPOSE 8081

CMD ["/app/analysis-engine"]
