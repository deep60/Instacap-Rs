# Build stage
FROM rust:latest as builder

WORKDIR /app

# Install system dependencies for packet capture
RUN apt-get update && apt-get install -y \
    libpcap-dev \
    pkg-config \
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
    libpcap0.8 \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy the binary from builder stage
COPY --from=builder /app/target/release/packet-capture /app/packet-capture

# Create necessary directories
RUN mkdir -p /app/captures /app/configs /var/log/packet-analyzer

# Set executable permissions
RUN chmod +x /app/packet-capture

# Set up a non-root user (though the service runs privileged)
RUN useradd -r -s /bin/false appuser
RUN chown -R appuser:appuser /app /var/log/packet-analyzer

USER appuser

EXPOSE 8080

CMD ["/app/packet-capture"]
