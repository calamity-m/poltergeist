# Stage 1: Build
FROM rust:1.92-slim-bookworm AS builder

WORKDIR /app

# Install build dependencies
RUN apt-get update && apt-get install -y pkg-config libssl-dev && rm -rf /var/lib/apt/lists/*

# Copy source code
COPY . .

# Build the application
RUN cargo build --release

# Stage 2: Runtime
FROM debian:bookworm-slim

# Install runtime dependencies (like CA certificates for upstream HTTPS)
RUN apt-get update && apt-get install -y ca-certificates libssl3 && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy the binary from the builder stage
COPY --from=builder /app/target/release/poltergeist /usr/local/bin/poltergeist

# Create a default empty config if needed, or rely on env vars
# Users should mount their own config.yaml or use POLTERGEIST_ env vars

EXPOSE 8080

ENTRYPOINT ["poltergeist"]
