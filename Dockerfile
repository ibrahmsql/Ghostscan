# Multi-stage Docker build for GhostScan
# Stage 1: Build stage
FROM golang:1.21-alpine AS builder

# Install build dependencies
RUN apk add --no-cache git ca-certificates tzdata gcc musl-dev sqlite-dev

# Set working directory
WORKDIR /app

# Copy go mod files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Build the application
RUN CGO_ENABLED=1 GOOS=linux go build -a -installsuffix cgo -ldflags='-w -s -extldflags "-static"' -o ghostscan ./cmd/ghostscan

# Stage 2: Runtime stage
FROM alpine:3.18

# Install runtime dependencies
RUN apk --no-cache add ca-certificates tzdata curl

# Create non-root user
RUN addgroup -g 1001 -S ghostscan && \
    adduser -u 1001 -S ghostscan -G ghostscan

# Set working directory
WORKDIR /app

# Copy binary from builder stage
COPY --from=builder /app/ghostscan /usr/local/bin/ghostscan

# Copy configuration files
COPY --from=builder /app/configs/ ./configs/
COPY --from=builder /app/wordlists/ ./wordlists/

# Create directories for output and logs
RUN mkdir -p /app/output /app/logs && \
    chown -R ghostscan:ghostscan /app

# Switch to non-root user
USER ghostscan

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD ghostscan --version || exit 1

# Set default command
ENTRYPOINT ["ghostscan"]
CMD ["--help"]

# Labels for metadata
LABEL maintainer="GhostScan Team" \
      version="1.0.0" \
      description="Ghost CMS Security Scanner" \
      org.opencontainers.image.title="GhostScan" \
      org.opencontainers.image.description="A comprehensive security scanner for Ghost CMS" \
      org.opencontainers.image.vendor="GhostScan" \
      org.opencontainers.image.version="1.0.0" \
      org.opencontainers.image.source="https://github.com/ibrahmsql/ghostscan" \
      org.opencontainers.image.documentation="https://github.com/ibrahmsql/ghostscan/blob/main/README.md" \
      org.opencontainers.image.licenses="BSD-2-Clause"

# Expose default port (if running as web service)
EXPOSE 8080

# Volume for persistent data
VOLUME ["/app/output", "/app/logs"]