# Build stage
FROM golang:1.22-alpine AS builder

WORKDIR /build

# Install build dependencies
RUN apk add --no-cache git ca-certificates tzdata

# Copy dependency files first for layer caching
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build the binary
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -ldflags="-w -s" \
    -o shield \
    ./cmd/shield

# Runtime stage
FROM alpine:3.19

LABEL maintainer="shield-team"
LABEL description="Shield WAF - Lightweight Web Application Firewall"

WORKDIR /app

# Install runtime dependencies
RUN apk add --no-cache ca-certificates tzdata

# Create necessary directories
RUN mkdir -p /app/configs /app/logs /app/data

# Copy binary from builder
COPY --from=builder /build/shield /app/shield

# Copy default config
COPY --from=builder /build/configs/config.yaml.docker /app/configs/config.yaml

# Expose proxy port
EXPOSE 8080

# Health check on proxy port
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD wget -qO- http://localhost:8080/ || exit 1

# Run as non-root user
RUN adduser -D -s /bin/sh shield && \
    chown -R shield:shield /app
USER shield

ENTRYPOINT ["/app/shield"]
CMD ["-c", "/app/configs/config.yaml", "start"]
