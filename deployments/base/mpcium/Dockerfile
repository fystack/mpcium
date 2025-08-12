# Stage 1: Build stage
FROM golang:1.24.4-alpine AS builder

# Install build dependencies
RUN apk add --no-cache git ca-certificates tzdata

# Set working directory
WORKDIR /app

# Copy go mod files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Build the binary
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -ldflags='-w -s -extldflags "-static"' \
    -o mpcium ./cmd/mpcium

# Stage 2: Runtime stage
FROM alpine:3.19

# Install runtime dependencies
RUN apk add --no-cache ca-certificates tzdata

# Create non-root user
RUN addgroup -g 1001 -S mpcium && \
    adduser -u 1001 -S mpcium -G mpcium

# Set working directory
WORKDIR /app

# Copy binary from builder stage
COPY --from=builder /app/mpcium .

# Create wrapper script for environment variable support
RUN echo '#!/bin/sh' > /app/entrypoint.sh && \
    echo 'NODE_NAME=${NODE_NAME:-node0}' >> /app/entrypoint.sh && \
    echo 'exec ./mpcium start --name "$NODE_NAME" "$@"' >> /app/entrypoint.sh && \
    chmod +x /app/entrypoint.sh

# Create necessary directories with proper permissions for volume mounting
RUN mkdir -p db backups identity certs && \
    chmod 777 db backups && \
    chown -R mpcium:mpcium /app

# Switch to non-root user
USER mpcium

# Set default node name
ENV NODE_NAME=node0

# Expose default port
EXPOSE 8080

# Use wrapper script as entrypoint
ENTRYPOINT ["/app/entrypoint.sh"]