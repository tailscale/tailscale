# Build stage
FROM golang:alpine AS builder

# Install build dependencies
RUN apk add --no-cache git

# Set working directory
WORKDIR /src

# Copy only go.mod and go.sum first to leverage Docker caching
COPY go.mod go.sum ./
RUN go mod download

# Copy the entire repository
COPY . .

# Build the tsidp binary
RUN go build -o /bin/tsidp ./cmd/tsidp

# Final stage
FROM alpine:latest

# Create necessary directories
RUN mkdir -p /var/lib/tsidp

# Copy binary from builder stage
COPY --from=builder /bin/tsidp /app/tsidp

# Set working directory
WORKDIR /app

# Environment variables
ENV TAILSCALE_USE_WIP_CODE=1 \
    TS_HOSTNAME=idp \
    TS_STATE_DIR=/var/lib/tsidp

# Expose the default port
EXPOSE 443

# Run the application
ENTRYPOINT ["/bin/sh", "-c", "/app/tsidp --hostname=${TS_HOSTNAME} --dir=${TS_STATE_DIR}"]
