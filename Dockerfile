# Stage 1: Build
FROM golang:1.21-alpine AS builder

WORKDIR /app

# Copy dependency files first (layer caching)
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build static binary
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -ldflags="-s -w" -o security-analyzer .

# Stage 2: Runtime (minimal image)
FROM alpine:3.18

WORKDIR /app

# Copy binary from builder
COPY --from=builder /app/security-analyzer .

EXPOSE 8080

ENTRYPOINT ["./security-analyzer"]
