# ─────────────────────────────────────────────────────────────────────────────
# Stage 1: Builder
# Menggunakan Go official image untuk build binary statis.
# CGO_ENABLED=0 karena kita pakai modernc.org/sqlite (pure Go, no CGO).
# ─────────────────────────────────────────────────────────────────────────────
FROM golang:1.23-alpine AS builder

# Install ca-certificates untuk HTTPS calls (Let's Encrypt ACME)
RUN apk add --no-cache ca-certificates git

WORKDIR /build

# Copy go.mod dan go.sum terlebih dahulu untuk cache layer dependency
COPY go.mod go.sum ./
RUN go mod download

# Copy seluruh source code
COPY . .

# Build binary statis
# - CGO_ENABLED=0: pure Go, tidak butuh libc
# - GOOS=linux: target Linux (container)
# - -ldflags="-s -w": strip debug info, kurangi ukuran binary
# - -trimpath: hapus path absolut dari binary untuk reproducible build
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -ldflags="-s -w -X main.version=$(git describe --tags --always --dirty 2>/dev/null || echo dev)" \
    -trimpath \
    -o hapm \
    ./cmd/hapm

# ─────────────────────────────────────────────────────────────────────────────
# Stage 2: Runtime
# Menggunakan image sekecil mungkin untuk production.
# scratch = image kosong, hanya binary + CA certs.
# ─────────────────────────────────────────────────────────────────────────────
FROM scratch

# CA certificates untuk HTTPS
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

# Binary hasil build
COPY --from=builder /build/hapm /hapm

# Port default aplikasi
EXPOSE 8282

# Health check — pastikan API merespons
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD ["/hapm", "-health"]

# Jalankan binary
ENTRYPOINT ["/hapm"]
