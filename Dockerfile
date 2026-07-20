# ─────────────────────────────────────────────────────────────────────────────
# Stage 1: Builder
# Menggunakan Go official image untuk build binary statis.
# CGO_ENABLED=0 karena kita pakai modernc.org/sqlite (pure Go, no CGO).
# TARGETARCH ditetapkan otomatis oleh docker buildx sesuai --platform yang dipilih.
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

# ARG TARGETARCH diisi otomatis oleh docker buildx (amd64 / arm64 / arm/v7 dst.)
# Tidak perlu hardcode — satu Dockerfile untuk semua arsitektur.
ARG TARGETARCH

# Build binary statis
# - CGO_ENABLED=0: pure Go, tidak butuh libc
# - GOOS=linux: target Linux (container)
# - GOARCH=${TARGETARCH}: arsitektur sesuai platform yang di-build
# - -ldflags="-s -w": strip debug info, kurangi ukuran binary
# - -trimpath: hapus path absolut dari binary untuk reproducible build
RUN CGO_ENABLED=0 GOOS=linux GOARCH=${TARGETARCH} go build \
    -ldflags="-s -w -X main.version=$(git describe --tags --always --dirty 2>/dev/null || echo dev)" \
    -trimpath \
    -o hapm \
    ./cmd/hapm

# ─────────────────────────────────────────────────────────────────────────────
# Stage 2: Runtime
# Menggunakan image sekecil mungkin untuk production.
# scratch = image kosong, hanya binary + CA certs.
# ─────────────────────────────────────────────────────────────────────────────
# ─────────────────────────────────────────────────────────────────────────────
# Stage 2: Seleksi binary aefw-serial sesuai arsitektur target
# Docker buildx mengisi TARGETARCH dan TARGETVARIANT secara otomatis:
#   linux/amd64      → TARGETARCH=amd64,  TARGETVARIANT=""
#   linux/arm64      → TARGETARCH=arm64,  TARGETVARIANT=""
#   linux/arm/v7     → TARGETARCH=arm,    TARGETVARIANT=v7   (Pi 2/3 32-bit, ARMv7)
#   linux/arm/v6     → TARGETARCH=arm,    TARGETVARIANT=v6   (Pi Zero / Pi 1)
#   linux/386        → TARGETARCH=386,    TARGETVARIANT=""
# ─────────────────────────────────────────────────────────────────────────────
FROM alpine:3.19 AS serial-picker
ARG TARGETARCH
ARG TARGETVARIANT
COPY bin/ /tmp/bin/
RUN set -e; \
    if   [ "${TARGETARCH}" = "arm" ] && [ "${TARGETVARIANT}" = "v6" ]; then BIN=aefw-serial-armv6; \
    elif [ "${TARGETARCH}" = "arm" ]; then BIN=aefw-serial-armv7; \
    else BIN=aefw-serial-${TARGETARCH}; fi; \
    cp /tmp/bin/${BIN} /aefw-serial && chmod +x /aefw-serial

FROM scratch

# CA certificates untuk HTTPS
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

# Binary hasil build
COPY --from=builder /build/hapm /hapm

# aefw-serial: verifikasi entitlement premium
# Pre-built untuk amd64 / arm64 / armv7 / armv6 / 386 — source di Golang/aefw-serial (private)
COPY --from=serial-picker /aefw-serial /bin/aefw-serial

# Port default aplikasi
EXPOSE 8282

# Health check — pastikan API merespons
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD ["/hapm", "-health"]

# Jalankan binary
ENTRYPOINT ["/hapm"]
