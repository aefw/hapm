# ─────────────────────────────────────────────────────────────────────────────
# HAPM — HAProxy Manager
# Makefile — semua perintah development dan deployment dalam satu tempat.
#
# Penggunaan:
#   make help        — tampilkan semua perintah
#   make dev         — jalankan dalam mode development
#   make build       — build binary production
#   make docker-up   — jalankan via Docker Compose
# ─────────────────────────────────────────────────────────────────────────────

# Variabel
BINARY       := hapm
CMD          := ./cmd/hapm
BUILD_DIR    := ./bin
FRONTEND_DIR := $(HOME)/framework7/Hapm
WEB_DIST     := ./web/dist
VERSION      := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
BUILD_TIME   := $(shell date -u '+%Y-%m-%dT%H:%M:%SZ')
LDFLAGS      := -ldflags="-s -w -X main.version=$(VERSION) -X main.buildTime=$(BUILD_TIME)"
LEGO_VERSION := v4.17.4

# Go tools
GO         := go
GOTEST     := $(GO) test
GOBUILD    := $(GO) build
GOVET      := $(GO) vet
GOFMT      := gofmt

# Colors untuk output
GREEN  := \033[0;32m
YELLOW := \033[0;33m
RED    := \033[0;31m
NC     := \033[0m # No Color

.PHONY: help build build-linux build-arm64 run dev dev-acme clean test test-verbose test-coverage \
        lint fmt vet tidy download \
        build-frontend build-all \
        docker-build docker-up docker-down docker-logs docker-restart docker-shell docker-clean \
        gen-secret gen-key setup install-lego version

# ─── Default target ──────────────────────────────────────────────────────────
.DEFAULT_GOAL := help

help: ## Tampilkan semua perintah yang tersedia
	@echo ""
	@echo "  $(GREEN)HAPM — HAProxy Manager$(NC)"
	@echo "  ────────────────────────────────────────"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  $(YELLOW)%-20s$(NC) %s\n", $$1, $$2}'
	@echo ""

# ─── Frontend ────────────────────────────────────────────────────────────────
build-frontend: ## Build frontend (config-publish) dan sync ke web/dist/
	@echo "$(GREEN)Building frontend...$(NC)"
	@cd $(FRONTEND_DIR) && npm run build-docker
	@mkdir -p $(WEB_DIST)
	@rsync -av --delete $(FRONTEND_DIR)/www/ $(WEB_DIST)/
	@echo "$(GREEN)✓ Frontend berhasil di-sync ke $(WEB_DIST)$(NC)"

build-all: build-frontend build ## Build frontend + binary backend sekaligus

# ─── Build ───────────────────────────────────────────────────────────────────
build: ## Build binary production (output: ./bin/hapm)
	@echo "$(GREEN)Building $(BINARY) v$(VERSION)...$(NC)"
	@mkdir -p $(BUILD_DIR)
	CGO_ENABLED=0 $(GOBUILD) $(LDFLAGS) -trimpath -o $(BUILD_DIR)/$(BINARY) $(CMD)
	@echo "$(GREEN)✓ Binary: $(BUILD_DIR)/$(BINARY)$(NC)"

build-linux: ## Cross-compile untuk Linux AMD64
	@mkdir -p $(BUILD_DIR)
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GOBUILD) $(LDFLAGS) -trimpath \
		-o $(BUILD_DIR)/$(BINARY)-linux-amd64 $(CMD)
	@echo "$(GREEN)✓ Binary: $(BUILD_DIR)/$(BINARY)-linux-amd64$(NC)"

build-arm64: ## Cross-compile untuk Linux ARM64 (Raspberry Pi, etc)
	@mkdir -p $(BUILD_DIR)
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 $(GOBUILD) $(LDFLAGS) -trimpath \
		-o $(BUILD_DIR)/$(BINARY)-linux-arm64 $(CMD)
	@echo "$(GREEN)✓ Binary: $(BUILD_DIR)/$(BINARY)-linux-arm64$(NC)"

# ─── Run ─────────────────────────────────────────────────────────────────────
run: build ## Build dan jalankan binary
	$(BUILD_DIR)/$(BINARY)

dev-acme: ## Jalankan hapm-acme worker saja (port 8889, untuk dev terpisah)
	@ACME_PORT=8889 \
	 LEGO_PATH=$$(which lego 2>/dev/null || echo "/usr/local/bin/lego") \
	 $(GO) run ./cmd/hapm-acme

dev: ## Jalankan hapm + hapm-acme sekaligus dalam mode development
	@if [ ! -f .env ]; then \
		echo "$(RED)Error: .env tidak ditemukan. Jalankan: make setup$(NC)"; exit 1; \
	fi
	@bash -c '\
		set -a && . ./.env && set +a; \
		export CMC_ACME_SERVICE_URL=$${CMC_ACME_SERVICE_URL:-http://localhost:8889}; \
		export ACME_PORT=8889; \
		if [ -n "$$LEGO_PATH" ]; then \
			RESOLVED_LEGO="$$LEGO_PATH"; \
		elif [ -x "$(BUILD_DIR)/lego" ]; then \
			RESOLVED_LEGO="$$(pwd)/$(BUILD_DIR)/lego"; \
		elif command -v lego > /dev/null 2>&1; then \
			RESOLVED_LEGO="$$(which lego)"; \
		else \
			echo "$(RED)Error: lego $(LEGO_VERSION) tidak ditemukan.$(NC)"; \
			echo "$(YELLOW)Jalankan: make install-lego$(NC)"; \
			exit 1; \
		fi; \
		export LEGO_PATH="$$RESOLVED_LEGO"; \
		echo "$(GREEN)Using lego: $$RESOLVED_LEGO$(NC)"; \
		export CMC_STORAGE_PATH=$${CMC_STORAGE_PATH:-./data/storage/certificates}; \
		export CMC_WEBROOT_PATH=$${CMC_WEBROOT_PATH:-./data/acme-webroot}; \
		mkdir -p "$$CMC_STORAGE_PATH" "$$CMC_WEBROOT_PATH"; \
		echo "$(GREEN)Starting hapm-acme worker (port 8889)...$(NC)"; \
		$(GO) run ./cmd/hapm-acme & \
		ACME_PID=$$!; \
		trap "echo \"$(YELLOW)Stopping hapm-acme (PID $$ACME_PID)...$(NC)\"; kill $$ACME_PID 2>/dev/null; wait $$ACME_PID 2>/dev/null" EXIT INT TERM; \
		sleep 1; \
		if command -v air > /dev/null 2>&1; then \
			echo "$(GREEN)Starting hapm with air (hot reload)...$(NC)"; \
			APP_MODE=development air; \
		else \
			echo "$(YELLOW)air tidak ditemukan, jalankan langsung...$(NC)"; \
			APP_MODE=development $(GO) run $(CMD); \
		fi \
	'

# ─── Test ────────────────────────────────────────────────────────────────────
test: ## Jalankan semua unit test
	$(GOTEST) -race -count=1 ./...

test-verbose: ## Jalankan test dengan output verbose
	$(GOTEST) -v -race -count=1 ./...

test-coverage: ## Jalankan test dengan coverage report
	$(GOTEST) -race -coverprofile=coverage.out ./...
	$(GO) tool cover -html=coverage.out -o coverage.html
	@echo "$(GREEN)✓ Coverage report: coverage.html$(NC)"

# ─── Code Quality ────────────────────────────────────────────────────────────
fmt: ## Format semua kode Go
	$(GOFMT) -w -s .

vet: ## Jalankan go vet untuk cek kode
	$(GOVET) ./...

lint: fmt vet ## Format + vet (tanpa eksternal linter)
	@echo "$(GREEN)✓ Lint selesai$(NC)"

# ─── Dependencies ────────────────────────────────────────────────────────────
tidy: ## Bersihkan dan update go.mod / go.sum
	$(GO) mod tidy

download: ## Download semua dependencies
	$(GO) mod download

# ─── Docker ──────────────────────────────────────────────────────────────────
docker-build: ## Build Docker image
	docker compose build

docker-up: ## Jalankan semua service via Docker Compose
	docker compose up -d
	@echo "$(GREEN)✓ HAPM berjalan di http://localhost:$${APP_PORT:-8080}$(NC)"

docker-down: ## Hentikan semua service Docker
	docker compose down

docker-restart: ## Restart service HAPM
	docker compose restart hapm

docker-logs: ## Lihat log container HAPM (real-time)
	docker compose logs -f hapm

docker-shell: ## Masuk ke shell container (debug)
	docker compose exec hapm sh

docker-clean: ## Hapus container, image, dan volume (HATI-HATI: data hilang!)
	@echo "$(RED)WARNING: Ini akan menghapus semua data!$(NC)"
	@read -p "Ketik 'yes' untuk konfirmasi: " confirm && [ "$$confirm" = "yes" ]
	docker compose down -v --rmi local

# ─── Setup ───────────────────────────────────────────────────────────────────
setup: ## Setup environment baru (generate .env dari .env.example)
	@if [ -f .env ]; then \
		echo "$(YELLOW).env sudah ada, skip.$(NC)"; \
	else \
		cp .env.example .env; \
		echo "$(GREEN)✓ .env dibuat dari .env.example$(NC)"; \
		echo "$(YELLOW)⚠ Jangan lupa isi APP_JWT_ACCESS_SECRET, APP_JWT_REFRESH_SECRET, dan APP_SECURITY_ENCRYPTION_KEY!$(NC)"; \
	fi

gen-secret: ## Generate random 64-char secret untuk JWT
	@echo "$(GREEN)JWT Secret (64 chars):$(NC)"
	@openssl rand -hex 32 2>/dev/null || \
		$(GO) run -e 'package main; import ("crypto/rand";"encoding/hex";"fmt"); func main(){b:=make([]byte,32);rand.Read(b);fmt.Println(hex.EncodeToString(b))}'

gen-key: ## Generate random 32-byte hex key untuk AES-256-GCM encryption
	@echo "$(GREEN)Encryption Key (32 bytes = 64 hex chars):$(NC)"
	@openssl rand -hex 32 2>/dev/null || \
		head -c 32 /dev/urandom | xxd -p -c 32

# ─── LEGO CLI ────────────────────────────────────────────────────────────────
install-lego: ## Download lego CLI v4.17.4 ke ./bin/lego (versi sama dengan Docker)
	@mkdir -p $(BUILD_DIR)
	@ARCH=$$(uname -m); \
	case "$$ARCH" in \
	  x86_64)  LEGO_ARCH="amd64" ;; \
	  arm64)   LEGO_ARCH="arm64" ;; \
	  *)       LEGO_ARCH="amd64" ;; \
	esac; \
	OS=$$(uname -s | tr '[:upper:]' '[:lower:]'); \
	URL="https://github.com/go-acme/lego/releases/download/$(LEGO_VERSION)/lego_$(LEGO_VERSION)_$${OS}_$${LEGO_ARCH}.tar.gz"; \
	echo "$(GREEN)Download lego $(LEGO_VERSION) ($${OS}/$${LEGO_ARCH})...$(NC)"; \
	echo "  URL: $$URL"; \
	curl -fsSL "$$URL" -o /tmp/lego-hapm.tar.gz && \
	tar -xzf /tmp/lego-hapm.tar.gz -C $(BUILD_DIR) lego && \
	chmod +x $(BUILD_DIR)/lego && \
	rm /tmp/lego-hapm.tar.gz
	@echo "$(GREEN)✓ lego terinstall: $$($(BUILD_DIR)/lego --version)$(NC)"
	@echo "$(YELLOW)  Lokasi: $$(pwd)/$(BUILD_DIR)/lego$(NC)"
	@echo "$(YELLOW)  make dev akan otomatis menggunakan binary ini$(NC)"

# ─── Cleanup ─────────────────────────────────────────────────────────────────
clean: ## Hapus binary dan file build
	rm -rf $(BUILD_DIR)
	rm -f coverage.out coverage.html
	@echo "$(GREEN)✓ Clean selesai$(NC)"

# ─── Info ────────────────────────────────────────────────────────────────────
version: ## Tampilkan versi build
	@echo "Version:    $(VERSION)"
	@echo "Build time: $(BUILD_TIME)"
	@echo "Go version: $(shell $(GO) version)"
