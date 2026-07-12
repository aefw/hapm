# HAProxy Manager (HAPM)

> Centralized multi-node HAProxy management platform

**Author:** Aldo · [aldo-expert.com](https://aldo-expert.com)
**Company:** [indonetsoft.com](https://indonetsoft.com)
**Framework:** [AE Framework (AEFW)](https://github.com/aefw)
**License:** MIT

---

## Table of Contents

1. [Installation (Docker)](#installation-docker)
2. [Overview](#overview)
3. [Architecture Analysis](#architecture-analysis)
4. [API Specification](#api-specification) — termasuk [CMC](#certificate-management-center-cmc), [Domain Authentication](#domain-authentication-haproxy-userlist), [Settings](#settings-endpoints)
5. [Certificate Management Center (CMC)](#certificate-management-center-cmc)
6. [Backend HTTPS & Forward Headers](#backend-https--forward-headers)
7. [Security Design](#security-design)
8. [Docker Deployment Plan](#docker-deployment-plan)
9. [Development Task List](#development-task-list)

---

## Installation (Docker)

### Prerequisites

- Docker ≥ 24.x
- Docker Compose v2 (`docker compose`, bukan `docker-compose`)
- Port 8282 tersedia di server

### Langkah Instalasi

**1. Clone repository**

```bash
git clone https://github.com/aefw/hapm.git
cd hapm
```

**2. Buat file konfigurasi**

```bash
cp .env.example .env
```

**3. Edit `.env` — isi nilai wajib berikut**

```bash
nano .env
```

Nilai yang **wajib** diisi (generate masing-masing, jangan pakai contoh di bawah):

```env
# Generate dengan: openssl rand -hex 32
APP_JWT_ACCESS_SECRET=ganti_dengan_64_karakter_hex_acak

# Generate dengan: openssl rand -hex 32
APP_JWT_REFRESH_SECRET=ganti_dengan_64_karakter_hex_acak

# Generate dengan: openssl rand -hex 32
APP_ENCRYPTION_KEY=ganti_dengan_64_karakter_hex_acak
```

> Untuk generate secret, jalankan: `openssl rand -hex 32`

**4. Jalankan**

```bash
docker compose up -d
```

**5. Akses aplikasi**

Buka browser dan akses:

```
http://<IP-SERVER>:8282
```

Login dengan:
- **Username:** `admin`
- **Password:** `admin`

> Ganti password segera setelah login pertama melalui menu **Settings → Password**.

---

### Update / Upgrade

**Langkah yang aman:**

**1. Backup data dulu (wajib sebelum upgrade)**

```bash
docker run --rm \
  -v hapm_data:/data \
  -v $(pwd):/backup \
  alpine \
  tar czf /backup/hapm_backup_$(date +%Y%m%d_%H%M%S).tar.gz -C / data
```

File backup akan tersimpan di direktori repo dengan nama `hapm_backup_YYYYMMDD_HHMMSS.tar.gz`.

**2. Upgrade aplikasi**

```bash
git pull
docker compose up -d --build
```

atau

```bash
git pull
docker compose build --no-cache
docker compose up -d
```

> **JANGAN gunakan `docker compose down -v`** — flag `-v` menghapus volume dan seluruh data.
> Gunakan `docker compose up -d --build` (satu perintah) agar volume tetap terjaga.

Data tidak akan hilang — database SQLite dan certificate tersimpan di Docker volume `hapm_data`.

---

### Recovery jika data hilang setelah upgrade

Jika data terlanjur hilang, cek apakah volume lama masih ada:

```bash
# Lihat semua volume
docker volume ls | grep hapm

# Jika ada volume lama (misal: haproxy-manager_hapm_data), restore dari sana:
docker run --rm \
  -v <nama_volume_lama>:/source \
  -v hapm_data:/dest \
  alpine \
  sh -c "cp -a /source/. /dest/"
```

Jika ada file backup tar.gz:

```bash
docker run --rm \
  -v hapm_data:/data \
  -v $(pwd):/backup \
  alpine \
  tar xzf /backup/hapm_backup_YYYYMMDD_HHMMSS.tar.gz -C /
```

---

### Port yang digunakan

| Port | Keterangan |
|---|---|
| `8282` | HAPM UI + API (expose ke host) |
| `8889` | hapm-acme ACME worker (internal Docker network, tidak di-expose) |

---

### Troubleshooting

**Lihat log:**
```bash
docker compose logs -f hapm
docker compose logs -f hapm-acme
```

**Restart:**
```bash
docker compose restart hapm
```

**Status container:**
```bash
docker compose ps
```

**Reset password admin (jika tidak bisa login):**

Jalankan dari host (Docker):
```bash
docker exec hapm /hapm reset-password
```

Atau dengan password custom:
```bash
docker exec hapm /hapm reset-password admin passwordbaru
```

Format: `reset-password [username] [password]`
- Jika tanpa argumen: reset `admin` ke password `admin`
- Unlock akun otomatis jika terkunci
- Semua session aktif dicabut

Contoh output:
```
========================================================
 Password berhasil di-reset
 Username : admin
 Password : admin
 Akun di-unlock, semua session lama dicabut.
 Ganti password segera setelah login!
========================================================
```

---

## Overview

HAPM is a **self-hosted**, **production-ready**, **open-source** platform for managing multiple HAProxy nodes from a single unified dashboard.

### Design Principles

| Principle | Decision |
|---|---|
| Long-term maintainability | Clean Architecture, interface-driven, full DI |
| Minimal dependency | Go standard library first; zero frameworks |
| Security first | Argon2id, AES-256-GCM, JWT rotate, rate-limit |
| Production ready | Graceful shutdown, structured logging, audit trail |
| Docker ready | Single binary + Docker Compose; multi-stage build |
| Open source friendly | MIT License, clear contribution guidelines |
| Self hosted friendly | SQLite default, no external services required |

---

## Architecture Analysis

### Why Clean Architecture?

Clean Architecture enforces **dependency inversion** — outer layers depend on inner layers, never the reverse. This means:

- Domain models never import HTTP or database packages
- Business logic (service) is testable without HTTP or DB
- Swapping SQLite → MariaDB only touches the repository layer
- Adding a new transport (gRPC, WebSocket) does not touch domain/service

```
┌─────────────────────────────────────────────────────┐
│  Transport Layer  (cmd / handler / middleware)       │
│  ┌───────────────────────────────────────────────┐  │
│  │  Application Layer  (service)                 │  │
│  │  ┌─────────────────────────────────────────┐  │  │
│  │  │  Domain Layer  (entity / interface)     │  │  │
│  │  └─────────────────────────────────────────┘  │  │
│  │  Infrastructure Layer  (repository / security)│  │
│  └───────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────┘
```

### Dependency Flow (Strict)

```
handler → service interface → repository interface → database
handler → service interface → security package
handler → middleware (auth / rate-limit / audit)
```

No handler imports repository directly.
No service imports handler.
No domain imports anything external.

### Why net/http only?

- Zero magic routing — explicit, auditable route table
- No hidden middleware chains
- Smaller binary, faster startup
- Forces engineers to understand HTTP semantics
- No framework CVE surface area

### Why SQLite default?

- Zero external service for self-hosted deployment
- WAL mode supports concurrent readers
- Single file backup is trivial
- MariaDB can be plugged in via repository interface swap

### Why AES-256-GCM for SSH keys & Cloudflare token?

- Authenticated encryption (confidentiality + integrity)
- NIST recommended for symmetric encryption
- `APP_ENCRYPTION_KEY` from environment — never stored in DB
- Each ciphertext has unique random nonce (96-bit)

### CMC Architecture (Certificate Management Center)

```
┌─────────────────────────────────────────────────────────────────┐
│  HAPM (hapm container, port 8282)                               │
│                                                                 │
│  SchedulerService ──(every 24h)──▶ CertificateService          │
│  CertificateService ──HTTP──▶ hapm-acme (internal network)     │
│  DistributionService ──SSH──▶ HAProxy Nodes (external VMs)     │
└─────────────────────────────────────────────────────────────────┘
         │ HTTP (internal Docker network, hapm_net)
         ▼
┌─────────────────────────────────────────────────────────────────┐
│  hapm-acme container (port 8889, internal only)                 │
│                                                                 │
│  LEGO CLI (v4.17.4) ──DNS-01──▶ Cloudflare API                │
│                    ──HTTP-01──▶ .well-known/acme-challenge/     │
│                                  (served by HAPM on :8282)     │
└─────────────────────────────────────────────────────────────────┘
         │ shared volume (hapm_data:/data)
         ▼
┌─────────────────────────────────────────────────────────────────┐
│  /data/storage/certificates/<uuid>/                             │
│    certificate.pem   issuer.pem   chain.pem                    │
│    private.key       metadata.json                              │
└─────────────────────────────────────────────────────────────────┘
```

**Certificate adalah resource global** — satu certificate dapat digunakan oleh banyak domain dan di-deploy ke banyak node sekaligus.

---

## API Specification

### Base URL: `/api/v1`

### Authentication

All protected endpoints require:
```
Authorization: Bearer <access_token>
```

### Response Format

```json
{
  "status": true,
  "code": 200,
  "message": "Success",
  "data": {},
  "datas": []
}
```

### Pencarian & Pagination (semua endpoint GET list)

| Parameter | Type | Default | Keterangan |
|---|---|---|---|
| `q` | string | — | Keyword pencarian (case-insensitive, multi-kolom) |
| `start` | int | `0` | Offset halaman (0-based) |
| `limit` | int | `50` | Jumlah data per halaman (max `500`) |

Response list:

```json
{
  "data": {
    "total": 100,
    "start": 0,
    "limit": 50,
    "items": []
  }
}
```

### Default Admin Credentials

```
Username: admin
Password: admin
```

---

### Auth Endpoints

| Method | Path | Role | Description |
|---|---|---|---|
| POST | `/api/v1/auth/login` | Public | Login, returns access+refresh token |
| POST | `/api/v1/auth/refresh` | Public | Refresh access token |
| GET | `/api/v1/auth/me` | Any | Profil user yang sedang login |
| POST | `/api/v1/auth/logout` | Any | Revoke refresh token |
| PUT | `/api/v1/auth/change-password` | Any | Ganti password sendiri |

---

### User Endpoints

| Method | Path | Role | Description |
|---|---|---|---|
| GET | `/api/v1/users` | SuperAdmin | List semua user |
| POST | `/api/v1/users` | SuperAdmin | Buat user baru |
| GET | `/api/v1/users/{id}` | Admin+ | Get user by ID |
| PUT | `/api/v1/users/{id}` | Admin+ | Update user |
| DELETE | `/api/v1/users/{id}` | SuperAdmin | Hapus user |
| PUT | `/api/v1/users/{id}/lock` | Admin+ | Kunci akun user |
| PUT | `/api/v1/users/{id}/unlock` | Admin+ | Buka kunci akun user |

---

### Node Endpoints

| Method | Path | Role | Description |
|---|---|---|---|
| GET | `/api/v1/nodes` | Viewer+ | List nodes |
| POST | `/api/v1/nodes` | Admin+ | Tambah node baru |
| GET | `/api/v1/nodes/{id}` | Viewer+ | Get node by ID |
| PUT | `/api/v1/nodes/{id}` | Admin+ | Update node |
| DELETE | `/api/v1/nodes/{id}` | Admin+ | Hapus node |
| POST | `/api/v1/nodes/{id}/test` | Operator+ | Test koneksi SSH |
| POST | `/api/v1/nodes/{id}/provision` | SuperAdmin | Install & setup HAProxy di node via SSH |

**Body POST/PUT node:**
```json
{
  "name": "node-1",
  "hostname": "node1.example.com",
  "ip_address": "10.0.0.1",
  "ssh_port": 22,
  "ssh_user": "root",
  "ssh_private_key": "-----BEGIN OPENSSH PRIVATE KEY-----\n...",
  "description": "...",
  "behind_cloudflare": false,
  "https_frontend_enabled": true
}
```

> `https_frontend_enabled`: `false` (default) — frontend `https_in` hanya di-generate otomatis jika ada domain dengan `ssl_mode=terminate`. `true` — selalu generate `frontend https_in` pada konfigurasi HAProxy node ini, terlepas dari konfigurasi domain.

> **Catatan SSL Cert saat Deploy**: Pipeline deploy (`POST /api/v1/nodes/{id}/deploy`) secara otomatis mendistribusikan semua SSL cert aktif yang dipakai domain ke node (`/etc/haproxy/certs/<uuid>.pem`) sebelum validasi dan reload HAProxy. Tidak perlu menjalankan endpoint deploy cert secara manual sebelum deploy config.

---

### Backend Pool Endpoints

| Method | Path | Role | Description |
|---|---|---|---|
| GET | `/api/v1/backends` | Viewer+ | List pool beserta servers |
| POST | `/api/v1/backends` | Operator+ | Buat pool baru |
| GET | `/api/v1/backends/{id}` | Viewer+ | Get pool by ID |
| PUT | `/api/v1/backends/{id}` | Operator+ | Update pool |
| DELETE | `/api/v1/backends/{id}` | Admin+ | Hapus pool |

---

### Domain Endpoints

| Method | Path | Role | Description |
|---|---|---|---|
| GET | `/api/v1/domains` | Viewer+ | List domain |
| POST | `/api/v1/domains` | Operator+ | Buat domain routing baru |
| GET | `/api/v1/domains/{id}` | Viewer+ | Get domain by ID |
| PUT | `/api/v1/domains/{id}` | Operator+ | Update domain |
| DELETE | `/api/v1/domains/{id}` | Admin+ | Hapus domain |

**Body POST/PUT domain:**
```json
{
  "domain_name": "example.com",
  "id_backend_pools": 1,
  "ssl_mode": "terminate",
  "cert_uuid": "550e8400-e29b-41d4-a716-446655440000",
  "id_auth_groups": null,
  "http_redirect": true,
  "enabled": true,
  "description": "..."
}
```

> `ssl_mode`: `none` | `terminate` | `passthrough`
> `cert_uuid`: UUID dari certificate di CMC (nullable). **Gantikan `id_ssl_certs` lama.**

---

### Domain Authentication (HAProxy Userlist)

Melindungi domain routing dengan **HTTP Basic Auth** langsung di level HAProxy.

#### Auth User Endpoints

| Method | Path | Role | Description |
|---|---|---|---|
| GET | `/api/v1/auth-users` | Auth | List auth user |
| POST | `/api/v1/auth-users` | Admin | Buat auth user baru |
| GET | `/api/v1/auth-users/{id}` | Auth | Detail auth user |
| PUT | `/api/v1/auth-users/{id}` | Admin | Update auth user |
| DELETE | `/api/v1/auth-users/{id}` | Admin | Hapus auth user |

#### Auth Group Endpoints

| Method | Path | Role | Description |
|---|---|---|---|
| GET | `/api/v1/auth-groups` | Auth | List auth group (include members) |
| POST | `/api/v1/auth-groups` | Admin | Buat auth group baru |
| GET | `/api/v1/auth-groups/{id}` | Auth | Detail group (beserta members) |
| PUT | `/api/v1/auth-groups/{id}` | Admin | Update auth group |
| DELETE | `/api/v1/auth-groups/{id}` | Admin | Hapus auth group |
| GET | `/api/v1/auth-groups/{id}/members` | Auth | List member group |
| POST | `/api/v1/auth-groups/{id}/members` | Admin | Tambah member ke group |
| DELETE | `/api/v1/auth-groups/{id}/members/{userID}` | Admin | Hapus member dari group |

---

### TCP Services / Port Balancing

| Method | Path | Role | Description |
|---|---|---|---|
| GET | `/api/v1/services` | Auth | Daftar semua service |
| POST | `/api/v1/services` | Admin | Tambah service baru |
| GET | `/api/v1/services/{id}` | Auth | Detail service |
| PUT | `/api/v1/services/{id}` | Admin | Update service |
| DELETE | `/api/v1/services/{id}` | Admin | Hapus service |

---

### Config & Deploy Endpoints

| Method | Path | Role | Description |
|---|---|---|---|
| GET | `/api/v1/nodes/{id}/config` | Admin+ | Preview config HAProxy |
| POST | `/api/v1/nodes/{id}/config/validate` | Admin+ | Validasi config via `haproxy -c` |
| POST | `/api/v1/nodes/{id}/deploy` | Admin+ | Mulai deployment ke node (async) |
| GET | `/api/v1/deployments/{id}` | Viewer+ | Get status deployment by ID |
| GET | `/api/v1/nodes/{id}/deployments` | Viewer+ | Riwayat deployment per node |

---

### Revision Endpoints

| Method | Path | Role | Description |
|---|---|---|---|
| GET | `/api/v1/nodes/{id}/revisions` | Viewer+ | List revisi config per node |
| GET | `/api/v1/nodes/{id}/revisions/{rev}` | Viewer+ | Get isi revisi |
| GET | `/api/v1/nodes/{id}/revisions/{rev}/diff` | Viewer+ | Diff dengan revisi sebelumnya |
| POST | `/api/v1/nodes/{id}/revisions/{rev}/restore` | Admin+ | Restore ke revisi ini |

---

### Replication Endpoints

| Method | Path | Role | Description |
|---|---|---|---|
| GET | `/api/v1/replication/targets` | Viewer+ | List replication targets |
| POST | `/api/v1/replication/targets` | Admin+ | Buat replication target |
| PUT | `/api/v1/replication/targets/{id}` | Admin+ | Update target |
| DELETE | `/api/v1/replication/targets/{id}` | Admin+ | Hapus target |
| POST | `/api/v1/replication/targets/{id}/push` | Operator+ | Trigger push replication |
| GET | `/api/v1/replication/drift` | Viewer+ | Cek drift config semua node |

---

### Dashboard Endpoints

| Method | Path | Role | Description |
|---|---|---|---|
| GET | `/api/v1/dashboard` | Viewer+ | Overview sistem dari DB |
| GET | `/api/v1/dashboard/nodes/stats` | Admin+ | Live HAProxy stats semua node via SSH |

---

### Monitoring Endpoints

| Method | Path | Role | Description |
|---|---|---|---|
| GET | `/api/v1/nodes/{id}/stats` | Viewer+ | HAProxy stats lengkap |
| GET | `/api/v1/nodes/{id}/stats/frontends` | Viewer+ | Frontend stats saja |
| GET | `/api/v1/nodes/{id}/stats/backends` | Viewer+ | Backend stats saja |

---

### Audit Log Endpoints

| Method | Path | Role | Description |
|---|---|---|---|
| GET | `/api/v1/audit` | Admin+ | List audit log |
| GET | `/api/v1/audit/{id}` | Admin+ | Get audit log by ID |

---

## Certificate Management Center (CMC)

HAPM adalah **Certificate Controller** untuk seluruh cluster HAProxy. Certificate dikelola secara terpusat dan di-deploy ke node melalui SSH.

### Konsep Utama

| Konsep | Penjelasan |
|---|---|
| **Certificate global** | Satu cert dapat digunakan oleh banyak domain dan di-push ke banyak node |
| **UUID identity** | Certificate diidentifikasi dengan UUID, bukan integer ID |
| **File-based storage** | File cert disimpan di filesystem (`/data/storage/certificates/<uuid>/`), bukan di DB |
| **Async jobs** | Issue/renew menggunakan goroutine; API langsung return job UUID |
| **hapm-acme** | Service Docker terpisah yang menjalankan LEGO CLI |
| **Auto-renewal** | Scheduler berjalan setiap 24 jam, auto-renew cert yang akan kadaluarsa |

### Certificate Lifecycle

```
pending → issuing → active
                  ↓ (error)
                error
active → (expired oleh scheduler)
active → (revoke manual)
       → revoked
```

### Certificate Storage (Filesystem)

```
/data/storage/certificates/
└── <uuid>/
    ├── certificate.pem    # Sertifikat server (DER/PEM dari CA)
    ├── private.key        # Private key (mode 0600, TIDAK pernah dikirim ke frontend)
    ├── chain.pem          # Intermediate chain
    ├── issuer.pem         # CA root certificate
    └── metadata.json      # Fingerprint, NotBefore, NotAfter, domains
```

HAProxy bundle (untuk deployment):
```
cat certificate.pem chain.pem private.key > /etc/haproxy/certs/<uuid>.pem
```

### CMC REST API

Prefix `/api/v1/ssl/` dipertahankan untuk kompatibilitas frontend.

#### Certificate Endpoints

| Method | Path | Role | Description |
|---|---|---|---|
| GET | `/api/v1/ssl/providers` | Any | Daftar provider (letsencrypt, manual) |
| GET | `/api/v1/ssl/certificates` | Viewer+ | List semua certificate |
| POST | `/api/v1/ssl/certificates` | Admin+ | Buat entri certificate baru (belum issue) |
| GET | `/api/v1/ssl/certificates/{uuid}` | Viewer+ | Detail certificate |
| PUT | `/api/v1/ssl/certificates/{uuid}` | Admin+ | Update metadata certificate |
| DELETE | `/api/v1/ssl/certificates/{uuid}` | Admin+ | Hapus certificate + file |
| POST | `/api/v1/ssl/certificates/{uuid}/issue` | Admin+ | Mulai penerbitan (async → return job) |
| POST | `/api/v1/ssl/certificates/{uuid}/renew` | Admin+ | Mulai renewal (async → return job) |
| POST | `/api/v1/ssl/certificates/{uuid}/revoke` | Admin+ | Revoke certificate |
| POST | `/api/v1/ssl/certificates/{uuid}/deploy` | Admin+ | Deploy cert ke node(s) via SSH |
| GET | `/api/v1/ssl/certificates/{uuid}/deployments` | Viewer+ | Riwayat deployment cert ini |
| GET | `/api/v1/ssl/certificates/{uuid}/jobs` | Viewer+ | Riwayat jobs cert ini |
| POST | `/api/v1/ssl/upload` | Admin+ | Upload certificate manual (PEM) |
| GET | `/api/v1/ssl/jobs` | Viewer+ | Semua jobs (limit 50) |
| GET | `/api/v1/ssl/jobs/{uuid}` | Viewer+ | Detail job (untuk polling) |
| GET | `/.well-known/acme-challenge/{token}` | Public | HTTP-01 ACME challenge |

#### Buat Certificate (Let's Encrypt DNS-01 Wildcard)

```json
POST /api/v1/ssl/certificates
{
  "name": "wildcard-example",
  "provider": "letsencrypt",
  "challenge": "dns01",
  "domains": ["*.example.com", "example.com"],
  "primary_domain": "example.com",
  "zone": "example.com",
  "dns_provider": "cloudflare",
  "renew_before": 30,
  "auto_renew": true
}
```

> Wildcard (`*.example.com`) **hanya** bisa menggunakan `challenge: "dns01"`. Mencoba HTTP-01 akan ditolak dengan error.

#### Buat Certificate (Let's Encrypt HTTP-01)

```json
POST /api/v1/ssl/certificates
{
  "name": "cert-app",
  "provider": "letsencrypt",
  "challenge": "http01",
  "domains": ["app.example.com"],
  "primary_domain": "app.example.com",
  "renew_before": 30,
  "auto_renew": true
}
```

#### Issue Certificate (async)

```json
POST /api/v1/ssl/certificates/550e8400-e29b-41d4-a716-446655440000/issue
```

Response langsung (tidak menunggu selesai):
```json
{
  "status": true,
  "code": 201,
  "message": "Proses penerbitan certificate dimulai",
  "data": {
    "uuid": "job-uuid-here",
    "cert_uuid": "550e8400-e29b-41d4-a716-446655440000",
    "job_type": "issue",
    "status": "pending",
    "created": "2026-07-09T10:00:00Z"
  }
}
```

Poll job status di `GET /api/v1/ssl/jobs/{job_uuid}`:
```json
{
  "data": {
    "uuid": "job-uuid",
    "status": "success",
    "logs": "...",
    "started_at": "2026-07-09T10:00:01Z",
    "finished_at": "2026-07-09T10:00:45Z"
  }
}
```

#### Deploy Certificate ke Node

```json
POST /api/v1/ssl/certificates/{uuid}/deploy
{
  "node_ids": [1, 2, 3]
}
```

Jika `node_ids` kosong atau tidak disertakan → deploy ke **semua node** secara paralel.

Proses deployment per node:
1. Build HAProxy bundle: `certificate.pem + chain.pem + private.key`
2. Upload ke node via SSH: `/etc/haproxy/certs/<uuid>.pem`
3. Graceful reload HAProxy: `haproxy -sf $(cat /var/run/haproxy.pid) || systemctl reload haproxy`

#### Upload Certificate Manual

```json
POST /api/v1/ssl/upload
{
  "name": "cert-internal",
  "cert_pem": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----",
  "key_pem": "-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----",
  "chain_pem": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----"
}
```

> `chain_pem` opsional. Fingerprint dan tanggal expiry diekstrak otomatis dari `cert_pem`.

### HTTP-01 Challenge Setup

Untuk HTTP-01, Let's Encrypt perlu mengakses `http://<domain>/.well-known/acme-challenge/<token>` dari internet.

**Konfigurasi HAProxy node** — arahkan traffic ACME challenge ke HAPM controller:

```haproxy
frontend http_in
    bind *:80
    # ACME challenge diarahkan ke HAPM controller
    acl is_acme_challenge path_beg /.well-known/acme-challenge/
    use_backend hapm_acme_backend if is_acme_challenge
    ...

backend hapm_acme_backend
    server hapm-controller <CMC_CHALLENGE_ADDR>
```

Set `CMC_CHALLENGE_ADDR` ke IP:PORT HAPM controller yang dapat dijangkau dari internet (contoh: `203.0.113.10:8282`).

### DNS-01 (Cloudflare) Setup

1. Daftarkan Cloudflare API Token:
   ```
   PUT /api/v1/settings/cloudflare
   { "api_token": "your-cloudflare-api-token" }
   ```

2. Test koneksi:
   ```
   POST /api/v1/settings/cloudflare/test
   ```

3. Discover zones:
   ```
   GET /api/v1/settings/cloudflare/zones
   ```

4. Buat certificate dengan `challenge: "dns01"` dan `zone: "example.com"`.

> **Keamanan**: Token dienkripsi AES-256-GCM sebelum disimpan di DB. Token **tidak pernah dikembalikan** ke frontend. HAPM mendekripsi token saat dibutuhkan oleh hapm-acme.

### Auto-Renewal Scheduler

- Berjalan pertama kali saat startup, lalu setiap **24 jam**
- Mencari certificate dengan `expires_at - renew_before days <= NOW()` dan `auto_renew=1`
- Untuk setiap cert yang perlu diperbarui:
  1. Panggil `CertificateService.Renew()` (async job)
  2. Tunggu 5 menit
  3. Panggil `DistributionService.DistributeToAll()` untuk mendistribusi cert baru

---

### Settings Endpoints

| Method | Path | Role | Description |
|---|---|---|---|
| PUT | `/api/v1/settings/cloudflare` | SuperAdmin | Simpan Cloudflare API Token (encrypted) |
| POST | `/api/v1/settings/cloudflare/test` | Admin+ | Test koneksi Cloudflare API |
| GET | `/api/v1/settings/cloudflare/zones` | Admin+ | Daftar zona Cloudflare |
| PUT | `/api/v1/settings/acme` | SuperAdmin | Set ACME email + staging flag |
| GET | `/api/v1/settings/acme` | Admin+ | Get ACME settings (email + staging) |

**PUT /api/v1/settings/cloudflare**
```json
{ "api_token": "cf_xxxxxx" }
```
> Token dienkripsi AES-256-GCM sebelum disimpan. Tidak pernah dikembalikan ke frontend.

**PUT /api/v1/settings/acme**
```json
{ "email": "admin@example.com", "staging": false }
```

**GET /api/v1/settings/acme** → Response:
```json
{ "email": "admin@example.com", "staging": false }
```

> `staging: true` menggunakan Let's Encrypt staging server (untuk testing — tidak menghasilkan cert valid).

---

## Advanced Health Checks

Backend Pool mendukung berbagai metode health check. Lihat field `health_check_type` dan `health_check_config` di Backend Pool.

| Type | HAProxy Directive |
|---|---|
| `none` | — |
| `TCP` | `check` |
| `HTTP` | `option httpchk` |
| `HTTPS` | `option httpchk` + `ssl verify none check` |
| `SSH` | `option tcp-check` + `tcp-check expect rstring SSH-2.0-OpenSSH.*` |
| `MYSQL` | `option mysql-check user <user>` |
| `POSTGRESQL` | `option pgsql-check user <user>` |
| `REDIS` | `option tcp-check` + PING/PONG |
| `CUSTOM` | raw directives dari `health_check_config.custom` |

---

## Backend HTTPS & Forward Headers

### Field Reference

#### `protocol`

| Nilai | Kegunaan |
|---|---|
| `http` | Backend biasa tanpa SSL (default) |
| `https` | Backend menggunakan SSL |
| `tcp` | Pass-through TCP murni |

#### `ssl_mode`

Hanya berlaku jika `protocol=https`.

| Nilai | HAProxy Directive | Kapan |
|---|---|---|
| `none` | — | Bukan https |
| `trusted` | `ssl verify required` | Backend pakai cert CA tepercaya |
| `self_signed` | `ssl verify none` | Backend pakai self-signed |

#### `forward_headers`

| Nilai | Efek |
|---|---|
| `true` (default) | Tambah `X-Forwarded-Proto`, `X-Forwarded-Ssl`, `X-Forwarded-Port` + deteksi Cloudflare |
| `false` | Tidak ada header tambahan |

### Panduan Pemilihan

| Skenario | `protocol` | `ssl_mode` | `forward_headers` |
|---|---|---|---|
| Web app PHP/Node di port 80 | `http` | — | `true` |
| CyberPanel / OLS dengan HTTPS | `https` | `self_signed` | `true` |
| Backend dengan Let's Encrypt | `https` | `trusted` | `true` |
| Database (MySQL, PG, Redis) | `tcp` | — | `false` |
| SSH cluster | `tcp` | — | `false` |

---

## Security Design

### Authentication Flow

```
POST /api/v1/auth/login
  → Rate limit check (5 req/min per IP)
  → Account lockout check (5 failures → lock 15min)
  → Argon2id password verify
  → Generate access_token (JWT, 15min, HS512)
  → Generate refresh_token (JWT, 7d, HS512, stored as SHA256 hash in DB)
  → Log audit: user.login
  → Return both tokens
```

### JWT Design

```
Access Token:
  Algorithm: HS512 | Expiry: 15m | Claims: id_users, username, role
  Stateless — stored client-side only

Refresh Token:
  Algorithm: HS512 | Expiry: 7d | Claims: id_users, jti
  SHA256(token) stored in DB — single use, rotates on refresh
```

### Password Hashing (Argon2id)

```
memory: 64MB | iterations: 3 | parallelism: 2
salt: 16 bytes (crypto/rand) | output: $argon2id$v=19$m=65536,t=3,p=2$...
```

### SSH Key & Cloudflare Token Encryption (AES-256-GCM)

```
Key source: APP_ENCRYPTION_KEY (32-byte hex, from environment — NEVER stored)
Nonce:      96-bit random per encryption (crypto/rand)
Ciphertext: base64(nonce + encrypted_data + auth_tag)
```

Private keys never logged. Cloudflare token never returned to frontend.

### Private Key Security

- Private key file disimpan dengan mode `0600`
- Private key **tidak pernah** dikembalikan melalui API endpoint manapun
- HAProxy bundle dikirim ke node via SSH dengan enkripsi in-transit
- `/data/storage/certificates/` hanya accessible oleh proses hapm dan hapm-acme

### Rate Limiting

```
Login:          5 req/min per IP (DB-backed, persists restart)
Account lockout: 5 failures → locked 15 minutes
API general:    100 req/min per IP (in-memory sliding window)
```

### RBAC

```
SuperAdmin → full access, user management, system config, settings
Admin      → node management, deploy, CMC certificates
Operator   → backend/domain CRUD, deploy, monitoring
Viewer     → read-only
```

---

## Backend Implementation Plan

### Phase 1: Foundation ✅
- `go.mod` with module `github.com/aefw/hapm`
- `internal/config/` — env-based config
- `internal/core/` — app server, router, response helpers
- `internal/security/` — argon2, aes, jwt, random

### Phase 2: Database ✅
- SQLite WAL mode setup
- Migration runner (sequential, idempotent, v1–v32)
- All repository interfaces defined first
- SQLite implementations

### Phase 3: Domain + Service ✅
- All domain entities
- All service interfaces
- Auth + User service

### Phase 4: HTTP Layer ✅
- Route registration (explicit mux)
- Auth handler + middleware
- RBAC middleware + rate limit

### Phase 5: Core Features ✅
- Node management + SSH provision
- Backend pools + servers
- Domain management
- CMC certificate management (replaces old SSL)

### Phase 6: HAProxy Engine ✅
- Config generator
- Deploy pipeline (6-stage + rollback)
- Revision management

### Phase 7: Advanced Features ✅
- Push replication + drift detection
- HAProxy stats monitoring
- CMC auto-renewal scheduler
- CMC distribution service (SSH push to nodes)

### Phase 8: CMC (Certificate Management Center) ✅
- `hapm-acme` Docker service (LEGO CLI wrapper)
- `pkg/acme/client.go` — HTTP client ke hapm-acme
- `pkg/storage/cert_store.go` — file-based cert storage
- `internal/service/settings_service.go` — Cloudflare token (encrypted)
- `internal/service/certificate_service.go` — async jobs
- `internal/service/distribution_service.go` — SSH push to nodes
- `internal/service/scheduler_service.go` — 24h renewal checker
- `internal/handler/cmc_handler.go` — REST API
- `internal/handler/settings_handler.go` — Cloudflare + ACME settings
- Migration v27–v32: settings, certificate_storage, certificate_jobs, certificate_deployments, domains rebuild, drop ssl_certs

---

## Frontend Implementation Plan

### Tech Stack
- Framework7 (CLI Core) for UI components
- Capacitor for mobile PWA packaging
- PWA manifest + service worker

### Pages

```
/ → Dashboard (node overview, status cards)
/nodes → Node list + status indicators
/nodes/:id → Node detail + deploy button
/nodes/:id/provision → Provisioning wizard
/backends → Backend pool list
/backends/:id → Pool detail + server list
/domains → Domain list
/ssl → Certificate list (CMC)
/ssl/:uuid → Certificate detail + jobs + deployments
/ssl/:uuid/deploy → Deploy wizard (pilih node atau semua)
/settings → System settings (Cloudflare, ACME)
/config/:node_id → Config preview
/deploy/:node_id → Deploy wizard
/revisions/:node_id → Revision history + diff viewer
/replication → Replication topology view
/monitoring/:node_id → Real-time stats dashboard
/audit → Audit log table
/users → User management (SuperAdmin only)
/auth-users → HAProxy auth users
/auth-groups → HAProxy auth groups
```

### CMC Frontend Flow

**Buat + Issue certificate (DNS-01):**
1. Cek settings: `GET /api/v1/settings/acme` — pastikan email sudah diset
2. Cek Cloudflare: `POST /api/v1/settings/cloudflare/test`
3. Discover zones: `GET /api/v1/settings/cloudflare/zones`
4. Buat cert: `POST /api/v1/ssl/certificates`
5. Issue: `POST /api/v1/ssl/certificates/{uuid}/issue` → dapat job UUID
6. Poll setiap 3 detik: `GET /api/v1/ssl/jobs/{job_uuid}` hingga `status` = `success` atau `failed`
7. Deploy: `POST /api/v1/ssl/certificates/{uuid}/deploy` (tanpa body = semua node)

**Assign certificate ke domain:**
1. `GET /api/v1/ssl/certificates` — pilih cert dengan status `active`
2. `PUT /api/v1/domains/{id}` → `{ "cert_uuid": "<uuid>", "ssl_mode": "terminate" }`
3. Deploy konfigurasi HAProxy: `POST /api/v1/nodes/{id}/deploy`

### Real-time Strategy
- Job status: polling setiap 3 detik via `GET /api/v1/ssl/jobs/{uuid}`
- Deploy status: polling setiap 2 detik via `GET /api/v1/deployments/{id}`
- Monitoring stats: polling setiap 5 detik
- No WebSocket required

---

## Docker Deployment Plan

### Services

```yaml
services:
  hapm:         # HAPM API Server + frontend, port 8282
  hapm-acme:    # ACME worker (LEGO CLI), internal only port 8889
```

### hapm-acme

- Container **tidak di-expose** ke host — hanya accessible via internal Docker network `hapm_net`
- `hapm` hanya dapat berkomunikasi dengan `hapm-acme` melalui `http://hapm-acme:8889`
- Health check: `wget -qO- http://localhost:8889/internal/health`
- `hapm` menunggu `hapm-acme` healthy sebelum start (`depends_on: condition: service_healthy`)

### Volumes

```
hapm_data:/data
  ├── hapm.db                          # SQLite database
  ├── storage/certificates/<uuid>/     # Certificate files (hapm + hapm-acme)
  └── acme-webroot/.well-known/        # HTTP-01 challenge files (hapm-acme writes, hapm serves)
```

### Environment Variables

**Wajib:**
```env
APP_ENCRYPTION_KEY=<32-byte-hex>         # untuk encrypt SSH key + Cloudflare token
APP_JWT_ACCESS_SECRET=<random-64-char>
APP_JWT_REFRESH_SECRET=<random-64-char>
```

**CMC:**
```env
CMC_ACME_SERVICE_URL=http://hapm-acme:8889    # URL hapm-acme (internal Docker network)
CMC_CHALLENGE_ADDR=<ip:port>                   # IP:port HAPM yg bisa diakses internet (HTTP-01)
```

**Opsional:**
```env
APP_PORT=8282
APP_MODE=production
APP_JWT_ACCESS_EXPIRY=15m
APP_JWT_REFRESH_EXPIRY=168h
APP_LOG_LEVEL=info
APP_LOG_FORMAT=json
APP_PROXY_MODE=direct        # direct|proxy|cloudflare
APP_RATE_LIMIT_LOGIN_PER_MINUTE=5
APP_RATE_LIMIT_API_PER_MINUTE=120
```

### Quick Start

```bash
cp .env.example .env
# Edit .env — isi APP_ENCRYPTION_KEY, JWT secrets, admin password
docker compose up -d
```

---

## Development Task List

### Sprint 1 — Foundation ✅
- [x] Architecture design & documentation
- [x] `go.mod` init, folder scaffold
- [x] `internal/config/` — env loader
- [x] `internal/core/` — app, router, response, request, context
- [x] `internal/security/` — argon2, aes, jwt, random

### Sprint 2 — Database ✅
- [x] SQLite WAL mode, MaxOpenConns=10
- [x] Migration runner (v1–v32)
- [x] Semua repository interfaces + SQLite implementations

### Sprint 3 — Domain + Auth ✅
- [x] Auth service, User service
- [x] JWT middleware, RBAC middleware, rate-limit middleware

### Sprint 4 — Core Resources ✅
- [x] Node CRUD + SSH test + provision
- [x] Backend pool + server CRUD
- [x] Domain CRUD + ssl_mode validation

### Sprint 5 — HAProxy Engine ✅
- [x] Config generator (modern TLS, HSTS, Cloudflare header, ACME challenge)
- [x] HAProxy provisioner (Debian/Ubuntu + RHEL, HAProxy 3.x)
- [x] Deploy pipeline async (6 stages: generate → validate → backup → upload → reload → verify)
- [x] Auto rollback jika reload/verify gagal
- [x] Revision management (list, get, diff, restore)

### Sprint 6 — Advanced ✅
- [x] HAProxy stats per node
- [x] Push replication (source → target node)
- [x] Drift detection (live config vs generated)
- [x] Backend HTTPS & Forward Headers (protocol, ssl_mode, forward_headers)

### Sprint 7 — CMC (Certificate Management Center) ✅
- [x] **HAPUS** old SSL subsystem (`ssl.go`, `ssl_handler.go`, `ssl_service.go`, `ssl_repo.go`)
- [x] `internal/domain/certificate.go` — domain model CMC
- [x] `internal/repository/sqlite/certificate_repo.go` — CertificateRepository, CertJobRepository, CertDeploymentRepository
- [x] `internal/repository/sqlite/settings_repo.go` — SettingRepository (upsert)
- [x] `pkg/storage/cert_store.go` — file-based storage (UUID dirs, fingerprint, dates)
- [x] `pkg/acme/client.go` — HTTP client ke hapm-acme
- [x] `internal/service/settings_service.go` — Cloudflare (encrypted), ACME email/staging
- [x] `internal/service/certificate_service.go` — async issue/renew/revoke
- [x] `internal/service/cert_job_service.go` — job query wrapper
- [x] `internal/service/distribution_service.go` — SSH push ke HAProxy nodes
- [x] `internal/service/scheduler_service.go` — 24h auto-renewal checker
- [x] `internal/handler/cmc_handler.go` — semua CMC REST endpoints + HTTP-01 challenge
- [x] `internal/handler/settings_handler.go` — Cloudflare + ACME settings endpoints
- [x] `cmd/hapm-acme/main.go` — ACME worker service (LEGO CLI wrapper)
- [x] `Dockerfile.acme` — multi-stage build untuk hapm-acme + LEGO v4.17.4
- [x] `docker-compose.yml` — tambah hapm-acme service + shared volume
- [x] Migration v27–v32: settings, certificate_storage, certificate_jobs, certificate_deployments, domains rebuild (cert_uuid), drop ssl_certs
- [x] Update domain_repo.go → cert_uuid (TEXT)
- [x] Update config_service.go, dashboard_service.go, domain_service.go → CMC types
- [x] Update pkg/haproxy/generator.go → `[]*domain.Certificate`
- [x] Update cmd/hapm/main.go — DI wiring CMC services
- [x] README.md — dokumentasi CMC lengkap

### Sprint 8 — Frontend ✅
- [x] Framework7 project setup
- [x] PWA manifest + service worker
- [x] Semua halaman implementasi (termasuk CMC pages)
- [x] `web/embed.go` — embed frontend ke binary via Go embed
- [x] `web/handler.go` — SPA handler dengan fallback index.html
- [x] `web/dist/` — hasil build Framework7 ter-embed di binary

### Sprint 9 — Docker + Polish ✅
- [x] Makefile (termasuk `build-frontend`, `build-all`)
- [x] Health check endpoint (`-health` flag)
- [x] Graceful shutdown (SIGINT/SIGTERM)
- [x] Docker: single binary scratch image, serve UI + API pada port 8282

### Sprint 10 — HTTPS Frontend Control + Auto Cert Push ✅
- [x] Migration v33: kolom `https_frontend_enabled` pada tabel `nodes`
- [x] Field `https_frontend_enabled` pada `Node`, `NodeSummary`, `CreateNodeRequest`, `UpdateNodeRequest`
- [x] Generator HAProxy: generate `frontend https_in` jika `hasSSLTerminate || node.HTTPSFrontendEnabled`
- [x] Deploy pipeline: push semua SSL cert aktif ke node sebelum `haproxy -c` (validasi) dan reload
- [x] Cert push otomatis di `deployService.pushCertsToNode()` — non-fatal, paralel per cert UUID

---

## Tech Decisions Log

| Decision | Rationale |
|---|---|
| `net/http` only | Zero framework CVE, full HTTP semantics control, minimal binary |
| `modernc.org/sqlite` | Pure Go SQLite driver, CGO_ENABLED=0, static binary possible |
| Argon2id over bcrypt | OWASP recommended, memory-hard, GPU-resistant |
| AES-256-GCM over AES-CBC | Authenticated encryption, prevents ciphertext tampering |
| JWT HS512 | Faster than RS256 for symmetric use, stronger than HS256 |
| Short-lived access token (15m) | Minimize exposure window; refresh token rotates |
| Database as source of truth | HAProxy cfg is generated artifact; prevents config drift |
| Idempotent provisioning | Safe to re-run; convergent state management |
| go:embed for web assets | Single binary deployment; no separate static file server |
| SHA256 for refresh token storage | Never store raw token; breach-resistant |
| LEGO CLI via os/exec (not library) | Zero new Go transitive deps; LEGO CLI is battle-tested and self-contained |
| hapm-acme as separate container | Isolation; LEGO needs network egress to CA — separate from main app |
| UUID for certificate identity | Global resource semantics; no integer ID collision across nodes |
| File-based cert storage | Private key never in DB; easier backup/audit; HAProxy bundle is trivial to build |
| Optimistic locking (locked column) | Prevent concurrent ACME operations on same cert without distributed lock |
| DNS-01 + Cloudflare for wildcard | Only supported challenge method for `*.domain.com` |
| Cloudflare token never returned | AES-256-GCM at rest + never in API response — defense in depth |
