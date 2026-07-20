package sqlite

import (
	"database/sql"
	"fmt"
	"log"
)

// migration mendefinisikan satu langkah migrasi schema
type migration struct {
	version int
	name    string
	sql     string
}

// migrations adalah daftar migrasi berurutan.
// WAJIB append-only — jangan pernah edit migrasi yang sudah ada.
var migrations = []migration{
	{
		version: 1,
		name:    "create_schema_migrations",
		sql: `
CREATE TABLE IF NOT EXISTS schema_migrations (
    version   INTEGER PRIMARY KEY,
    name      TEXT    NOT NULL,
    applied_at DATETIME DEFAULT CURRENT_TIMESTAMP
)`,
	},
	{
		version: 2,
		name:    "create_users",
		sql: `
CREATE TABLE IF NOT EXISTS users (
    id_users   INTEGER  PRIMARY KEY AUTOINCREMENT,
    username   TEXT     NOT NULL UNIQUE,
    email      TEXT     NOT NULL UNIQUE,
    password   TEXT     NOT NULL,
    full_name  TEXT     NOT NULL DEFAULT '',
    role       TEXT     NOT NULL DEFAULT 'viewer',
    active     INTEGER  NOT NULL DEFAULT 1,
    locked     INTEGER  NOT NULL DEFAULT 0,
    lock_until DATETIME,
    last_login DATETIME,
    created    DATETIME DEFAULT CURRENT_TIMESTAMP,
    timestamp  DATETIME DEFAULT CURRENT_TIMESTAMP
)`,
	},
	{
		version: 3,
		name:    "create_refresh_tokens",
		sql: `
CREATE TABLE IF NOT EXISTS refresh_tokens (
    id_refresh_tokens INTEGER  PRIMARY KEY AUTOINCREMENT,
    id_users          INTEGER  NOT NULL,
    token_hash        TEXT     NOT NULL UNIQUE,
    expires_at        DATETIME NOT NULL,
    revoked           INTEGER  NOT NULL DEFAULT 0,
    created           DATETIME DEFAULT CURRENT_TIMESTAMP,
    timestamp         DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (id_users) REFERENCES users(id_users) ON DELETE CASCADE
)`,
	},
	{
		version: 4,
		name:    "create_login_attempts",
		sql: `
CREATE TABLE IF NOT EXISTS login_attempts (
    id_login_attempts INTEGER  PRIMARY KEY AUTOINCREMENT,
    ip_address        TEXT     NOT NULL,
    username          TEXT,
    success           INTEGER  NOT NULL DEFAULT 0,
    created           DATETIME DEFAULT CURRENT_TIMESTAMP,
    timestamp         DATETIME DEFAULT CURRENT_TIMESTAMP
)`,
	},
	{
		version: 5,
		name:    "create_nodes",
		sql: `
CREATE TABLE IF NOT EXISTS nodes (
    id_nodes        INTEGER  PRIMARY KEY AUTOINCREMENT,
    name            TEXT     NOT NULL UNIQUE,
    hostname        TEXT     NOT NULL,
    ip_address      TEXT     NOT NULL,
    ssh_port        INTEGER  NOT NULL DEFAULT 22,
    ssh_user        TEXT     NOT NULL DEFAULT 'root',
    ssh_private_key TEXT,
    description     TEXT,
    status          TEXT     NOT NULL DEFAULT 'unknown',
    last_checked    DATETIME,
    haproxy_version TEXT,
    created         DATETIME DEFAULT CURRENT_TIMESTAMP,
    timestamp       DATETIME DEFAULT CURRENT_TIMESTAMP
)`,
	},
	{
		version: 6,
		name:    "create_backend_pools",
		sql: `
CREATE TABLE IF NOT EXISTS backend_pools (
    id_backend_pools INTEGER  PRIMARY KEY AUTOINCREMENT,
    name             TEXT     NOT NULL UNIQUE,
    description      TEXT,
    algorithm        TEXT     NOT NULL DEFAULT 'roundrobin',
    timeout_connect  INTEGER  NOT NULL DEFAULT 5000,
    timeout_server   INTEGER  NOT NULL DEFAULT 50000,
    health_check     INTEGER  NOT NULL DEFAULT 1,
    created          DATETIME DEFAULT CURRENT_TIMESTAMP,
    timestamp        DATETIME DEFAULT CURRENT_TIMESTAMP
)`,
	},
	{
		version: 7,
		name:    "create_backend_servers",
		sql: `
CREATE TABLE IF NOT EXISTS backend_servers (
    id_backend_servers INTEGER  PRIMARY KEY AUTOINCREMENT,
    id_backend_pools   INTEGER  NOT NULL,
    name               TEXT     NOT NULL,
    ip_address         TEXT     NOT NULL,
    port               INTEGER  NOT NULL DEFAULT 80,
    weight             INTEGER  NOT NULL DEFAULT 1,
    backup             INTEGER  NOT NULL DEFAULT 0,
    enabled            INTEGER  NOT NULL DEFAULT 1,
    created            DATETIME DEFAULT CURRENT_TIMESTAMP,
    timestamp          DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (id_backend_pools) REFERENCES backend_pools(id_backend_pools) ON DELETE CASCADE
)`,
	},
	{
		version: 8,
		name:    "create_ssl_certs",
		sql: `
CREATE TABLE IF NOT EXISTS ssl_certs (
    id_ssl_certs INTEGER  PRIMARY KEY AUTOINCREMENT,
    name         TEXT     NOT NULL UNIQUE,
    domain       TEXT     NOT NULL,
    cert_type    TEXT     NOT NULL DEFAULT 'upload',
    cert_pem     TEXT     NOT NULL,
    not_before   DATETIME,
    not_after    DATETIME,
    auto_renew   INTEGER  NOT NULL DEFAULT 0,
    dns_provider TEXT,
    acme_account TEXT,
    created      DATETIME DEFAULT CURRENT_TIMESTAMP,
    timestamp    DATETIME DEFAULT CURRENT_TIMESTAMP
)`,
	},
	{
		version: 9,
		name:    "create_domains",
		sql: `
CREATE TABLE IF NOT EXISTS domains (
    id_domains       INTEGER  PRIMARY KEY AUTOINCREMENT,
    domain_name      TEXT     NOT NULL UNIQUE,
    id_backend_pools INTEGER  NOT NULL,
    ssl_mode         TEXT     NOT NULL DEFAULT 'none',
    id_ssl_certs     INTEGER,
    http_redirect    INTEGER  NOT NULL DEFAULT 1,
    enabled          INTEGER  NOT NULL DEFAULT 1,
    description      TEXT,
    created          DATETIME DEFAULT CURRENT_TIMESTAMP,
    timestamp        DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (id_backend_pools) REFERENCES backend_pools(id_backend_pools),
    FOREIGN KEY (id_ssl_certs) REFERENCES ssl_certs(id_ssl_certs)
)`,
	},
	{
		version: 10,
		name:    "create_config_revisions",
		sql: `
CREATE TABLE IF NOT EXISTS config_revisions (
    id_config_revisions INTEGER  PRIMARY KEY AUTOINCREMENT,
    id_nodes            INTEGER  NOT NULL,
    revision_number     INTEGER  NOT NULL,
    config_content      TEXT     NOT NULL,
    comment             TEXT,
    id_users            INTEGER  NOT NULL,
    deployed            INTEGER  NOT NULL DEFAULT 0,
    created             DATETIME DEFAULT CURRENT_TIMESTAMP,
    timestamp           DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (id_nodes) REFERENCES nodes(id_nodes) ON DELETE CASCADE,
    FOREIGN KEY (id_users) REFERENCES users(id_users)
)`,
	},
	{
		version: 11,
		name:    "create_deployments",
		sql: `
CREATE TABLE IF NOT EXISTS deployments (
    id_deployments      INTEGER  PRIMARY KEY AUTOINCREMENT,
    id_nodes            INTEGER  NOT NULL,
    id_config_revisions INTEGER  NOT NULL,
    id_users            INTEGER  NOT NULL,
    status              TEXT     NOT NULL DEFAULT 'pending',
    stage               TEXT,
    error_message       TEXT,
    started_at          DATETIME,
    finished_at         DATETIME,
    created             DATETIME DEFAULT CURRENT_TIMESTAMP,
    timestamp           DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (id_nodes) REFERENCES nodes(id_nodes),
    FOREIGN KEY (id_config_revisions) REFERENCES config_revisions(id_config_revisions),
    FOREIGN KEY (id_users) REFERENCES users(id_users)
)`,
	},
	{
		version: 12,
		name:    "create_replication_targets",
		sql: `
CREATE TABLE IF NOT EXISTS replication_targets (
    id_replication_targets INTEGER  PRIMARY KEY AUTOINCREMENT,
    id_nodes_source        INTEGER  NOT NULL,
    id_nodes_target        INTEGER  NOT NULL,
    sync_frontends         INTEGER  NOT NULL DEFAULT 1,
    sync_backends          INTEGER  NOT NULL DEFAULT 1,
    sync_ssl               INTEGER  NOT NULL DEFAULT 1,
    sync_maps              INTEGER  NOT NULL DEFAULT 1,
    enabled                INTEGER  NOT NULL DEFAULT 1,
    created                DATETIME DEFAULT CURRENT_TIMESTAMP,
    timestamp              DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (id_nodes_source) REFERENCES nodes(id_nodes),
    FOREIGN KEY (id_nodes_target) REFERENCES nodes(id_nodes)
)`,
	},
	{
		version: 13,
		name:    "create_replication_jobs",
		sql: `
CREATE TABLE IF NOT EXISTS replication_jobs (
    id_replication_jobs    INTEGER  PRIMARY KEY AUTOINCREMENT,
    id_replication_targets INTEGER  NOT NULL,
    id_users               INTEGER,
    status                 TEXT     NOT NULL DEFAULT 'pending',
    error_message          TEXT,
    started_at             DATETIME,
    finished_at            DATETIME,
    created                DATETIME DEFAULT CURRENT_TIMESTAMP,
    timestamp              DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (id_replication_targets) REFERENCES replication_targets(id_replication_targets)
)`,
	},
	{
		version: 14,
		name:    "create_drift_reports",
		sql: `
CREATE TABLE IF NOT EXISTS drift_reports (
    id_drift_reports INTEGER  PRIMARY KEY AUTOINCREMENT,
    id_nodes         INTEGER  NOT NULL,
    live_config_hash TEXT     NOT NULL,
    db_config_hash   TEXT     NOT NULL,
    drift_detected   INTEGER  NOT NULL DEFAULT 0,
    checked_at       DATETIME NOT NULL,
    created          DATETIME DEFAULT CURRENT_TIMESTAMP,
    timestamp        DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (id_nodes) REFERENCES nodes(id_nodes)
)`,
	},
	{
		version: 15,
		name:    "create_audit_logs",
		sql: `
CREATE TABLE IF NOT EXISTS audit_logs (
    id_audit_logs INTEGER  PRIMARY KEY AUTOINCREMENT,
    id_users      INTEGER,
    action        TEXT     NOT NULL,
    resource_type TEXT,
    resource_id   INTEGER,
    detail        TEXT,
    ip_address    TEXT,
    user_agent    TEXT,
    created       DATETIME DEFAULT CURRENT_TIMESTAMP,
    timestamp     DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (id_users) REFERENCES users(id_users)
)`,
	},
	{
		version: 16,
		name:    "create_indexes",
		sql: `
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_user   ON refresh_tokens(id_users);
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_hash   ON refresh_tokens(token_hash);
CREATE INDEX IF NOT EXISTS idx_login_attempts_ip     ON login_attempts(ip_address);
CREATE INDEX IF NOT EXISTS idx_login_attempts_user   ON login_attempts(username);
CREATE INDEX IF NOT EXISTS idx_backend_servers_pool  ON backend_servers(id_backend_pools);
CREATE INDEX IF NOT EXISTS idx_domains_pool          ON domains(id_backend_pools);
CREATE INDEX IF NOT EXISTS idx_config_revisions_node ON config_revisions(id_nodes);
CREATE INDEX IF NOT EXISTS idx_deployments_node      ON deployments(id_nodes);
CREATE INDEX IF NOT EXISTS idx_drift_reports_node    ON drift_reports(id_nodes);
CREATE INDEX IF NOT EXISTS idx_audit_logs_user       ON audit_logs(id_users);
CREATE INDEX IF NOT EXISTS idx_audit_logs_action     ON audit_logs(action)`,
	},
	{
		version: 17,
		name:    "nodes_add_behind_cloudflare",
		sql:     `ALTER TABLE nodes ADD COLUMN behind_cloudflare INTEGER NOT NULL DEFAULT 0`,
	},
	{
		version: 18,
		name:    "ssl_certs_add_id_nodes",
		sql:     `ALTER TABLE ssl_certs ADD COLUMN id_nodes INTEGER REFERENCES nodes(id_nodes)`,
	},
	{
		version: 19,
		name:    "deployments_nullable_revision",
		// SQLite tidak mendukung ALTER COLUMN, perlu recreate table.
		// id_config_revisions dibuat nullable agar deploy bisa dimulai sebelum revision tersimpan.
		sql: `
CREATE TABLE IF NOT EXISTS deployments_v2 (
    id_deployments      INTEGER  PRIMARY KEY AUTOINCREMENT,
    id_nodes            INTEGER  NOT NULL,
    id_config_revisions INTEGER,
    id_users            INTEGER  NOT NULL,
    status              TEXT     NOT NULL DEFAULT 'pending',
    stage               TEXT,
    error_message       TEXT,
    started_at          DATETIME,
    finished_at         DATETIME,
    created             DATETIME DEFAULT CURRENT_TIMESTAMP,
    timestamp           DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (id_nodes) REFERENCES nodes(id_nodes),
    FOREIGN KEY (id_config_revisions) REFERENCES config_revisions(id_config_revisions),
    FOREIGN KEY (id_users) REFERENCES users(id_users)
);
INSERT OR IGNORE INTO deployments_v2 SELECT * FROM deployments;
DROP TABLE deployments;
ALTER TABLE deployments_v2 RENAME TO deployments;
`,
	},
	{
		version: 20,
		name:    "create_services",
		sql: `
CREATE TABLE IF NOT EXISTS services (
    id_services      INTEGER  PRIMARY KEY AUTOINCREMENT,
    name             TEXT     NOT NULL UNIQUE,
    service_type     TEXT     NOT NULL DEFAULT 'TCP',
    listen_port      INTEGER  NOT NULL,
    id_backend_pools INTEGER  NOT NULL,
    description      TEXT     DEFAULT '',
    enabled          INTEGER  NOT NULL DEFAULT 1,
    created          DATETIME DEFAULT CURRENT_TIMESTAMP,
    timestamp        DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (id_backend_pools) REFERENCES backend_pools(id_backend_pools)
);
CREATE INDEX IF NOT EXISTS idx_services_port ON services(listen_port);
CREATE INDEX IF NOT EXISTS idx_services_pool ON services(id_backend_pools);
`,
	},
	{
		version: 21,
		name:    "backend_pools_advanced_health_check",
		// Tambah dua kolom untuk konfigurasi health check lanjutan.
		// health_check_type: jenis check (none/TCP/HTTP/HTTPS/SSH/MYSQL/POSTGRESQL/REDIS/CUSTOM)
		// health_check_config: parameter JSON (path, expect, user, custom)
		// Migrasi data lama: pool yang sudah health_check=1 diset ke HTTP (behavior lama).
		sql: `
ALTER TABLE backend_pools ADD COLUMN health_check_type   TEXT NOT NULL DEFAULT 'none';
ALTER TABLE backend_pools ADD COLUMN health_check_config TEXT NOT NULL DEFAULT '{}';
UPDATE backend_pools SET health_check_type = 'HTTP' WHERE health_check = 1;
`,
	},
	{
		version: 22,
		name:    "create_auth_users",
		sql: `
CREATE TABLE IF NOT EXISTS auth_users (
    id_auth_users INTEGER  PRIMARY KEY AUTOINCREMENT,
    username      TEXT     NOT NULL UNIQUE,
    password_hash TEXT     NOT NULL,
    description   TEXT     NOT NULL DEFAULT '',
    enabled       INTEGER  NOT NULL DEFAULT 1,
    created       DATETIME DEFAULT CURRENT_TIMESTAMP,
    timestamp     DATETIME DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_auth_users_username ON auth_users(username);
`,
	},
	{
		version: 23,
		name:    "create_auth_groups",
		sql: `
CREATE TABLE IF NOT EXISTS auth_groups (
    id_auth_groups INTEGER  PRIMARY KEY AUTOINCREMENT,
    group_name     TEXT     NOT NULL UNIQUE,
    description    TEXT     NOT NULL DEFAULT '',
    enabled        INTEGER  NOT NULL DEFAULT 1,
    created        DATETIME DEFAULT CURRENT_TIMESTAMP,
    timestamp      DATETIME DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_auth_groups_name ON auth_groups(group_name);
`,
	},
	{
		version: 24,
		name:    "create_auth_group_users",
		sql: `
CREATE TABLE IF NOT EXISTS auth_group_users (
    id_auth_group_users INTEGER  PRIMARY KEY AUTOINCREMENT,
    id_auth_groups      INTEGER  NOT NULL,
    id_auth_users       INTEGER  NOT NULL,
    created             DATETIME DEFAULT CURRENT_TIMESTAMP,
    timestamp           DATETIME DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (id_auth_groups, id_auth_users),
    FOREIGN KEY (id_auth_groups) REFERENCES auth_groups(id_auth_groups) ON DELETE CASCADE,
    FOREIGN KEY (id_auth_users)  REFERENCES auth_users(id_auth_users)  ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_auth_group_users_group ON auth_group_users(id_auth_groups);
CREATE INDEX IF NOT EXISTS idx_auth_group_users_user  ON auth_group_users(id_auth_users);
`,
	},
	{
		version: 25,
		name:    "domains_add_auth_group",
		sql:     `ALTER TABLE domains ADD COLUMN id_auth_groups INTEGER REFERENCES auth_groups(id_auth_groups)`,
	},
	{
		version: 26,
		name:    "backend_pools_add_protocol_ssl_forward",
		// Tambah tiga kolom baru untuk dukungan backend HTTPS dan forward headers.
		// protocol: http (default) | https | tcp
		// ssl_mode: none (default) | trusted | self_signed  — hanya relevan saat protocol=https
		// forward_headers: 1 (default, aktif) — kirim X-Forwarded-Proto/Ssl/Port ke backend
		// Data lama otomatis mendapat protocol=http, ssl_mode=none, forward_headers=1 via DEFAULT.
		sql: `
ALTER TABLE backend_pools ADD COLUMN protocol TEXT NOT NULL DEFAULT 'http';
ALTER TABLE backend_pools ADD COLUMN ssl_mode TEXT NOT NULL DEFAULT 'none';
ALTER TABLE backend_pools ADD COLUMN forward_headers INTEGER NOT NULL DEFAULT 1;
`,
	},
	{
		version: 27,
		name:    "create_cmc_settings",
		sql: `
CREATE TABLE IF NOT EXISTS settings (
    key        TEXT     PRIMARY KEY,
    value      TEXT     NOT NULL DEFAULT '',
    encrypted  INTEGER  NOT NULL DEFAULT 0,
    created    DATETIME DEFAULT CURRENT_TIMESTAMP,
    timestamp  DATETIME DEFAULT CURRENT_TIMESTAMP
);
`,
	},
	{
		version: 28,
		name:    "create_certificate_storage",
		sql: `
CREATE TABLE IF NOT EXISTS certificate_storage (
    uuid          TEXT     PRIMARY KEY,
    name          TEXT     NOT NULL UNIQUE,
    provider      TEXT     NOT NULL DEFAULT 'manual',
    challenge     TEXT     NOT NULL DEFAULT 'none',
    status        TEXT     NOT NULL DEFAULT 'pending',
    primary_domain TEXT    NOT NULL,
    domains       TEXT     NOT NULL DEFAULT '[]',
    san           TEXT     NOT NULL DEFAULT '[]',
    zone          TEXT     NOT NULL DEFAULT '',
    dns_provider  TEXT     NOT NULL DEFAULT '',
    issued_at     DATETIME,
    expires_at    DATETIME,
    renew_before  INTEGER  NOT NULL DEFAULT 30,
    auto_renew    INTEGER  NOT NULL DEFAULT 0,
    fingerprint   TEXT     NOT NULL DEFAULT '',
    error_message TEXT     NOT NULL DEFAULT '',
    locked        INTEGER  NOT NULL DEFAULT 0,
    created       DATETIME DEFAULT CURRENT_TIMESTAMP,
    timestamp     DATETIME DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_cert_storage_status   ON certificate_storage(status);
CREATE INDEX IF NOT EXISTS idx_cert_storage_expires  ON certificate_storage(expires_at);
CREATE INDEX IF NOT EXISTS idx_cert_storage_name     ON certificate_storage(name);
`,
	},
	{
		version: 29,
		name:    "create_certificate_jobs",
		sql: `
CREATE TABLE IF NOT EXISTS certificate_jobs (
    uuid         TEXT     PRIMARY KEY,
    cert_uuid    TEXT     NOT NULL,
    job_type     TEXT     NOT NULL,
    status       TEXT     NOT NULL DEFAULT 'pending',
    logs         TEXT     NOT NULL DEFAULT '',
    error_message TEXT    NOT NULL DEFAULT '',
    started_at   DATETIME,
    finished_at  DATETIME,
    created      DATETIME DEFAULT CURRENT_TIMESTAMP,
    timestamp    DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (cert_uuid) REFERENCES certificate_storage(uuid) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_cert_jobs_cert   ON certificate_jobs(cert_uuid);
CREATE INDEX IF NOT EXISTS idx_cert_jobs_status ON certificate_jobs(status);
`,
	},
	{
		version: 30,
		name:    "create_certificate_deployments",
		sql: `
CREATE TABLE IF NOT EXISTS certificate_deployments (
    uuid        TEXT     PRIMARY KEY,
    cert_uuid   TEXT     NOT NULL,
    id_nodes    INTEGER  NOT NULL,
    status      TEXT     NOT NULL DEFAULT 'pending',
    error_message TEXT   NOT NULL DEFAULT '',
    deployed_at DATETIME,
    created     DATETIME DEFAULT CURRENT_TIMESTAMP,
    timestamp   DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (cert_uuid) REFERENCES certificate_storage(uuid) ON DELETE CASCADE,
    FOREIGN KEY (id_nodes)  REFERENCES nodes(id_nodes) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_cert_deploy_cert ON certificate_deployments(cert_uuid);
CREATE INDEX IF NOT EXISTS idx_cert_deploy_node ON certificate_deployments(id_nodes);
`,
	},
	{
		version: 31,
		name:    "domains_migrate_to_cert_uuid",
		// Migrasi domains: ganti id_ssl_certs (INTEGER) dengan cert_uuid (TEXT)
		// SQLite tidak mendukung DROP COLUMN (pre-3.35), gunakan recreate pattern.
		sql: `
CREATE TABLE IF NOT EXISTS domains_v2 (
    id_domains       INTEGER  PRIMARY KEY AUTOINCREMENT,
    domain_name      TEXT     NOT NULL UNIQUE,
    id_backend_pools INTEGER  NOT NULL,
    ssl_mode         TEXT     NOT NULL DEFAULT 'none',
    cert_uuid        TEXT,
    http_redirect    INTEGER  NOT NULL DEFAULT 1,
    enabled          INTEGER  NOT NULL DEFAULT 1,
    description      TEXT,
    id_auth_groups   INTEGER,
    created          DATETIME DEFAULT CURRENT_TIMESTAMP,
    timestamp        DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (id_backend_pools) REFERENCES backend_pools(id_backend_pools),
    FOREIGN KEY (cert_uuid)        REFERENCES certificate_storage(uuid),
    FOREIGN KEY (id_auth_groups)   REFERENCES auth_groups(id_auth_groups)
);
INSERT OR IGNORE INTO domains_v2 (id_domains, domain_name, id_backend_pools, ssl_mode,
    cert_uuid, http_redirect, enabled, description, id_auth_groups, created, timestamp)
SELECT id_domains, domain_name, id_backend_pools, ssl_mode,
    NULL, http_redirect, enabled, description, id_auth_groups, created, timestamp
FROM domains;
DROP TABLE domains;
ALTER TABLE domains_v2 RENAME TO domains;
CREATE INDEX IF NOT EXISTS idx_domains_pool      ON domains(id_backend_pools);
CREATE INDEX IF NOT EXISTS idx_domains_cert_uuid ON domains(cert_uuid);
`,
	},
	{
		version: 32,
		name:    "drop_ssl_certs",
		sql:     `DROP TABLE IF EXISTS ssl_certs;`,
	},
	{
		version: 33,
		name:    "nodes_add_https_frontend_enabled",
		// https_frontend_enabled = 0 (default): ikuti logika domain (generate https_in hanya jika ada domain ssl_mode=terminate)
		// https_frontend_enabled = 1: selalu generate frontend https_in pada node ini
		sql: `ALTER TABLE nodes ADD COLUMN https_frontend_enabled INTEGER NOT NULL DEFAULT 0`,
	},
	{
		version: 34,
		name:    "nodes_add_provision_tracking",
		// provision_step: step terakhir yang berhasil (0=idle, 1-6=sedang berjalan/gagal, 7=selesai)
		// provision_error: pesan error jika gagal, kosong jika sukses atau belum pernah provision
		sql: `ALTER TABLE nodes ADD COLUMN provision_step  INTEGER NOT NULL DEFAULT 0;
ALTER TABLE nodes ADD COLUMN provision_error TEXT    NOT NULL DEFAULT ''`,
	},
	{
		version: 35,
		name:    "create_error_pages",
		// Tabel menyimpan custom HTML untuk setiap HTTP error code.
		// enabled=0 default — error page tidak aktif sampai user mengisi konten dan mengaktifkan.
		// Pre-populate semua 8 error code yang didukung HAProxy errorfile.
		sql: `
CREATE TABLE IF NOT EXISTS error_pages (
    id_error_pages INTEGER  PRIMARY KEY AUTOINCREMENT,
    error_code     INTEGER  NOT NULL UNIQUE,
    content        TEXT     NOT NULL DEFAULT '',
    enabled        INTEGER  NOT NULL DEFAULT 0,
    created        DATETIME DEFAULT CURRENT_TIMESTAMP,
    timestamp      DATETIME DEFAULT CURRENT_TIMESTAMP
);
INSERT OR IGNORE INTO error_pages (error_code) VALUES (400),(403),(404),(408),(500),(502),(503),(504);
`,
	},
	{
		version: 36,
		name:    "nodes_add_stats",
		// Konfigurasi HAProxy statistics page per node.
		// stats_allowed_groups: JSON array berisi ID dari auth_groups.
		// stats_hide_version: default 1 (aman — tidak menampilkan versi HAProxy).
		sql: `ALTER TABLE nodes ADD COLUMN stats_enabled       INTEGER NOT NULL DEFAULT 0;
ALTER TABLE nodes ADD COLUMN stats_bind_addr     TEXT    NOT NULL DEFAULT '127.0.0.1';
ALTER TABLE nodes ADD COLUMN stats_port          INTEGER NOT NULL DEFAULT 8404;
ALTER TABLE nodes ADD COLUMN stats_uri           TEXT    NOT NULL DEFAULT '/stats';
ALTER TABLE nodes ADD COLUMN stats_refresh       TEXT    NOT NULL DEFAULT '10s';
ALTER TABLE nodes ADD COLUMN stats_hide_version  INTEGER NOT NULL DEFAULT 1;
ALTER TABLE nodes ADD COLUMN stats_readonly      INTEGER NOT NULL DEFAULT 0;
ALTER TABLE nodes ADD COLUMN stats_admin         INTEGER NOT NULL DEFAULT 0;
ALTER TABLE nodes ADD COLUMN stats_allowed_groups TEXT   NOT NULL DEFAULT '[]'`,
	},
}

// RunMigrations menjalankan semua migrasi yang belum diaplikasikan.
// Idempotent — aman dijalankan berulang kali.
func RunMigrations(db *sql.DB) error {
	// Buat tabel schema_migrations jika belum ada
	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS schema_migrations (
			version    INTEGER  PRIMARY KEY,
			name       TEXT     NOT NULL,
			applied_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)`)
	if err != nil {
		return fmt.Errorf("[MIGRATION] gagal membuat tabel schema_migrations: %v", err)
	}

	// Ambil versi migrasi yang sudah diaplikasikan
	applied := make(map[int]bool)
	rows, err := db.Query("SELECT version FROM schema_migrations ORDER BY version")
	if err != nil {
		return fmt.Errorf("[MIGRATION] gagal query applied migrations: %v", err)
	}
	defer rows.Close()
	for rows.Next() {
		var v int
		if err := rows.Scan(&v); err != nil {
			return err
		}
		applied[v] = true
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("[MIGRATION] error iterasi rows: %v", err)
	}

	// Jalankan migrasi yang belum diaplikasikan
	for _, m := range migrations {
		if applied[m.version] {
			continue
		}

		log.Printf("[MIGRATION] Menerapkan v%d: %s", m.version, m.name)

		// Jalankan dalam transaksi agar atomic
		tx, err := db.Begin()
		if err != nil {
			return fmt.Errorf("[MIGRATION] gagal begin tx untuk v%d: %v", m.version, err)
		}

		if _, err := tx.Exec(m.sql); err != nil {
			tx.Rollback()
			return fmt.Errorf("[MIGRATION] gagal eksekusi v%d '%s': %v", m.version, m.name, err)
		}

		if _, err := tx.Exec(
			"INSERT INTO schema_migrations (version, name) VALUES (?, ?)",
			m.version, m.name,
		); err != nil {
			tx.Rollback()
			return fmt.Errorf("[MIGRATION] gagal record v%d: %v", m.version, err)
		}

		if err := tx.Commit(); err != nil {
			return fmt.Errorf("[MIGRATION] gagal commit v%d: %v", m.version, err)
		}

		log.Printf("[MIGRATION] v%d berhasil diterapkan", m.version)
	}

	log.Println("[MIGRATION] Semua migrasi up-to-date")
	return nil
}
