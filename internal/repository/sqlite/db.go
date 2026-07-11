package sqlite

import (
	"database/sql"
	"fmt"
	"log"
	"path/filepath"
	"os"

	"github.com/aefw/hapm/internal/config"
	_ "modernc.org/sqlite"
)

// DB membungkus *sql.DB dengan konfigurasi SQLite khusus HAPM
type DB struct {
	db *sql.DB
}

// NewDB membuat koneksi SQLite baru dengan WAL mode dan optimasi produksi.
//
// WAL mode dipilih karena:
//   - Memungkinkan concurrent readers tanpa blocking writer
//   - Performa write lebih baik untuk workload HAPM
//   - Crash-safe dengan journal mode WAL
func NewDB(cfg *config.Config) (*DB, error) {
	// Pastikan direktori database ada
	dir := filepath.Dir(cfg.DB.Path)
	if err := os.MkdirAll(dir, 0750); err != nil {
		return nil, fmt.Errorf("[SQLite] gagal membuat direktori %s: %v", dir, err)
	}

	// Buka koneksi SQLite
	// modernc.org/sqlite: pure Go, CGO_ENABLED=0 compatible
	db, err := sql.Open("sqlite", cfg.DB.Path)
	if err != nil {
		return nil, fmt.Errorf("[SQLite] gagal membuka database %s: %v", cfg.DB.Path, err)
	}

	// SQLite WAL mode mendukung concurrent readers.
	// Set MaxOpenConns > 1 agar query bersarang (nested queries) tidak deadlock.
	// Write serialization ditangani oleh SQLite di level DB, bukan connection pool.
	db.SetMaxOpenConns(10)
	db.SetMaxIdleConns(5)

	// Terapkan PRAGMA optimasi
	pragmas := []string{
		"PRAGMA journal_mode=WAL",          // Write-Ahead Logging
		"PRAGMA synchronous=NORMAL",        // Balance: durability vs performance
		"PRAGMA foreign_keys=ON",           // Enforce referential integrity
		"PRAGMA busy_timeout=5000",         // 5 detik timeout jika DB sedang locked
		"PRAGMA cache_size=-64000",         // 64MB page cache
		"PRAGMA temp_store=MEMORY",         // Temp tables di memory
		"PRAGMA mmap_size=268435456",       // 256MB memory-mapped I/O
	}

	for _, pragma := range pragmas {
		if _, err := db.Exec(pragma); err != nil {
			return nil, fmt.Errorf("[SQLite] gagal menerapkan '%s': %v", pragma, err)
		}
	}

	// Verifikasi koneksi
	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("[SQLite] gagal ping database: %v", err)
	}

	log.Printf("[SQLite] Koneksi berhasil: %s (WAL mode)", cfg.DB.Path)

	return &DB{db: db}, nil
}

// SQL mengembalikan *sql.DB underlying untuk digunakan repository
func (d *DB) SQL() *sql.DB {
	return d.db
}

// Close menutup koneksi database
func (d *DB) Close() error {
	log.Println("[SQLite] Menutup koneksi database...")
	return d.db.Close()
}
