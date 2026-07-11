package sqlite

import (
	"database/sql"
	"fmt"
	"log"
	"os"

	"github.com/aefw/hapm/internal/security"
)

const defaultAdminPassword = "admin"

// Seed membuat SuperAdmin jika belum ada user di database.
// Password default bisa di-override via APP_ADMIN_DEFAULT_PASSWORD.
// Password TIDAK di-print ke log — gunakan kredensial default atau yang di-set di env.
func Seed(db *sql.DB) error {
	var count int
	if err := db.QueryRow("SELECT COUNT(*) FROM users").Scan(&count); err != nil {
		return fmt.Errorf("seed: gagal count users: %v", err)
	}

	if count > 0 {
		return nil
	}

	// Ambil password dari env, fallback ke default
	password := os.Getenv("APP_ADMIN_DEFAULT_PASSWORD")
	usingDefault := false
	if password == "" {
		password = defaultAdminPassword
		usingDefault = true
	}

	hashed, err := security.HashPassword(password)
	if err != nil {
		return fmt.Errorf("seed: gagal hash password: %v", err)
	}

	_, err = db.Exec(
		`INSERT INTO users (username, email, password, full_name, role, active)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		"admin", "admin@hapm.local", hashed, "HAProxy Manager Admin", "superadmin", 1,
	)
	if err != nil {
		return fmt.Errorf("seed: gagal insert superadmin: %v", err)
	}

	log.Println("========================================================")
	log.Println("[SEED] SuperAdmin dibuat: username=admin")
	if usingDefault {
		log.Println("[SEED] Password: gunakan password default (lihat dokumentasi)")
		log.Println("[SEED] WAJIB set APP_ADMIN_DEFAULT_PASSWORD di production!")
	} else {
		log.Println("[SEED] Password: dari APP_ADMIN_DEFAULT_PASSWORD")
	}
	log.Println("[SEED] Ganti password segera setelah login pertama!")
	log.Println("========================================================")

	return nil
}
