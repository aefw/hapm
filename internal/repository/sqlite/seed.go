package sqlite

import (
	"database/sql"
	"fmt"
	"log"

	"github.com/aefw/hapm/internal/security"
)

// Seed membuat SuperAdmin jika belum ada user di database.
// Kredensial awal: username=admin, password=admin.
// Pengguna wajib mengganti password setelah login pertama.
func Seed(db *sql.DB) error {
	var count int
	if err := db.QueryRow("SELECT COUNT(*) FROM users").Scan(&count); err != nil {
		return fmt.Errorf("seed: gagal count users: %v", err)
	}

	if count > 0 {
		return nil
	}

	hashed, err := security.HashPassword("admin")
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
	log.Println("[SEED] SuperAdmin dibuat: username=admin / password=admin")
	log.Println("[SEED] Ganti password segera setelah login pertama!")
	log.Println("========================================================")

	return nil
}
