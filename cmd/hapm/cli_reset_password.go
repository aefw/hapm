package main

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/aefw/hapm/internal/security"
	_ "modernc.org/sqlite"
)

// runResetPassword menangani subcommand: hapm reset-password [username] [password]
//
// Penggunaan:
//
//	hapm reset-password                   → reset admin ke password "admin"
//	hapm reset-password admin             → reset user "admin" ke password "admin"
//	hapm reset-password admin newpassword → reset user "admin" ke "newpassword"
//
// Cocok untuk recovery via docker exec atau terminal langsung.
func runResetPassword(args []string) {
	username := "admin"
	password := "admin"

	if len(args) >= 1 && args[0] != "" {
		username = args[0]
	}
	if len(args) >= 2 && args[1] != "" {
		password = args[1]
	}

	dbPath := resolveDBPath()
	log.Printf("[RESET] Menggunakan database: %s", dbPath)

	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		log.Fatalf("[RESET] Gagal membuka database: %v", err)
	}
	defer db.Close()

	if err := db.Ping(); err != nil {
		log.Fatalf("[RESET] Database tidak dapat diakses: %v", err)
	}

	ctx := context.Background()

	// Cari user
	var userID int
	var username2 string
	err = db.QueryRowContext(ctx, "SELECT id_users, username FROM users WHERE username=?", username).Scan(&userID, &username2)
	if err == sql.ErrNoRows {
		log.Fatalf("[RESET] User %q tidak ditemukan", username)
	}
	if err != nil {
		log.Fatalf("[RESET] Gagal query user: %v", err)
	}

	// Hash password baru
	hashed, err := security.HashPassword(password)
	if err != nil {
		log.Fatalf("[RESET] Gagal hash password: %v", err)
	}

	// Update password + unlock akun
	_, err = db.ExecContext(ctx,
		`UPDATE users SET password=?, locked=0, lock_until=NULL, timestamp=CURRENT_TIMESTAMP WHERE id_users=?`,
		hashed, userID,
	)
	if err != nil {
		log.Fatalf("[RESET] Gagal update password: %v", err)
	}

	// Hapus semua refresh token aktif agar session lama tidak bisa dipakai
	_, _ = db.ExecContext(ctx, "UPDATE refresh_tokens SET revoked=1 WHERE user_id=?", userID)

	fmt.Println("========================================================")
	fmt.Printf(" Password berhasil di-reset\n")
	fmt.Printf(" Username : %s\n", username2)
	fmt.Printf(" Password : %s\n", password)
	fmt.Println(" Akun di-unlock, semua session lama dicabut.")
	fmt.Println(" Ganti password segera setelah login!")
	fmt.Println("========================================================")

	os.Exit(0)
}

// resolveDBPath menentukan path database untuk CLI recovery.
// Prioritas: APP_DB_PATH env → /data/hapm.db → ./data/hapm.db → ./hapm.db
func resolveDBPath() string {
	if v := os.Getenv("APP_DB_PATH"); v != "" {
		return v
	}
	if _, err := os.Stat("/data"); err == nil {
		return "/data/hapm.db"
	}
	if _, err := os.Stat("./data"); err == nil {
		return "./data/hapm.db"
	}
	cwd, _ := os.Getwd()
	return filepath.Join(cwd, "hapm.db")
}
