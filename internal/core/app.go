package core

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/aefw/hapm/internal/config"
)

// App adalah aplikasi utama HAPM.
// Memegang konfigurasi, router, dan HTTP server.
type App struct {
	Config *config.Config
	Router *Router
	Server *http.Server
}

// NewApp membuat instance App baru dengan dependency injection.
func NewApp(cfg *config.Config, router *Router) *App {
	return &App{
		Config: cfg,
		Router: router,
	}
}

// Run memulai HTTP server dan menunggu sinyal shutdown.
// Mendukung graceful shutdown dengan timeout 30 detik.
func (a *App) Run(handler http.Handler) error {
	addr := fmt.Sprintf(":%d", a.Config.App.Port)

	a.Server = &http.Server{
		Addr:         addr,
		Handler:      handler,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
		// Security: sembunyikan Go version dari header Server
		// Tidak ada cara native di net/http, tapi kita akan override di middleware
	}

	// Graceful shutdown goroutine
	errCh := make(chan error, 1)
	go func() {
		// Tangkap SIGINT (Ctrl+C) dan SIGTERM (Docker stop / systemd stop)
		quit := make(chan os.Signal, 1)
		signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
		sig := <-quit

		log.Printf("[APP] Menerima sinyal: %v. Memulai graceful shutdown...", sig)

		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		if err := a.Server.Shutdown(ctx); err != nil {
			errCh <- fmt.Errorf("[APP] Error saat shutdown: %v", err)
			return
		}
		errCh <- nil
	}()

	a.printBanner()

	if err := a.Server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return fmt.Errorf("[APP] Server error: %v", err)
	}

	// Tunggu hasil graceful shutdown
	if err := <-errCh; err != nil {
		return err
	}

	log.Println("[APP] Server dihentikan dengan baik.")
	return nil
}

// printBanner mencetak info startup ke log
func (a *App) printBanner() {
	log.Println("========================================================")
	log.Printf("  %s", a.Config.App.Name)
	log.Printf("  Mode    : %s", a.Config.App.Mode)
	log.Printf("  Port    : %d", a.Config.App.Port)
	log.Printf("  Base URL: %s", a.Config.App.BaseURL)
	log.Printf("  DB      : %s", a.Config.DB.Driver)
	log.Println("========================================================")
	log.Printf("[APP] Server berjalan di http://localhost:%d", a.Config.App.Port)
}
