package service

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/aefw/hapm/internal/domain"
)

const (
	snServerBase = "https://office.indonetsoft.com/system_manager/manage/app_license_download/"
	snFileName   = "license.sn"
	snModule     = "hapm"
)

type snService struct {
	dataDir     string
	settingRepo domain.SettingRepository
}

// NewSNService membuat instance SNService baru.
func NewSNService(settingRepo domain.SettingRepository) domain.SNService {
	return &snService{
		dataDir:     detectDataDir(),
		settingRepo: settingRepo,
	}
}

func detectDataDir() string {
	if _, err := os.Stat("/data"); err == nil {
		return "/data"
	}
	return "./data"
}

func (s *snService) filePath() string {
	return filepath.Join(s.dataDir, snFileName)
}

// Activate mengunduh license dari server menggunakan kode aktivasi,
// lalu memverifikasi dan mengaktifkan fitur premium jika valid.
// Kode salah atau tidak ditemukan di server langsung menghasilkan error — tidak ada fallback.
func (s *snService) Activate(ctx context.Context, code string) (*domain.SNResult, error) {
	if code == "" {
		return nil, fmt.Errorf("kode aktivasi tidak boleh kosong")
	}
	content, err := s.downloadFromServer(code)
	if err != nil {
		return nil, fmt.Errorf("kode tidak valid atau tidak ditemukan: %w", err)
	}
	if err := s.saveFile(content); err != nil {
		return nil, fmt.Errorf("gagal menyimpan file lisensi: %w", err)
	}
	return s.activateFromFile(ctx, s.filePath())
}

// Status membaca file lokal tanpa mengunduh dari server.
func (s *snService) Status(ctx context.Context) (*domain.SNResult, error) {
	if _, err := s.readFile(); err != nil {
		return &domain.SNResult{HasFile: false}, nil
	}
	result, err := s.callBinary(ctx, s.filePath())
	if err != nil {
		return &domain.SNResult{HasFile: true, IsValid: false}, nil
	}
	return result, nil
}

func (s *snService) activateFromFile(ctx context.Context, filePath string) (*domain.SNResult, error) {
	result, err := s.callBinary(ctx, filePath)
	if err != nil {
		return result, err
	}

	if !result.IsValid {
		return result, fmt.Errorf("tidak valid: integrity check gagal")
	}
	if result.IsExpired {
		return result, fmt.Errorf("sudah expired")
	}
	if !result.HasModule {
		return result, fmt.Errorf("modul yang diperlukan tidak tersedia")
	}

	if err := s.settingRepo.Set(ctx, domain.SettingCustomErrorPages, "true", false); err != nil {
		return result, fmt.Errorf("gagal mengaktifkan fitur premium: %w", err)
	}
	result.PremiumEnabled = true
	return result, nil
}

// callBinary menjalankan aefw-serial dan memparsing JSON output-nya.
// Selalu membaca stdout agar JSON tetap terbaca meski exit code != 0.
func (s *snService) callBinary(ctx context.Context, filePath string) (*domain.SNResult, error) {
	binPath := s.binPath()

	tCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	cmd := exec.CommandContext(tCtx, binPath, filePath)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	_ = cmd.Run() // exit code diabaikan; status ada dalam JSON

	out := stdout.Bytes()
	if len(out) == 0 {
		return nil, fmt.Errorf("verifikasi gagal: binary tidak ditemukan atau tidak bisa dijalankan (%s)", binPath)
	}

	var raw struct {
		HasFile   bool           `json:"has_file"`
		IsValid   bool           `json:"is_valid"`
		IsExpired bool           `json:"is_expired"`
		HasHAPM   bool           `json:"has_hapm"`
		Info      map[string]any `json:"info,omitempty"`
		Error     string         `json:"error,omitempty"`
	}
	if err := json.Unmarshal(out, &raw); err != nil {
		return nil, fmt.Errorf("output tidak valid: %w", err)
	}

	if raw.Error != "" {
		return &domain.SNResult{HasFile: raw.HasFile, IsValid: raw.IsValid}, fmt.Errorf("%s", raw.Error)
	}

	return &domain.SNResult{
		HasFile:   raw.HasFile,
		IsValid:   raw.IsValid,
		IsExpired: raw.IsExpired,
		HasModule: raw.HasHAPM,
		Info:      raw.Info,
	}, nil
}

// binPath mengembalikan path binary aefw-serial.
// Bisa di-override via env var AEFW_SN_BIN.
func (s *snService) binPath() string {
	if v := os.Getenv("AEFW_SN_BIN"); v != "" {
		return v
	}
	return "./bin/aefw-serial"
}

func (s *snService) downloadFromServer(code string) (string, error) {
	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Get(snServerBase + code)
	if err != nil {
		return "", fmt.Errorf("koneksi gagal: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("server mengembalikan status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("baca response gagal: %w", err)
	}
	if len(body) < 10 {
		return "", fmt.Errorf("response tidak valid")
	}
	return string(body), nil
}

func (s *snService) readFile() (string, error) {
	data, err := os.ReadFile(s.filePath())
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func (s *snService) saveFile(content string) error {
	if err := os.MkdirAll(s.dataDir, 0755); err != nil {
		return err
	}
	return os.WriteFile(s.filePath(), []byte(content), 0644)
}
