package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/aefw/hapm/internal/config"
	"github.com/aefw/hapm/internal/domain"
	"github.com/aefw/hapm/internal/security"
)

type settingsService struct {
	cfg      *config.Config
	repo     domain.SettingRepository
	auditSvc domain.AuditService
}

func NewSettingsService(
	cfg *config.Config,
	repo domain.SettingRepository,
	auditSvc domain.AuditService,
) domain.SettingsService {
	return &settingsService{cfg: cfg, repo: repo, auditSvc: auditSvc}
}

func (s *settingsService) GetCloudflareToken(ctx context.Context) (string, error) {
	setting, err := s.repo.Get(ctx, domain.SettingCFAPIToken)
	if err != nil {
		return "", nil // token belum diset
	}
	if !setting.Encrypted {
		return setting.Value, nil
	}
	plain, err := security.Decrypt(setting.Value, s.cfg.Security.EncryptionKey)
	if err != nil {
		return "", fmt.Errorf("decrypt token gagal")
	}
	return plain, nil
}

func (s *settingsService) SetCloudflareToken(ctx context.Context, token string) error {
	encrypted, err := security.Encrypt(token, s.cfg.Security.EncryptionKey)
	if err != nil {
		return fmt.Errorf("enkripsi token gagal: %w", err)
	}
	if err := s.repo.Set(ctx, domain.SettingCFAPIToken, encrypted, true); err != nil {
		return fmt.Errorf("simpan token gagal: %w", err)
	}
	_ = s.auditSvc.Log(ctx, &domain.AuditLog{
		Action: domain.AuditActionSettingUpdated,
		Detail: "Cloudflare API Token diperbarui",
	})
	return nil
}

func (s *settingsService) TestCloudflareConnection(ctx context.Context) (*domain.CloudflareTestResult, error) {
	token, err := s.GetCloudflareToken(ctx)
	if err != nil || token == "" {
		return &domain.CloudflareTestResult{Success: false, Message: "Cloudflare API Token belum dikonfigurasi"}, nil
	}
	return callCFVerifyToken(token)
}

func (s *settingsService) DiscoverCloudflareZones(ctx context.Context, inputToken string) ([]*domain.CloudflareZone, error) {
	token := strings.TrimSpace(inputToken)
	if token == "" {
		var err error
		token, err = s.GetCloudflareToken(ctx)
		if err != nil || token == "" {
			return nil, errors.New("Cloudflare API Token belum dikonfigurasi. Masukkan token atau simpan terlebih dahulu")
		}
	}
	return callCFListZones(token)
}

func (s *settingsService) GetACMEEmail(ctx context.Context) (string, error) {
	setting, err := s.repo.Get(ctx, domain.SettingACMEEmail)
	if err != nil {
		return "acme@hapm.local", nil
	}
	return setting.Value, nil
}

func (s *settingsService) SetACMEEmail(ctx context.Context, email string) error {
	return s.repo.Set(ctx, domain.SettingACMEEmail, email, false)
}

func (s *settingsService) IsACMEStaging(ctx context.Context) (bool, error) {
	setting, err := s.repo.Get(ctx, domain.SettingACMEStaging)
	if err != nil {
		return false, nil
	}
	return setting.Value == "true", nil
}

func (s *settingsService) SetACMEStaging(ctx context.Context, staging bool) error {
	return s.repo.Set(ctx, domain.SettingACMEStaging, strconv.FormatBool(staging), false)
}

// ─── Cloudflare API helpers ───────────────────────────────────────────────────

type cfTokenResult struct {
	Result struct {
		ID     string `json:"id"`
		Status string `json:"status"`
	} `json:"result"`
	Success bool `json:"success"`
	Errors  []struct {
		Message string `json:"message"`
	} `json:"errors"`
}

type cfZonesResult struct {
	Result []struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	} `json:"result"`
	Success    bool `json:"success"`
	ResultInfo struct {
		Count int `json:"count"`
		Page  int `json:"page"`
		Total int `json:"total_count"`
	} `json:"result_info"`
}

func callCFVerifyToken(token string) (*domain.CloudflareTestResult, error) {
	req, _ := http.NewRequest(http.MethodGet, "https://api.cloudflare.com/client/v4/user/tokens/verify", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return &domain.CloudflareTestResult{Success: false, Message: fmt.Sprintf("koneksi ke Cloudflare gagal: %v", err)}, nil
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	var result cfTokenResult
	if err := json.Unmarshal(body, &result); err != nil {
		return &domain.CloudflareTestResult{Success: false, Message: "response Cloudflare tidak valid"}, nil
	}

	if !result.Success {
		msg := "Token tidak valid"
		if len(result.Errors) > 0 {
			msg = result.Errors[0].Message
		}
		return &domain.CloudflareTestResult{Success: false, Message: msg}, nil
	}
	if result.Result.Status != "active" {
		return &domain.CloudflareTestResult{
			Success: false,
			Message: fmt.Sprintf("Token status: %s (bukan active)", result.Result.Status),
		}, nil
	}

	return &domain.CloudflareTestResult{Success: true, Message: "Koneksi Cloudflare berhasil"}, nil
}

func callCFListZones(token string) ([]*domain.CloudflareZone, error) {
	var allZones []*domain.CloudflareZone
	page := 1

	client := &http.Client{Timeout: 10 * time.Second}

	for {
		url := fmt.Sprintf("https://api.cloudflare.com/client/v4/zones?per_page=50&page=%d", page)
		req, _ := http.NewRequest(http.MethodGet, url, nil)
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/json")

		resp, err := client.Do(req)
		if err != nil {
			return nil, fmt.Errorf("Cloudflare API gagal: %w", err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		var result cfZonesResult
		if err := json.Unmarshal(body, &result); err != nil || !result.Success {
			return nil, errors.New("gagal mengambil daftar zone Cloudflare")
		}

		for _, z := range result.Result {
			if strings.TrimSpace(z.ID) != "" {
				allZones = append(allZones, &domain.CloudflareZone{ID: z.ID, Name: z.Name})
			}
		}

		if len(allZones) >= result.ResultInfo.Total || len(result.Result) == 0 {
			break
		}
		page++
	}

	return allZones, nil
}
