package handler

import (
	"fmt"
	"net/http"
	"time"

	"github.com/aefw/hapm/internal/config"
	"github.com/aefw/hapm/internal/core"
	"github.com/aefw/hapm/internal/domain"
	"github.com/aefw/hapm/internal/middleware"
)

// AlertItem adalah satu entri notifikasi terkait SSL certificate.
type AlertItem struct {
	Type     string `json:"type"`               // "cert_error" | "cert_dist_failed"
	Title    string `json:"title"`
	Message  string `json:"message"`
	CertUUID string `json:"cert_uuid,omitempty"`
	CertName string `json:"cert_name,omitempty"`
	NodeName string `json:"node_name,omitempty"`
	Since    string `json:"since"`
}

type AlertHandler struct {
	certRepo   domain.CertificateRepository
	deployRepo domain.CertDeploymentRepository
	cfg        *config.Config
}

func RegisterAlertRoutes(
	router *core.Router,
	cfg *config.Config,
	certRepo domain.CertificateRepository,
	deployRepo domain.CertDeploymentRepository,
) {
	h := &AlertHandler{certRepo: certRepo, deployRepo: deployRepo, cfg: cfg}
	router.GET("/api/v1/alerts", middleware.RequireAuth(cfg, h.GetAlerts))
}

// GetAlerts godoc
// GET /api/v1/alerts   [Auth Required]
// Mengembalikan daftar alert aktif:
//   - Certificate dengan status error (renewal/issue gagal)
//   - Distribusi certificate yang gagal dalam 7 hari terakhir
func (h *AlertHandler) GetAlerts(w http.ResponseWriter, r *http.Request, params []string) {
	ctx := r.Context()
	var alerts []AlertItem

	// 1. Certificate dengan status error
	errorCerts, _ := h.certRepo.ListByStatus(ctx, domain.CertStatusError)
	for _, c := range errorCerts {
		msg := fmt.Sprintf("Certificate '%s' mengalami error", c.Name)
		if c.ErrorMessage != "" {
			msg += ": " + c.ErrorMessage
		}
		alerts = append(alerts, AlertItem{
			Type:     "cert_error",
			Title:    "SSL Gagal Diperbarui",
			Message:  msg,
			CertUUID: c.UUID,
			CertName: c.Name,
			Since:    c.Timestamp.UTC().Format(time.RFC3339),
		})
	}

	// 2. Distribusi certificate yang gagal dalam 7 hari terakhir
	failedDeploys, _ := h.deployRepo.ListRecentFailed(ctx, 7)
	for _, d := range failedDeploys {
		nodeLabel := d.NodeName
		if nodeLabel == "" {
			nodeLabel = fmt.Sprintf("node #%d", d.NodeID)
		}
		msg := fmt.Sprintf("Distribusi SSL ke node '%s' gagal", nodeLabel)
		if d.ErrorMsg != "" {
			msg += ": " + d.ErrorMsg
		}
		alerts = append(alerts, AlertItem{
			Type:     "cert_dist_failed",
			Title:    "Distribusi SSL Gagal",
			Message:  msg,
			CertUUID: d.CertUUID,
			NodeName: nodeLabel,
			Since:    d.Created.UTC().Format(time.RFC3339),
		})
	}

	if alerts == nil {
		alerts = []AlertItem{}
	}
	core.Success(w, "alerts", map[string]interface{}{
		"count": len(alerts),
		"items": alerts,
	})
}
