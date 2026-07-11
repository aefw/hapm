package handler

import (
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/aefw/hapm/internal/core"
	"github.com/aefw/hapm/internal/domain"
)

// handleServiceError memetakan error dari service layer ke HTTP response yang sesuai.
// Ini adalah single point of error-to-HTTP mapping untuk semua handler.
// PENTING: urutan case menentukan prioritas — 400 validasi dicek SEBELUM 401 auth
// agar pesan seperti "cert_pem tidak valid" tidak salah diklasifikasi sebagai 401.
func handleServiceError(w http.ResponseWriter, err error) {
	if err == nil {
		return
	}

	// Gunakan full error string untuk kategorisasi, innermost untuk display ke client.
	full := err.Error()
	lower := strings.ToLower(full)
	display := innerMsg(err)

	switch {
	// 404 Not Found
	case containsAny(lower, "tidak ditemukan", "not found", "no rows"):
		core.NotFound(w, display)

	// 409 Conflict
	case containsAny(lower, "sudah ada", "duplicate", "exists", "already"):
		core.Conflict(w, display)

	// 403 Forbidden
	case containsAny(lower, "tidak diizinkan", "forbidden", "tidak boleh",
		"cannot delete", "only superadmin", "only let"):
		core.Forbidden(w, display)

	// 429 Too Many Requests
	case containsAny(lower, "terlalu banyak", "rate limit", "too many"):
		core.TooManyRequests(w, display)

	// 423 Locked — account locked
	case containsAny(lower, "terkunci", "account is locked"):
		core.Error(w, http.StatusLocked, display)

	// 422 Unprocessable — operasi SSH/provisioning gagal (request valid, eksekusi gagal di node)
	case containsAny(lower, "provision gagal", "provisioner:"):
		core.Error(w, http.StatusUnprocessableEntity, display)

	// 400 Bad Request — konfigurasi salah atau validasi input
	case containsAny(lower, "ssh private key tidak bisa didekripsi",
		"is required", "must be", "wajib diisi", "tidak valid",
		"invalid role", "tidak didukung", "at least", "invalid port", "invalid algorithm",
		"invalid ssl", "invalid password", "invalid cert", "pem tidak valid",
		"failed to decode pem", "failed to parse cert",
		"health_check_config", "health check mysql", "health check postgresql",
		"health check custom", "health_check_type"):
		core.BadRequest(w, display)

	// 401 Unauthorized — invalid creds, bad/expired token
	case containsAny(lower, "invalid username", "invalid credentials", "credential",
		"token", "expired", "signature"):
		core.Unauthorized(w, display)

	// 500 — real server errors (DB errors, encryption failures, etc.)
	default:
		core.InternalError(w, display)
	}
}

// innerMsg mengambil pesan error terdalam dari chain wrapped error.
// Ini memastikan client melihat pesan bisnis ("node tidak ditemukan")
// bukan prefix internal ("node: find by id: node tidak ditemukan").
func innerMsg(err error) string {
	for {
		inner := errors.Unwrap(err)
		if inner == nil {
			return err.Error()
		}
		err = inner
	}
}

// containsAny memeriksa apakah s mengandung salah satu dari substr.
func containsAny(s string, substrs ...string) bool {
	for _, sub := range substrs {
		if sub != "" && strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

// ListResult adalah wrapper pagination yang konsisten untuk semua endpoint list.
type ListResult[T any] struct {
	Total int `json:"total"`
	Start int `json:"start"`
	Limit int `json:"limit"`
	Items []T `json:"items"`
}

// parseListFilter membaca q, start, limit dari query string.
// Jika start tidak diisi, default 0. Jika limit tidak diisi, default 10. Limit maksimal 500.
func parseListFilter(r *http.Request) domain.ListFilter {
	q := r.URL.Query()
	f := domain.ListFilter{
		Q:     q.Get("q"),
		Limit: 10,
		Start: 0,
	}
	if s := q.Get("start"); s != "" {
		if v, err := strconv.Atoi(s); err == nil && v >= 0 {
			f.Start = v
		}
	}
	if l := q.Get("limit"); l != "" {
		if v, err := strconv.Atoi(l); err == nil && v > 0 {
			f.Limit = v
			if f.Limit > 500 {
				f.Limit = 500
			}
		}
	}
	return f
}

// respondList membungkus hasil list dengan metadata pagination dan mengirim JSON response.
func respondList[T any](w http.ResponseWriter, msg string, items []T, total int, f domain.ListFilter) {
	if items == nil {
		items = []T{}
	}
	core.Success(w, msg, &ListResult[T]{
		Total: total,
		Start: f.Start,
		Limit: f.Limit,
		Items: items,
	})
}

// parseID mengambil ID integer dari path parameter.
// Mengembalikan 0 dan false jika params kosong atau bukan angka.
func parseID(params []string, idx int) (int, bool) {
	if idx >= len(params) || params[idx] == "" {
		return 0, false
	}
	id := 0
	for _, ch := range params[idx] {
		if ch < '0' || ch > '9' {
			return 0, false
		}
		id = id*10 + int(ch-'0')
	}
	if id == 0 {
		return 0, false
	}
	return id, true
}

