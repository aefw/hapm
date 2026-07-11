package service

import (
	"context"
	"fmt"
	"strings"

	"github.com/aefw/hapm/internal/domain"
)

// revisionService implements domain.RevisionService
type revisionService struct {
	repo     domain.RevisionRepository
	auditSvc domain.AuditService
}

// NewRevisionService membuat instance RevisionService baru
func NewRevisionService(repo domain.RevisionRepository, auditSvc domain.AuditService) domain.RevisionService {
	return &revisionService{repo: repo, auditSvc: auditSvc}
}

// ListByNode mengembalikan daftar revisi konfigurasi untuk node tertentu
func (s *revisionService) ListByNode(ctx context.Context, nodeID int) ([]*domain.ConfigRevisionSummary, error) {
	revs, err := s.repo.ListByNode(ctx, nodeID)
	if err != nil {
		return nil, fmt.Errorf("revision: list by node: %w", err)
	}
	return revs, nil
}

// GetRevision mengambil revisi konfigurasi berdasarkan node ID dan nomor revisi
func (s *revisionService) GetRevision(ctx context.Context, nodeID, revNumber int) (*domain.ConfigRevision, error) {
	rev, err := s.repo.FindByNodeAndNumber(ctx, nodeID, revNumber)
	if err != nil {
		return nil, fmt.Errorf("revision: find by node and number: %w", err)
	}
	return rev, nil
}

// Diff menghasilkan unified diff antara revisi sebelumnya dan revisi yang diminta
func (s *revisionService) Diff(ctx context.Context, nodeID, revNumber int) (*domain.ConfigDiff, error) {
	// Ambil revisi yang diminta
	current, err := s.repo.FindByNodeAndNumber(ctx, nodeID, revNumber)
	if err != nil {
		return nil, fmt.Errorf("revision: find current: %w", err)
	}

	// Ambil revisi sebelumnya
	var prevContent string
	var fromRev int
	if revNumber > 1 {
		prev, err := s.repo.FindByNodeAndNumber(ctx, nodeID, revNumber-1)
		if err == nil {
			prevContent = prev.ConfigContent
			fromRev = prev.RevisionNumber
		}
	}

	diff := generateUnifiedDiff(prevContent, current.ConfigContent, fromRev, revNumber)

	return &domain.ConfigDiff{
		FromRevision: fromRev,
		ToRevision:   revNumber,
		Diff:         diff,
	}, nil
}

// Restore memulihkan konfigurasi ke revisi tertentu dengan membuat revisi baru
func (s *revisionService) Restore(ctx context.Context, nodeID, revNumber int, actorID int) error {
	// Ambil revisi target
	target, err := s.repo.FindByNodeAndNumber(ctx, nodeID, revNumber)
	if err != nil {
		return fmt.Errorf("revision: find target revision: %w", err)
	}

	// Buat nomor revisi berikutnya
	nextNum, err := s.repo.NextRevisionNumber(ctx, nodeID)
	if err != nil {
		return fmt.Errorf("revision: get next revision number: %w", err)
	}

	// Buat revisi baru dengan content dari revisi target
	newRev := &domain.ConfigRevision{
		NodeID:         nodeID,
		RevisionNumber: nextNum,
		ConfigContent:  target.ConfigContent,
		Comment:        fmt.Sprintf("Restored from revision #%d", revNumber),
		UserID:         actorID,
	}

	_, err = s.repo.Create(ctx, newRev)
	if err != nil {
		return fmt.Errorf("revision: create restore revision: %w", err)
	}

	_ = s.auditSvc.Log(ctx, &domain.AuditLog{
		UserID:       &actorID,
		Action:       domain.AuditActionRevisionRestored,
		ResourceType: "config_revision",
		ResourceID:   &nodeID,
		Detail:       fmt.Sprintf("Restored node %d config to revision #%d", nodeID, revNumber),
	})

	return nil
}

// generateUnifiedDiff menghasilkan unified diff sederhana antara dua string
// Implementasi ini adalah pure Go tanpa external diff library
func generateUnifiedDiff(oldContent, newContent string, fromRev, toRev int) string {
	if oldContent == newContent {
		return ""
	}

	oldLines := strings.Split(oldContent, "\n")
	newLines := strings.Split(newContent, "\n")

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("--- revision/%d\n", fromRev))
	sb.WriteString(fmt.Sprintf("+++ revision/%d\n", toRev))

	// Myers diff algorithm sederhana: LCS-based line diff
	lcs := longestCommonSubsequence(oldLines, newLines)

	i, j, k := 0, 0, 0
	for k < len(lcs) || i < len(oldLines) || j < len(newLines) {
		// Tulis baris yang dihapus
		for i < len(oldLines) && (k >= len(lcs) || oldLines[i] != lcs[k]) {
			sb.WriteString("- " + oldLines[i] + "\n")
			i++
		}
		// Tulis baris yang ditambahkan
		for j < len(newLines) && (k >= len(lcs) || newLines[j] != lcs[k]) {
			sb.WriteString("+ " + newLines[j] + "\n")
			j++
		}
		// Tulis baris yang sama (konteks)
		if k < len(lcs) {
			sb.WriteString("  " + lcs[k] + "\n")
			i++
			j++
			k++
		}
	}

	return sb.String()
}

// longestCommonSubsequence menghitung LCS dari dua slice string (untuk diff)
func longestCommonSubsequence(a, b []string) []string {
	m, n := len(a), len(b)
	// dp[i][j] = panjang LCS dari a[:i] dan b[:j]
	dp := make([][]int, m+1)
	for i := range dp {
		dp[i] = make([]int, n+1)
	}

	for i := 1; i <= m; i++ {
		for j := 1; j <= n; j++ {
			if a[i-1] == b[j-1] {
				dp[i][j] = dp[i-1][j-1] + 1
			} else if dp[i-1][j] > dp[i][j-1] {
				dp[i][j] = dp[i-1][j]
			} else {
				dp[i][j] = dp[i][j-1]
			}
		}
	}

	// Rekonstruksi LCS
	result := make([]string, 0, dp[m][n])
	i, j := m, n
	for i > 0 && j > 0 {
		if a[i-1] == b[j-1] {
			result = append([]string{a[i-1]}, result...)
			i--
			j--
		} else if dp[i-1][j] > dp[i][j-1] {
			i--
		} else {
			j--
		}
	}
	return result
}
