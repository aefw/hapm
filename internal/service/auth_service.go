package service

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/aefw/hapm/internal/config"
	"github.com/aefw/hapm/internal/domain"
	"github.com/aefw/hapm/internal/security"
	"github.com/aefw/hapm/pkg/iputil"
)

// ErrInvalidCredentials dikembalikan ketika username/password tidak cocok
var ErrInvalidCredentials = errors.New("invalid username or password")

// ErrAccountLocked dikembalikan ketika akun dikunci
var ErrAccountLocked = errors.New("account is locked, please try again later")

// ErrTooManyAttempts dikembalikan ketika terlalu banyak percobaan login gagal
var ErrTooManyAttempts = errors.New("too many failed attempts, please try again later")

// ErrTokenExpired dikembalikan ketika token sudah kadaluarsa
var ErrTokenExpired = errors.New("token has expired")

// ErrTokenInvalid dikembalikan ketika token tidak valid
var ErrTokenInvalid = errors.New("token is invalid")

// authService implements domain.AuthService
type authService struct {
	cfg              *config.Config
	userRepo         domain.UserRepository
	refreshTokenRepo domain.RefreshTokenRepository
	loginAttemptRepo domain.LoginAttemptRepository
	auditSvc         domain.AuditService
	proxyMode        iputil.Mode
}

// NewAuthService membuat instance AuthService baru
func NewAuthService(
	cfg *config.Config,
	userRepo domain.UserRepository,
	refreshTokenRepo domain.RefreshTokenRepository,
	loginAttemptRepo domain.LoginAttemptRepository,
	auditSvc domain.AuditService,
) domain.AuthService {
	return &authService{
		cfg:              cfg,
		userRepo:         userRepo,
		refreshTokenRepo: refreshTokenRepo,
		loginAttemptRepo: loginAttemptRepo,
		auditSvc:         auditSvc,
		proxyMode:        iputil.Mode(cfg.Proxy.Mode),
	}
}

// Login memvalidasi kredensial dan menghasilkan access+refresh token
func (s *authService) Login(ctx context.Context, r *http.Request, req *domain.LoginRequest) (*domain.LoginResponse, error) {
	ip := iputil.RealIP(r, s.proxyMode)
	window := s.cfg.RateLimit.LoginWindowMinutes
	maxAttempts := s.cfg.RateLimit.LockoutAttempts

	// Cek rate limit per IP
	ipFailCount, err := s.loginAttemptRepo.CountFailedByIP(ctx, ip, window)
	if err != nil {
		return nil, fmt.Errorf("auth: count failed by ip: %w", err)
	}
	if ipFailCount >= maxAttempts {
		_ = s.auditSvc.LogFromRequest(ctx, r, nil, domain.AuditActionUserLoginFailed, "auth", nil,
			fmt.Sprintf("IP %s blocked after %d failed attempts", ip, ipFailCount))
		return nil, ErrTooManyAttempts
	}

	// Cek rate limit per username jika username diisi
	if req.Username != "" {
		usernameFailCount, err := s.loginAttemptRepo.CountFailedByUsername(ctx, req.Username, window)
		if err != nil {
			return nil, fmt.Errorf("auth: count failed by username: %w", err)
		}
		if usernameFailCount >= maxAttempts {
			return nil, ErrTooManyAttempts
		}
	}

	// recordAttempt mencatat percobaan login ke DB
	recordAttempt := func(userID *int, success bool) {
		la := &domain.LoginAttempt{
			UserID:    userID,
			Username:  req.Username,
			IPAddress: ip,
			Success:   success,
			UserAgent: r.UserAgent(),
		}
		_ = s.loginAttemptRepo.Create(ctx, la)
	}

	// Cari user berdasarkan username
	user, err := s.userRepo.FindByUsername(ctx, req.Username)
	if err != nil {
		recordAttempt(nil, false)
		return nil, ErrInvalidCredentials
	}

	// Cek status locked
	if user.IsLocked() {
		return nil, ErrAccountLocked
	}

	// Cek status aktif
	if !user.Active {
		recordAttempt(&user.ID, false)
		return nil, ErrInvalidCredentials
	}

	// Verifikasi password menggunakan Argon2id
	ok, err := security.VerifyPassword(req.Password, user.Password)
	if err != nil || !ok {
		recordAttempt(&user.ID, false)
		return nil, ErrInvalidCredentials
	}

	// Password benar — catat sukses
	recordAttempt(&user.ID, true)

	// Generate access token (JWT HS512)
	accessExpiry := s.cfg.JWT.AccessExpiry
	accessToken, err := security.GenerateAccessToken(user.ID, user.Username, user.Role, s.cfg.JWT.AccessSecret, accessExpiry)
	if err != nil {
		return nil, fmt.Errorf("auth: generate access token: %w", err)
	}

	// Generate refresh token
	refreshExpiry := s.cfg.JWT.RefreshExpiry
	refreshToken, jti, err := security.GenerateRefreshToken(user.ID, s.cfg.JWT.RefreshSecret, refreshExpiry)
	if err != nil {
		return nil, fmt.Errorf("auth: generate refresh token: %w", err)
	}

	// Simpan refresh token (hash) ke DB
	rt := &domain.RefreshToken{
		UserID:    user.ID,
		TokenHash: security.HashToken(refreshToken),
		JTI:       jti,
		ExpiresAt: time.Now().Add(refreshExpiry),
		UserAgent: r.UserAgent(),
		IPAddress: ip,
	}
	if err := s.refreshTokenRepo.Create(ctx, rt); err != nil {
		return nil, fmt.Errorf("auth: store refresh token: %w", err)
	}

	// Update last login timestamp
	_ = s.userRepo.UpdateLastLogin(ctx, user.ID)

	// Audit trail
	_ = s.auditSvc.LogFromRequest(ctx, r, &user.ID, domain.AuditActionUserLogin, "auth", nil,
		fmt.Sprintf("User %s logged in from %s", user.Username, ip))

	return &domain.LoginResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresIn:    int(accessExpiry.Seconds()),
		User:         user,
	}, nil
}

// Logout mencabut refresh token aktif milik user
func (s *authService) Logout(ctx context.Context, userID int, refreshToken string) error {
	hash := security.HashToken(refreshToken)
	rt, err := s.refreshTokenRepo.FindByTokenHash(ctx, hash)
	if err != nil {
		// Token tidak ditemukan — anggap sudah logout, tidak error
		return nil
	}
	if rt.UserID != userID {
		return ErrTokenInvalid
	}
	return s.refreshTokenRepo.Revoke(ctx, rt.ID)
}

// RefreshToken memvalidasi refresh token dan menerbitkan pasangan token baru (rotation)
func (s *authService) RefreshToken(ctx context.Context, req *domain.RefreshRequest) (*domain.RefreshResponse, error) {
	// Validasi JWT signature dan expiry
	claims, err := security.ValidateToken(req.RefreshToken, s.cfg.JWT.RefreshSecret)
	if err != nil {
		return nil, ErrTokenInvalid
	}

	// Cek keberadaan dan status token di DB
	hash := security.HashToken(req.RefreshToken)
	rt, err := s.refreshTokenRepo.FindByTokenHash(ctx, hash)
	if err != nil {
		return nil, ErrTokenInvalid
	}
	if rt.Revoked {
		return nil, ErrTokenInvalid
	}
	if time.Now().After(rt.ExpiresAt) {
		return nil, ErrTokenExpired
	}

	// Pastikan user masih aktif
	user, err := s.userRepo.FindByID(ctx, claims.UserID)
	if err != nil {
		return nil, ErrTokenInvalid
	}
	if !user.Active || user.IsLocked() {
		return nil, ErrAccountLocked
	}

	// Cabut token lama (refresh token rotation untuk keamanan)
	_ = s.refreshTokenRepo.Revoke(ctx, rt.ID)

	// Terbitkan access token baru
	accessExpiry := s.cfg.JWT.AccessExpiry
	accessToken, err := security.GenerateAccessToken(user.ID, user.Username, user.Role, s.cfg.JWT.AccessSecret, accessExpiry)
	if err != nil {
		return nil, fmt.Errorf("auth: generate access token: %w", err)
	}

	// Terbitkan refresh token baru
	refreshExpiry := s.cfg.JWT.RefreshExpiry
	newRefreshToken, jti, err := security.GenerateRefreshToken(user.ID, s.cfg.JWT.RefreshSecret, refreshExpiry)
	if err != nil {
		return nil, fmt.Errorf("auth: generate refresh token: %w", err)
	}

	newRT := &domain.RefreshToken{
		UserID:    user.ID,
		TokenHash: security.HashToken(newRefreshToken),
		JTI:       jti,
		ExpiresAt: time.Now().Add(refreshExpiry),
		UserAgent: rt.UserAgent,
		IPAddress: rt.IPAddress,
	}
	if err := s.refreshTokenRepo.Create(ctx, newRT); err != nil {
		return nil, fmt.Errorf("auth: store refresh token: %w", err)
	}

	return &domain.RefreshResponse{
		AccessToken:  accessToken,
		RefreshToken: newRefreshToken,
		ExpiresIn:    int(accessExpiry.Seconds()),
	}, nil
}

// GetMe mengembalikan profil user yang sedang login
func (s *authService) GetMe(ctx context.Context, userID int) (*domain.User, error) {
	user, err := s.userRepo.FindByID(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("auth: find user: %w", err)
	}
	user.Password = ""
	return user, nil
}

// ChangePassword mengganti password dengan verifikasi password lama terlebih dahulu
func (s *authService) ChangePassword(ctx context.Context, userID int, req *domain.ChangePasswordRequest) error {
	user, err := s.userRepo.FindByID(ctx, userID)
	if err != nil {
		return fmt.Errorf("auth: find user: %w", err)
	}

	// Verifikasi password lama
	ok, err := security.VerifyPassword(req.OldPassword, user.Password)
	if err != nil || !ok {
		return ErrInvalidCredentials
	}

	// Validasi kekuatan password baru
	if len(req.NewPassword) < 8 {
		return errors.New("new password must be at least 8 characters")
	}

	// Hash password baru dengan Argon2id
	hash, err := security.HashPassword(req.NewPassword)
	if err != nil {
		return fmt.Errorf("auth: hash password: %w", err)
	}

	if err := s.userRepo.UpdatePassword(ctx, userID, hash); err != nil {
		return fmt.Errorf("auth: update password: %w", err)
	}

	// Cabut semua refresh token — paksa re-login di semua device
	_ = s.refreshTokenRepo.RevokeAllByUser(ctx, userID)

	return nil
}
