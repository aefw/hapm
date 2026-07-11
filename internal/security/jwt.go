package security

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// JWTClaims adalah payload JWT HAPM.
// Tidak menggunakan library eksternal — pure Go.
type JWTClaims struct {
	// Standard claims
	Subject   string `json:"sub"`            // id_users sebagai string
	IssuedAt  int64  `json:"iat"`
	ExpiresAt int64  `json:"exp"`
	JWTID     string `json:"jti,omitempty"`  // unique ID untuk refresh token

	// Custom claims
	UserID   int    `json:"user_id"`
	Username string `json:"username"`
	Role     string `json:"role"`
}

// jwtHeader adalah header JWT fixed: {"alg":"HS512","typ":"JWT"}
var jwtHeader = base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS512","typ":"JWT"}`))

// GenerateAccessToken menghasilkan JWT access token.
//
//   - Algorithm: HS512
//   - Tidak ada external JWT library
//   - Claims: user_id, username, role, exp, iat
func GenerateAccessToken(userID int, username, role, secret string, expiry time.Duration) (string, error) {
	now := time.Now()
	claims := JWTClaims{
		Subject:   fmt.Sprintf("%d", userID),
		IssuedAt:  now.Unix(),
		ExpiresAt: now.Add(expiry).Unix(),
		UserID:    userID,
		Username:  username,
		Role:      role,
	}
	return signJWT(claims, secret)
}

// GenerateRefreshToken menghasilkan JWT refresh token dengan jti (unique ID).
//
//   - jti digunakan untuk single-use enforcement di database
//   - Lebih panjang expiry dari access token
func GenerateRefreshToken(userID int, secret string, expiry time.Duration) (string, string, error) {
	now := time.Now()

	// Generate unique JTI
	jti, err := RandomHex(16)
	if err != nil {
		return "", "", fmt.Errorf("gagal generate JTI: %v", err)
	}

	claims := JWTClaims{
		Subject:   fmt.Sprintf("%d", userID),
		IssuedAt:  now.Unix(),
		ExpiresAt: now.Add(expiry).Unix(),
		JWTID:     jti,
		UserID:    userID,
	}

	token, err := signJWT(claims, secret)
	if err != nil {
		return "", "", err
	}

	return token, jti, nil
}

// ValidateToken memvalidasi JWT token dan mengembalikan claims.
// Memeriksa: signature, expiry, algoritma.
func ValidateToken(tokenString, secret string) (*JWTClaims, error) {
	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("format token tidak valid")
	}

	// Verifikasi header
	expectedHeader := jwtHeader
	if parts[0] != expectedHeader {
		return nil, fmt.Errorf("header token tidak valid")
	}

	// Verifikasi signature
	signingInput := parts[0] + "." + parts[1]
	expectedSig := computeHMAC512(signingInput, secret)
	if !hmac.Equal([]byte(expectedSig), []byte(parts[2])) {
		return nil, fmt.Errorf("signature token tidak valid")
	}

	// Decode payload
	payloadJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("payload token tidak valid")
	}

	var claims JWTClaims
	if err := json.Unmarshal(payloadJSON, &claims); err != nil {
		return nil, fmt.Errorf("claims token tidak valid: %v", err)
	}

	// Cek expiry
	if time.Now().Unix() > claims.ExpiresAt {
		return nil, fmt.Errorf("token sudah expired")
	}

	return &claims, nil
}

// HashToken menghasilkan SHA256 hash dari raw token string.
// Digunakan untuk menyimpan refresh token di database
// tanpa menyimpan nilai aslinya.
func HashToken(token string) string {
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:])
}

// ─── internal helpers ───────────────────────────────────────────────────────

func signJWT(claims JWTClaims, secret string) (string, error) {
	payloadJSON, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("gagal marshal claims: %v", err)
	}

	payload := base64.RawURLEncoding.EncodeToString(payloadJSON)
	signingInput := jwtHeader + "." + payload
	signature := computeHMAC512(signingInput, secret)

	return signingInput + "." + signature, nil
}

func computeHMAC512(data, secret string) string {
	mac := hmac.New(sha512.New, []byte(secret))
	mac.Write([]byte(data))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// RandomHex menghasilkan hex string dari n random bytes.
// Menggunakan crypto/rand — cryptographically secure.
func RandomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("gagal generate random bytes: %v", err)
	}
	return hex.EncodeToString(b), nil
}
