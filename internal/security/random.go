package security

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math/big"
)

const (
	// charsetAlphanumeric digunakan untuk generate password/token yang readable
	charsetAlphanumeric = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	// charsetSafe digunakan untuk generate secret yang URL-safe
	charsetSafe = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
)

// RandomBytes menghasilkan n bytes acak secara kriptografis.
func RandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return nil, fmt.Errorf("gagal generate random bytes: %v", err)
	}
	return b, nil
}

// RandomBase64 menghasilkan base64 string dari n random bytes.
// URL-safe encoding, tanpa padding.
func RandomBase64(n int) (string, error) {
	b, err := RandomBytes(n)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// RandomString menghasilkan random string dengan panjang n dari charset yang aman.
// Setiap karakter dipilih secara uniform menggunakan crypto/rand.
func RandomString(n int) (string, error) {
	result := make([]byte, n)
	charsetLen := big.NewInt(int64(len(charsetSafe)))

	for i := range result {
		idx, err := rand.Int(rand.Reader, charsetLen)
		if err != nil {
			return "", fmt.Errorf("gagal generate random index: %v", err)
		}
		result[i] = charsetSafe[idx.Int64()]
	}

	return string(result), nil
}

// RandomAlphanumeric menghasilkan random alphanumeric string panjang n.
func RandomAlphanumeric(n int) (string, error) {
	result := make([]byte, n)
	charsetLen := big.NewInt(int64(len(charsetAlphanumeric)))

	for i := range result {
		idx, err := rand.Int(rand.Reader, charsetLen)
		if err != nil {
			return "", fmt.Errorf("gagal generate random index: %v", err)
		}
		result[i] = charsetAlphanumeric[idx.Int64()]
	}

	return string(result), nil
}

// GenerateEncryptionKey menghasilkan 32-byte random key dalam format hex.
// Digunakan saat setup awal untuk menghasilkan APP_ENCRYPTION_KEY.
func GenerateEncryptionKey() (string, error) {
	b, err := RandomBytes(32)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// GenerateJWTSecret menghasilkan random secret panjang 64 karakter.
// Digunakan untuk APP_JWT_ACCESS_SECRET dan APP_JWT_REFRESH_SECRET.
func GenerateJWTSecret() (string, error) {
	return RandomString(64)
}
