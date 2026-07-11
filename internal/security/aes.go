package security

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
)

// Encrypt mengenkripsi plaintext menggunakan AES-256-GCM.
//
// keyHex adalah 64-character hex string (32 bytes) dari APP_ENCRYPTION_KEY.
//
// Output format: base64(nonce[12] + ciphertext + tag[16])
//
// Security properties:
//   - Authenticated encryption: mencegah tampering
//   - Unique nonce per enkripsi: mencegah nonce reuse attack
//   - 256-bit key: brute-force resistant
func Encrypt(plaintext, keyHex string) (string, error) {
	key, err := hex.DecodeString(keyHex)
	if err != nil {
		return "", fmt.Errorf("encryption key tidak valid (harus 64-char hex): %v", err)
	}
	if len(key) != 32 {
		return "", fmt.Errorf("encryption key harus 32 bytes, dapat %d bytes", len(key))
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("gagal membuat AES cipher: %v", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("gagal membuat GCM: %v", err)
	}

	// Generate random nonce (96-bit / 12 bytes)
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("gagal generate nonce: %v", err)
	}

	// Seal: nonce + ciphertext + tag (GCM append tag otomatis)
	ciphertext := gcm.Seal(nonce, nonce, []byte(plaintext), nil)

	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// Decrypt mendekripsi ciphertext yang dihasilkan oleh Encrypt.
//
// keyHex adalah 64-character hex string yang sama dengan saat enkripsi.
func Decrypt(ciphertextB64, keyHex string) (string, error) {
	key, err := hex.DecodeString(keyHex)
	if err != nil {
		return "", fmt.Errorf("encryption key tidak valid: %v", err)
	}
	if len(key) != 32 {
		return "", fmt.Errorf("encryption key harus 32 bytes")
	}

	data, err := base64.StdEncoding.DecodeString(ciphertextB64)
	if err != nil {
		return "", fmt.Errorf("ciphertext tidak valid (base64): %v", err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("gagal membuat AES cipher: %v", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("gagal membuat GCM: %v", err)
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return "", fmt.Errorf("ciphertext terlalu pendek")
	}

	nonce, ciphertext := data[:nonceSize], data[nonceSize:]

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		// Jangan bocorkan detail error GCM (bisa jadi timing/oracle attack)
		return "", fmt.Errorf("dekripsi gagal: data rusak atau key salah")
	}

	return string(plaintext), nil
}

// EncryptBytes adalah versi Encrypt untuk input []byte
func EncryptBytes(data []byte, keyHex string) (string, error) {
	return Encrypt(string(data), keyHex)
}

// DecryptBytes adalah versi Decrypt yang mengembalikan []byte
func DecryptBytes(ciphertextB64, keyHex string) ([]byte, error) {
	s, err := Decrypt(ciphertextB64, keyHex)
	if err != nil {
		return nil, err
	}
	return []byte(s), nil
}
