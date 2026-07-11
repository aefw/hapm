package security

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

// Argon2Params adalah parameter hashing Argon2id.
// Mengikuti rekomendasi OWASP 2024.
type Argon2Params struct {
	Memory      uint32 // KB — 64 MB
	Iterations  uint32 // time cost
	Parallelism uint8  // thread count
	SaltLength  uint32 // bytes
	KeyLength   uint32 // output bytes
}

// DefaultArgon2Params adalah parameter default yang aman untuk produksi
var DefaultArgon2Params = &Argon2Params{
	Memory:      64 * 1024, // 64 MB
	Iterations:  3,
	Parallelism: 2,
	SaltLength:  16,
	KeyLength:   32,
}

// HashPassword menghasilkan hash Argon2id dari password plaintext.
// Mengembalikan string dalam format PHC:
//
//	$argon2id$v=19$m=65536,t=3,p=2$<base64_salt>$<base64_hash>
func HashPassword(password string) (string, error) {
	p := DefaultArgon2Params

	// Generate random salt
	salt := make([]byte, p.SaltLength)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("gagal generate salt: %v", err)
	}

	// Compute hash
	hash := argon2.IDKey([]byte(password), salt, p.Iterations, p.Memory, p.Parallelism, p.KeyLength)

	// Encode ke format PHC
	b64Salt := base64.RawStdEncoding.EncodeToString(salt)
	b64Hash := base64.RawStdEncoding.EncodeToString(hash)

	encoded := fmt.Sprintf(
		"$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version,
		p.Memory,
		p.Iterations,
		p.Parallelism,
		b64Salt,
		b64Hash,
	)

	return encoded, nil
}

// VerifyPassword memverifikasi password plaintext terhadap hash Argon2id.
// Mengembalikan true jika cocok, false jika tidak.
// Menggunakan constant-time comparison untuk mencegah timing attack.
func VerifyPassword(password, encodedHash string) (bool, error) {
	p, salt, hash, err := decodeHash(encodedHash)
	if err != nil {
		return false, err
	}

	// Hitung hash dari input password dengan parameter yang sama
	inputHash := argon2.IDKey([]byte(password), salt, p.Iterations, p.Memory, p.Parallelism, p.KeyLength)

	// Constant-time comparison
	if subtle.ConstantTimeCompare(hash, inputHash) == 1 {
		return true, nil
	}

	return false, nil
}

// decodeHash mengurai PHC format kembali ke komponen-komponennya
func decodeHash(encodedHash string) (*Argon2Params, []byte, []byte, error) {
	parts := strings.Split(encodedHash, "$")
	// Format: ["", "argon2id", "v=19", "m=65536,t=3,p=2", "<salt>", "<hash>"]
	if len(parts) != 6 {
		return nil, nil, nil, fmt.Errorf("format hash tidak valid: ekspektasi 6 bagian, dapat %d", len(parts))
	}

	if parts[1] != "argon2id" {
		return nil, nil, nil, fmt.Errorf("algoritma tidak didukung: %s", parts[1])
	}

	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil {
		return nil, nil, nil, fmt.Errorf("versi tidak valid: %v", err)
	}
	if version != argon2.Version {
		return nil, nil, nil, fmt.Errorf("versi Argon2 tidak kompatibel: %d", version)
	}

	p := &Argon2Params{}
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &p.Memory, &p.Iterations, &p.Parallelism); err != nil {
		return nil, nil, nil, fmt.Errorf("parameter tidak valid: %v", err)
	}

	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return nil, nil, nil, fmt.Errorf("salt tidak valid: %v", err)
	}
	p.SaltLength = uint32(len(salt))

	hash, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return nil, nil, nil, fmt.Errorf("hash tidak valid: %v", err)
	}
	p.KeyLength = uint32(len(hash))

	return p, salt, hash, nil
}
