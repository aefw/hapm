// Package storage menyediakan file-based certificate storage untuk CMC.
// Setiap certificate disimpan dalam direktori tersendiri dengan UUID sebagai nama direktori.
package storage

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// CertFiles berisi path absolut ke setiap file certificate
type CertFiles struct {
	CertPEM    string // certificate.pem
	KeyPEM     string // private.key
	IssuerPEM  string // issuer.pem
	ChainPEM   string // chain.pem
	MetaJSON   string // metadata.json
	Dir        string // direktori uuid
}

// CertMetadata adalah metadata certificate yang disimpan dalam metadata.json
type CertMetadata struct {
	UUID        string    `json:"uuid"`
	Provider    string    `json:"provider"`
	Challenge   string    `json:"challenge"`
	Domains     []string  `json:"domains"`
	SAN         []string  `json:"san"`
	Zone        string    `json:"zone"`
	IssuedAt    time.Time `json:"issued_at"`
	ExpiresAt   time.Time `json:"expires_at"`
	RenewBefore int       `json:"renew_before"`
	AutoRenew   bool      `json:"auto_renew"`
	Fingerprint string    `json:"fingerprint_sha256"`
	Status      string    `json:"status"`
}

// CertStore mengelola penyimpanan file certificate
type CertStore struct {
	rootPath string
}

// NewCertStore membuat instance CertStore baru
func NewCertStore(rootPath string) *CertStore {
	return &CertStore{rootPath: rootPath}
}

// Paths mengembalikan path ke semua file certificate untuk UUID tertentu
func (s *CertStore) Paths(uuid string) CertFiles {
	dir := filepath.Join(s.rootPath, uuid)
	return CertFiles{
		Dir:       dir,
		CertPEM:   filepath.Join(dir, "certificate.pem"),
		KeyPEM:    filepath.Join(dir, "private.key"),
		IssuerPEM: filepath.Join(dir, "issuer.pem"),
		ChainPEM:  filepath.Join(dir, "chain.pem"),
		MetaJSON:  filepath.Join(dir, "metadata.json"),
	}
}

// InitDir membuat direktori untuk certificate UUID baru
func (s *CertStore) InitDir(uuid string) error {
	dir := filepath.Join(s.rootPath, uuid)
	return os.MkdirAll(dir, 0700)
}

// SaveManual menyimpan certificate yang diupload manual
func (s *CertStore) SaveManual(uuid, certPEM, keyPEM, chainPEM string) (string, *time.Time, *time.Time, error) {
	if err := s.InitDir(uuid); err != nil {
		return "", nil, nil, fmt.Errorf("storage: init dir: %w", err)
	}
	paths := s.Paths(uuid)

	if err := writeSecure(paths.CertPEM, certPEM); err != nil {
		return "", nil, nil, fmt.Errorf("storage: write cert: %w", err)
	}
	if keyPEM != "" {
		if err := writeSecure(paths.KeyPEM, keyPEM); err != nil {
			return "", nil, nil, fmt.Errorf("storage: write key: %w", err)
		}
	}
	if chainPEM != "" {
		if err := writeSecure(paths.ChainPEM, chainPEM); err != nil {
			return "", nil, nil, fmt.Errorf("storage: write chain: %w", err)
		}
	}

	fingerprint, notBefore, notAfter, err := parseCertInfo(certPEM)
	if err != nil {
		return "", nil, nil, fmt.Errorf("storage: parse cert: %w", err)
	}

	return fingerprint, notBefore, notAfter, nil
}

// SaveLEGO menyimpan certificate hasil LEGO (setelah hapm-acme selesai)
// LEGO menyimpan file di: <lego_path>/certificates/<domain>.crt, <domain>.key, <domain>.issuer.crt
func (s *CertStore) SaveLEGO(uuid, legoDir, domain string) (string, *time.Time, *time.Time, error) {
	if err := s.InitDir(uuid); err != nil {
		return "", nil, nil, fmt.Errorf("storage: init dir: %w", err)
	}
	paths := s.Paths(uuid)

	// Baca file dari direktori LEGO
	certPath := filepath.Join(legoDir, "certificates", domain+".crt")
	keyPath := filepath.Join(legoDir, "certificates", domain+".key")
	issuerPath := filepath.Join(legoDir, "certificates", domain+".issuer.crt")

	certData, err := os.ReadFile(certPath)
	if err != nil {
		return "", nil, nil, fmt.Errorf("storage: baca cert lego: %w", err)
	}
	keyData, err := os.ReadFile(keyPath)
	if err != nil {
		return "", nil, nil, fmt.Errorf("storage: baca key lego: %w", err)
	}

	if err := writeSecure(paths.CertPEM, string(certData)); err != nil {
		return "", nil, nil, err
	}
	if err := writeSecure(paths.KeyPEM, string(keyData)); err != nil {
		return "", nil, nil, err
	}

	// issuer.crt adalah opsional
	if issuerData, err := os.ReadFile(issuerPath); err == nil {
		_ = writeSecure(paths.IssuerPEM, string(issuerData))

		// Gabungkan cert + issuer sebagai chain
		chain := strings.TrimSpace(string(certData)) + "\n" + strings.TrimSpace(string(issuerData)) + "\n"
		_ = writeSecure(paths.ChainPEM, chain)
	}

	fingerprint, notBefore, notAfter, err := parseCertInfo(string(certData))
	if err != nil {
		return "", nil, nil, fmt.Errorf("storage: parse cert lego: %w", err)
	}

	return fingerprint, notBefore, notAfter, nil
}

// BuildHAProxyBundle membuat bundle PEM untuk HAProxy (cert + chain + key) dalam satu file
// Ini yang dikirim ke HAProxy node
func (s *CertStore) BuildHAProxyBundle(uuid string) (string, error) {
	paths := s.Paths(uuid)

	certData, err := os.ReadFile(paths.CertPEM)
	if err != nil {
		return "", fmt.Errorf("storage: baca cert: %w", err)
	}
	keyData, err := os.ReadFile(paths.KeyPEM)
	if err != nil {
		return "", fmt.Errorf("storage: baca key: %w", err)
	}

	var sb strings.Builder
	sb.Write(certData)

	// Tambahkan chain jika ada
	if chainData, err := os.ReadFile(paths.ChainPEM); err == nil {
		sb.Write(chainData)
	}

	sb.Write(keyData)
	return sb.String(), nil
}

// ReadMeta membaca metadata.json
func (s *CertStore) ReadMeta(uuid string) (*CertMetadata, error) {
	data, err := os.ReadFile(s.Paths(uuid).MetaJSON)
	if err != nil {
		return nil, err
	}
	var m CertMetadata
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, err
	}
	return &m, nil
}

// WriteMeta menyimpan metadata.json
func (s *CertStore) WriteMeta(uuid string, m *CertMetadata) error {
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(s.Paths(uuid).MetaJSON, data, 0600)
}

// Remove menghapus seluruh direktori certificate
func (s *CertStore) Remove(uuid string) error {
	return os.RemoveAll(filepath.Join(s.rootPath, uuid))
}

// Exists memeriksa apakah direktori certificate ada
func (s *CertStore) Exists(uuid string) bool {
	_, err := os.Stat(filepath.Join(s.rootPath, uuid))
	return err == nil
}

// LegoDir mengembalikan path direktori yang digunakan hapm-acme untuk LEGO output
func (s *CertStore) LegoDir(uuid string) string {
	return filepath.Join(s.rootPath, uuid, ".lego")
}

// WebRootDir mengembalikan path webroot untuk HTTP-01 challenge
func (s *CertStore) WebRootDir(rootPath string) string {
	return filepath.Join(rootPath, ".well-known", "acme-challenge")
}

// ─── helpers ─────────────────────────────────────────────────────────────────

func writeSecure(path, content string) error {
	return os.WriteFile(path, []byte(content), 0600)
}

func parseCertInfo(certPEM string) (fingerprint string, notBefore, notAfter *time.Time, err error) {
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return "", nil, nil, errors.New("gagal decode PEM block")
	}
	if block.Type != "CERTIFICATE" {
		return "", nil, nil, fmt.Errorf("expected CERTIFICATE PEM, got %s", block.Type)
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", nil, nil, fmt.Errorf("gagal parse certificate: %w", err)
	}

	sum := sha256.Sum256(cert.Raw)
	fp := "sha256:" + hex.EncodeToString(sum[:])

	nb := cert.NotBefore
	na := cert.NotAfter
	return fp, &nb, &na, nil
}
