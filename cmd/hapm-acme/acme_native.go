package main

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/challenge/dns01"
	legoLog "github.com/go-acme/lego/v4/log"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/providers/dns/cloudflare"
	"github.com/go-acme/lego/v4/registration"
)

// acmeUser mengimplementasi lego's registration.User interface.
type acmeUser struct {
	email        string
	registration *registration.Resource
	key          crypto.PrivateKey
}

func (u *acmeUser) GetEmail() string                        { return u.email }
func (u *acmeUser) GetRegistration() *registration.Resource { return u.registration }
func (u *acmeUser) GetPrivateKey() crypto.PrivateKey        { return u.key }

// waitingCFProvider membungkus Cloudflare DNS provider lego dan menambahkan
// propagation wait via Cloudflare DoH (HTTPS) setelah record dibuat.
// Ini menghindari propagation check langsung ke Cloudflare NS yang diblokir firewall.
type waitingCFProvider struct {
	inner   *cloudflare.DNSProvider
	maxWait time.Duration
}

func (w *waitingCFProvider) Present(domain, token, keyAuth string) error {
	if err := w.inner.Present(domain, token, keyAuth); err != nil {
		return err
	}
	info := dns01.GetChallengeInfo(domain, keyAuth)
	log.Printf("[hapm-acme] DNS record dibuat untuk %s, menunggu propagasi via DoH...", info.FQDN)
	w.waitForDOH(info.FQDN, info.Value)
	return nil
}

func (w *waitingCFProvider) CleanUp(domain, token, keyAuth string) error {
	return w.inner.CleanUp(domain, token, keyAuth)
}

func (w *waitingCFProvider) waitForDOH(fqdn, expectedValue string) {
	deadline := time.Now().Add(w.maxWait)
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	for time.Now().Before(deadline) {
		<-ticker.C
		if visible, err := checkTXTViaDOH(fqdn, expectedValue); err == nil && visible {
			log.Printf("[hapm-acme] DNS record %s terlihat via DoH, lanjut ke verifikasi LE", fqdn)
			return
		}
		log.Printf("[hapm-acme] DNS %s belum terlihat via DoH, menunggu...", fqdn)
	}
	log.Printf("[hapm-acme] PERINGATAN: propagasi DoH timeout untuk %s, tetap lanjutkan", fqdn)
}

// checkTXTViaDOH memeriksa apakah TXT record terlihat via Cloudflare DoH (DNS over HTTPS).
// HTTPS tidak diblokir firewall; Cloudflare DoH selalu punya data terbaru dari zone mereka sendiri.
func checkTXTViaDOH(fqdn, expectedValue string) (bool, error) {
	name := strings.TrimSuffix(fqdn, ".")
	url := "https://cloudflare-dns.com/dns-query?name=" + name + "&type=TXT"

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("Accept", "application/dns-json")

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return false, err
	}

	var result struct {
		Answer []struct {
			Type uint16 `json:"type"`
			Data string `json:"data"`
		} `json:"Answer"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return false, err
	}

	for _, a := range result.Answer {
		if a.Type != 16 { // TXT = 16
			continue
		}
		data := strings.Trim(a.Data, `"`)
		data = strings.ReplaceAll(data, `" "`, "")
		if strings.Contains(data, expectedValue) {
			return true, nil
		}
	}
	return false, nil
}

// issueCertNative menerbitkan certificate menggunakan lego sebagai library Go.
// Menghindari exec CLI dan memberikan kontrol penuh atas flow DNS-01.
func issueCertNative(req *IssueRequest, cfg legoConfig) (logs string, err error) {
	var logBuf bytes.Buffer
	prevLogger := legoLog.Logger
	legoLog.Logger = log.New(io.MultiWriter(os.Stderr, &logBuf), "", log.LstdFlags)
	defer func() { legoLog.Logger = prevLogger }()

	// Generate account key untuk ACME registration
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", fmt.Errorf("generate account key: %w", err)
	}

	user := &acmeUser{email: req.Email, key: privateKey}

	legoConfig := lego.NewConfig(user)
	legoConfig.Certificate.KeyType = certcrypto.RSA2048

	if req.Staging {
		legoConfig.CADirURL = lego.LEDirectoryStaging
	} else {
		legoConfig.CADirURL = lego.LEDirectoryProduction
	}

	client, err := lego.NewClient(legoConfig)
	if err != nil {
		return logBuf.String(), fmt.Errorf("buat ACME client: %w", err)
	}

	// Setup Cloudflare DNS provider via env var
	if req.CFToken != "" {
		os.Setenv("CF_DNS_API_TOKEN", req.CFToken)
	}
	cfProvider, err := cloudflare.NewDNSProvider()
	if err != nil {
		return logBuf.String(), fmt.Errorf("buat Cloudflare provider: %w", err)
	}

	wrapped := &waitingCFProvider{
		inner:   cfProvider,
		maxWait: 5 * time.Minute,
	}

	// DisableCompletePropagationRequirement: lego tidak query Cloudflare NS langsung
	// (query tersebut diblokir firewall). Propagation sudah diverifikasi via DoH oleh wrapped provider.
	if err := client.Challenge.SetDNS01Provider(wrapped,
		dns01.DisableCompletePropagationRequirement()); err != nil {
		return logBuf.String(), fmt.Errorf("set DNS provider: %w", err)
	}

	// Register ACME account
	reg, err := client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
	if err != nil {
		return logBuf.String(), fmt.Errorf("register ACME account: %w", err)
	}
	user.registration = reg

	// Request certificate
	certRequest := certificate.ObtainRequest{
		Domains: req.Domains,
		Bundle:  true,
	}
	certs, err := client.Certificate.Obtain(certRequest)
	if err != nil {
		return logBuf.String(), fmt.Errorf("obtain certificate: %w", err)
	}

	// Tulis file ke direktori yang sama dengan format lego CLI output.
	// hapm membaca dari <storagePath>/certificates/<primaryDomain>.{crt,key,issuer.crt}
	primaryDomain := req.Domains[0]
	// Wildcard domain: *.dodols.com → _.dodols.com (lego CLI convention)
	legoFileName := strings.ReplaceAll(primaryDomain, "*", "_")
	certDir := filepath.Join(req.StoragePath, "certificates")
	if err := os.MkdirAll(certDir, 0700); err != nil {
		return logBuf.String(), fmt.Errorf("buat direktori certificates: %w", err)
	}

	if err := os.WriteFile(filepath.Join(certDir, legoFileName+".crt"), certs.Certificate, 0600); err != nil {
		return logBuf.String(), fmt.Errorf("tulis certificate: %w", err)
	}
	if err := os.WriteFile(filepath.Join(certDir, legoFileName+".key"), certs.PrivateKey, 0600); err != nil {
		return logBuf.String(), fmt.Errorf("tulis private key: %w", err)
	}
	if len(certs.IssuerCertificate) > 0 {
		if err := os.WriteFile(filepath.Join(certDir, legoFileName+".issuer.crt"), certs.IssuerCertificate, 0600); err != nil {
			return logBuf.String(), fmt.Errorf("tulis issuer cert: %w", err)
		}
	}

	log.Printf("[hapm-acme] Certificate berhasil diterbitkan untuk %v", req.Domains)
	return logBuf.String(), nil
}

// renewCertNative memperbarui certificate menggunakan lego sebagai library Go.
func renewCertNative(req *RenewRequest, cfg legoConfig) (logs string, err error) {
	// Cari file cert yang sudah ada
	primaryDomain := req.Domains[0]
	legoFileName := strings.ReplaceAll(primaryDomain, "*", "_")
	certDir := filepath.Join(req.StoragePath, "certificates")
	certPath := filepath.Join(certDir, legoFileName+".crt")

	certData, err := os.ReadFile(certPath)
	if err != nil {
		return "", fmt.Errorf("baca certificate lama gagal (belum pernah issue?): %w", err)
	}

	// Untuk renew, gunakan alur issue biasa (simpler) dengan domain yang sama.
	// Lego library juga bisa melakukan "renew" tapi butuh private key lama.
	// Untuk simplisitas, kita issue ulang (ACME mendukung ini - hanya perlu domain validation ulang).
	issueReq := &IssueRequest{
		JobUUID:     req.JobUUID,
		CertUUID:    req.CertUUID,
		Domains:     req.Domains,
		Challenge:   req.Challenge,
		CFToken:     req.CFToken,
		Email:       req.Email,
		Staging:     req.Staging,
		StoragePath: req.StoragePath,
		WebRootPath: req.WebRootPath,
	}
	_ = certData // consumed above for existence check
	return issueCertNative(issueReq, cfg)
}
