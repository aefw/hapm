package service

import (
	"context"
	"log"
	"time"

	"github.com/aefw/hapm/internal/domain"
)

// schedulerService implements domain.SchedulerService
// Berjalan setiap 24 jam untuk memeriksa dan memperbarui certificate yang akan expired.
type schedulerService struct {
	certRepo    domain.CertificateRepository
	certSvc     domain.CertificateService
	distSvc     domain.DistributionService
	stopCh      chan struct{}
}

func NewSchedulerService(
	certRepo domain.CertificateRepository,
	certSvc domain.CertificateService,
	distSvc domain.DistributionService,
) domain.SchedulerService {
	return &schedulerService{
		certRepo: certRepo,
		certSvc:  certSvc,
		distSvc:  distSvc,
		stopCh:   make(chan struct{}),
	}
}

func (s *schedulerService) Start(ctx context.Context) {
	log.Println("[SCHEDULER] Certificate renewal scheduler dimulai (interval: 24 jam)")

	// Jalankan langsung saat startup, lalu setiap 24 jam
	go func() {
		s.runRenewalCheck(ctx)

		ticker := time.NewTicker(24 * time.Hour)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				s.runRenewalCheck(ctx)
			case <-s.stopCh:
				log.Println("[SCHEDULER] Certificate renewal scheduler dihentikan")
				return
			case <-ctx.Done():
				return
			}
		}
	}()
}

func (s *schedulerService) Stop() {
	select {
	case s.stopCh <- struct{}{}:
	default:
	}
}

func (s *schedulerService) runRenewalCheck(ctx context.Context) {
	log.Println("[SCHEDULER] Memeriksa certificate yang perlu diperpanjang...")

	certs, err := s.certRepo.ListNeedingRenewal(ctx)
	if err != nil {
		log.Printf("[SCHEDULER] Gagal ambil daftar certificate: %v", err)
		return
	}

	if len(certs) == 0 {
		log.Println("[SCHEDULER] Tidak ada certificate yang perlu diperpanjang")
		return
	}

	log.Printf("[SCHEDULER] Ditemukan %d certificate yang perlu diperpanjang", len(certs))

	systemActorID := 0 // system actor
	for _, cert := range certs {
		log.Printf("[SCHEDULER] Memperbarui certificate: %s (%s)", cert.Name, cert.UUID)

		job, err := s.certSvc.Renew(ctx, cert.UUID, systemActorID)
		if err != nil {
			log.Printf("[SCHEDULER] Gagal trigger renewal untuk %s: %v", cert.Name, err)
			continue
		}

		log.Printf("[SCHEDULER] Renewal job %s dibuat untuk certificate %s", job.UUID, cert.Name)

		// Distribusi ke seluruh node setelah berhasil (async)
		go func(certUUID string) {
			// Tunggu sebentar untuk job selesai (polling sederhana)
			time.Sleep(5 * time.Minute)
			if _, err := s.distSvc.DistributeToAll(ctx, certUUID, systemActorID); err != nil {
				log.Printf("[SCHEDULER] Distribusi certificate %s gagal: %v", certUUID, err)
			}
		}(cert.UUID)
	}
}
