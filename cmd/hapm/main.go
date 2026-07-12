package main

import (
	"context"
	"log"
	"net/http"
	"os"

	"github.com/aefw/hapm/internal/config"
	"github.com/aefw/hapm/internal/core"
	"github.com/aefw/hapm/internal/domain"
	"github.com/aefw/hapm/internal/handler"
	"github.com/aefw/hapm/internal/middleware"
	"github.com/aefw/hapm/internal/repository/sqlite"
	"github.com/aefw/hapm/internal/service"
	"github.com/aefw/hapm/pkg/acme"
	"github.com/aefw/hapm/pkg/haproxy"
	pkgssh "github.com/aefw/hapm/pkg/ssh"
	"github.com/aefw/hapm/pkg/storage"
	"github.com/aefw/hapm/web"
)

func main() {
	// Subcommands CLI
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "-health":
			os.Exit(0)
		case "reset-password":
			runResetPassword(os.Args[2:])
		}
	}

	// ─── 1. Load konfigurasi dari environment ──────────────────────
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("[FATAL] Gagal load konfigurasi: %v", err)
	}

	// ─── 2. Inisialisasi database ──────────────────────────────────
	db, err := sqlite.NewDB(cfg)
	if err != nil {
		log.Fatalf("[FATAL] Gagal inisialisasi database: %v", err)
	}
	defer db.Close()

	if err := sqlite.RunMigrations(db.SQL()); err != nil {
		log.Fatalf("[FATAL] Gagal menjalankan migrasi: %v", err)
	}

	if err := sqlite.Seed(db.SQL()); err != nil {
		log.Printf("[WARNING] Seed gagal (mungkin sudah ada): %v", err)
	}

	// ─── 3. Inisialisasi repository ────────────────────────────────
	userRepo := sqlite.NewUserRepository(db.SQL())
	nodeRepo := sqlite.NewNodeRepository(db.SQL())
	backendRepo := sqlite.NewBackendRepository(db.SQL())
	domainRepo := sqlite.NewDomainRepository(db.SQL())
	certRepo := sqlite.NewCertificateRepository(db.SQL())
	certJobRepo := sqlite.NewCertJobRepository(db.SQL())
	certDeployRepo := sqlite.NewCertDeploymentRepository(db.SQL())
	settingRepo := sqlite.NewSettingRepository(db.SQL())
	revisionRepo := sqlite.NewRevisionRepository(db.SQL())
	deployRepo := sqlite.NewDeploymentRepository(db.SQL())
	replicationRepo := sqlite.NewReplicationRepository(db.SQL())
	auditRepo := sqlite.NewAuditRepository(db.SQL())
	refreshTokenRepo := sqlite.NewRefreshTokenRepository(db.SQL())
	loginAttemptRepo := sqlite.NewLoginAttemptRepository(db.SQL())
	driftRepo := sqlite.NewDriftRepository(db.SQL())
	serviceRepo := sqlite.NewServiceRepository(db.SQL())
	authUserRepo := sqlite.NewAuthUserRepository(db.SQL())
	authGroupRepo := sqlite.NewAuthGroupRepository(db.SQL())

	// ─── 4. Inisialisasi package eksternal ────────────────────────
	sshClient := pkgssh.NewClient()
	haproxyGen := haproxy.NewGenerator()
	haproxyVal := haproxy.NewValidatorWithSSH(sshClient)
	haproxyStats := haproxy.NewStatsCollector()
	haproxyProv := haproxy.NewProvisioner(sshClient)

	// CMC: certificate storage & ACME client
	certStore := storage.NewCertStore(cfg.CMC.StoragePath)
	acmeClient := acme.NewClient(cfg.CMC.ACMEServiceURL)

	// ─── 5. Inisialisasi services ──────────────────────────────────
	auditSvc := service.NewAuditService(cfg, auditRepo)
	authSvc := service.NewAuthService(cfg, userRepo, refreshTokenRepo, loginAttemptRepo, auditSvc)
	userSvc := service.NewUserService(userRepo, auditSvc)
	nodeSvc := service.NewNodeService(cfg, nodeRepo, sshClient, haproxyProv, auditSvc)
	backendSvc := service.NewBackendService(backendRepo, auditSvc)
	domainSvc := service.NewDomainService(domainRepo, backendRepo, auditSvc)
	settingsSvc := service.NewSettingsService(cfg, settingRepo, auditSvc)
	certSvc := service.NewCertificateService(cfg, certRepo, certJobRepo, settingsSvc, acmeClient, certStore, auditSvc)
	certJobSvc := service.NewCertJobService(certJobRepo)
	distSvc := service.NewDistributionService(cfg, certRepo, certDeployRepo, nodeRepo, certStore, sshClient, auditSvc)
	schedulerSvc := service.NewSchedulerService(certRepo, certSvc, distSvc)
	configSvc := service.NewConfigService(nodeRepo, backendRepo, domainRepo, certRepo, serviceRepo, authGroupRepo, haproxyGen)
	serviceSvc := service.NewServiceService(serviceRepo, backendRepo, auditSvc)
	revisionSvc := service.NewRevisionService(revisionRepo, auditSvc)
	deploySvc := service.NewDeployService(cfg, nodeRepo, domainRepo, certRepo, certStore, configSvc, revisionRepo, deployRepo, sshClient, haproxyVal, auditSvc)
	replicationSvc := service.NewReplicationService(cfg, nodeRepo, replicationRepo, driftRepo, configSvc, sshClient, auditSvc)
	monitoringSvc := service.NewMonitoringService(nodeRepo, haproxyStats, sshClient)
	dashboardSvc := service.NewDashboardService(nodeRepo, domainRepo, backendRepo, serviceRepo, certRepo, deployRepo, auditRepo, monitoringSvc)
	authUserSvc := service.NewAuthUserService(authUserRepo, auditSvc)
	authGroupSvc := service.NewAuthGroupService(authGroupRepo, authUserRepo, auditSvc)

	// Compile-time interface check
	var _ domain.AuditService = auditSvc
	var _ domain.AuthService = authSvc
	var _ domain.UserService = userSvc
	var _ domain.NodeService = nodeSvc
	var _ domain.BackendService = backendSvc
	var _ domain.DomainService = domainSvc
	var _ domain.CertificateService = certSvc
	var _ domain.CertJobService = certJobSvc
	var _ domain.DistributionService = distSvc
	var _ domain.SchedulerService = schedulerSvc
	var _ domain.SettingsService = settingsSvc
	var _ domain.ConfigService = configSvc
	var _ domain.RevisionService = revisionSvc
	var _ domain.DeployService = deploySvc
	var _ domain.ReplicationService = replicationSvc
	var _ domain.MonitoringService = monitoringSvc
	var _ domain.ServiceService = serviceSvc
	var _ domain.DashboardService = dashboardSvc
	var _ domain.AuthUserService = authUserSvc
	var _ domain.AuthGroupService = authGroupSvc

	// ─── 6. Inisialisasi router ─────────────────────────────────────
	router := core.NewRouter()

	// ─── 7. Inisialisasi handlers ───────────────────────────────────
	handler.RegisterAuthRoutes(router, cfg, authSvc)
	handler.RegisterUserRoutes(router, cfg, userSvc)
	handler.RegisterNodeRoutes(router, cfg, nodeSvc)
	handler.RegisterBackendRoutes(router, cfg, backendSvc)
	handler.RegisterDomainRoutes(router, cfg, domainSvc)
	handler.RegisterCMCRoutes(router, cfg, certSvc, certJobSvc, distSvc, certDeployRepo)
	handler.RegisterSettingsRoutes(router, cfg, settingsSvc)
	handler.RegisterConfigRoutes(router, cfg, configSvc)
	handler.RegisterDeployRoutes(router, cfg, deploySvc)
	handler.RegisterRevisionRoutes(router, cfg, revisionSvc)
	handler.RegisterReplicationRoutes(router, cfg, replicationSvc)
	handler.RegisterMonitoringRoutes(router, cfg, monitoringSvc)
	handler.RegisterAuditRoutes(router, cfg, auditSvc)
	handler.RegisterServiceRoutes(router, cfg, serviceSvc)
	handler.RegisterDashboardRoutes(router, cfg, dashboardSvc)
	handler.RegisterHAProxyAuthRoutes(router, cfg, authUserSvc, authGroupSvc)

	// ─── 8. Jalankan scheduler CMC ─────────────────────────────────
	ctx := context.Background()
	schedulerSvc.Start(ctx)

	// ─── 9. Bangun middleware stack ─────────────────────────────────
	// Mux utama: /api/ → router (API), / → frontend SPA
	mainMux := http.NewServeMux()
	mainMux.Handle("/api/", router)
	mainMux.Handle("/", web.Handler())

	var h http.Handler = mainMux
	h = middleware.NewLoggingMiddleware(cfg, h)
	h = middleware.NewAPIRateLimitMiddleware(cfg, h)
	h = middleware.NewRecoveryMiddleware(h)
	h = middleware.NewRequestIDMiddleware(h)
	h = middleware.NewCORSMiddleware(h, cfg)
	h = middleware.NewSecurityHeadersMiddleware(h)

	// ─── 10. Jalankan aplikasi ──────────────────────────────────────
	app := core.NewApp(cfg, router)
	if err := app.Run(h); err != nil {
		log.Fatalf("[FATAL] %v", err)
	}
}
