package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	_ "net/http/pprof"
	"os"
	"os/signal"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	utls "github.com/refraction-networking/utls"
	_ "go.uber.org/automaxprocs"

	"lucidgate/pki"
	"lucidgate/proxy"
	"lucidgate/stealth"
)

var (
	isReloading    int32
	isShuttingDown int32
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(logger)

	cfg, err := parseConfig(os.Args[1:], os.Getenv, os.Stderr)
	if err != nil {
		logger.Error("config parse failed", slog.Any("error", err))
		os.Exit(1)
	}
	if cfg.ShowVersion {
		fmt.Println(version)
		return
	}

	// Initialize upgrader
	upg, err := proxy.NewUpgrader()
	if err != nil {
		logger.Error("initialize upgrader failed", slog.Any("error", err))
		os.Exit(1)
	}
	defer upg.Close()

	// Handle SIGUSR2 for hot-restart
	go func() {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGUSR2)
		for range sigCh {
			logger.Info("SIGUSR2 received, upgrading binary")
			if err := upg.Upgrade(); err != nil {
				logger.Error("upgrade binary failed", slog.Any("error", err))
			}
		}
	}()

	var server *proxy.Server

	// Register health check endpoints
	http.HandleFunc("/livez", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK"))
	})

	http.HandleFunc("/readyz", func(w http.ResponseWriter, r *http.Request) {
		if atomic.LoadInt32(&isReloading) == 1 {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte("Config reload in progress"))
			return
		}
		if atomic.LoadInt32(&isShuttingDown) == 1 {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte("Shutting down"))
			return
		}
		if server != nil && server.IsSaturated() {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte("Connection pool saturated"))
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK"))
	})

	// Start unified administration/metrics server
	go func() {
		addr := "127.0.0.1:6060"
		if cfg.MetricsEnabled && cfg.MetricsListenAddr != "" {
			addr = cfg.MetricsListenAddr
		}
		if cfg.MetricsEnabled {
			http.Handle("/metrics", promhttp.Handler())
			logger.Info("admin server listening (pprof + metrics + health checks)", slog.String("addr", addr))
		} else {
			logger.Info("admin server listening (pprof + health checks)", slog.String("addr", addr))
		}
		if err := http.ListenAndServe(addr, nil); err != nil {
			logger.Error("admin server failed", slog.Any("error", err))
		}
	}()

	var currentConfig atomic.Value
	currentConfig.Store(&cfg)

	// Set certificate cache telemetry callbacks
	pki.OnCacheRequest = func() { proxy.CertCacheRequests.Inc() }
	pki.OnCacheHit = func() { proxy.CertCacheHits.Inc() }
	pki.OnCertGenerate = func(d time.Duration) { proxy.CertGenerationDuration.Observe(d.Seconds()) }

	ca, err := pki.LoadOrCreateCA(cfg.CertDir)
	if err != nil {
		logger.Error("load root ca failed", slog.Any("error", err))
		os.Exit(1)
	}

	logger.Info("root ca ready",
		slog.String("subject", ca.Certificate.Subject.CommonName),
		slog.String("expires", ca.Certificate.NotAfter.Format("2006-01-02")),
	)
	logConfig("config", &cfg, logger)
	if cfg.DumpCredentialsCleartext {
		logger.Warn("CRITICAL WARNING: dump_credentials_cleartext = true. Plaintext credentials (passwords, tokens, cookies) will be captured and written to disk. Ensure this is an authorized forensic environment!")
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	go func() {
		select {
		case <-ctx.Done():
		case <-upg.Exit():
			logger.Info("upgrader exit signaled, shutting down server")
		}
		atomic.StoreInt32(&isShuttingDown, 1)
		stop()
	}()

	otelCtx, otelCancel := context.WithTimeout(context.Background(), 5*time.Second)
	otelShutdown, err := proxy.InitTracing(otelCtx, cfg.TracingEnabled, cfg.TracingEndpoint, cfg.TracingInsecure, cfg.TracingServiceName, cfg.TracingSampleRate)
	otelCancel()
	if err != nil {
		logger.Error("initialize tracing failed", slog.Any("error", err))
		os.Exit(1)
	}
	defer func() {
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer shutdownCancel()
		if err := otelShutdown(shutdownCtx); err != nil {
			logger.Error("shutdown tracing failed", slog.Any("error", err))
		}
	}()

	leafCache := pki.NewLeafCache(ca.Certificate, ca.PrivateKey)
	server = proxy.NewServer(cfg.ListenAddr, logger, leafCache)
	server.SetUpgrader(upg)
	server.SetHandshakeTimeout(cfg.HandshakeTimeout)
	server.SetMaxConnections(cfg.MaxConnections)
	server.SetReusePort(cfg.ReusePort)
	server.SetHTTP3Enabled(cfg.HTTP3Enabled)
	server.SetUpstreamPool(proxy.UpstreamPoolConfig{
		MaxIdlePerHost: cfg.UpstreamMaxIdlePerHost,
		IdleTimeout:    cfg.UpstreamIdleTimeout,
	})
	if err := applyRuntimeConfig(server, &cfg); err != nil {
		logger.Error("load rules failed", slog.Any("error", err))
		os.Exit(1)
	}
	server.PrewarmCertificates(cfg.MITMPrewarmHosts)
	server.SetUpstreamDialer(stealth.Dialer{
		Timeout: cfg.DialTimeout,
		Config: &utls.Config{
			InsecureSkipVerify: cfg.UpstreamInsecure,
		},
	})
	server.SetH2UpstreamDialer(stealth.Dialer{
		Timeout: cfg.DialTimeout,
		Config: &utls.Config{
			InsecureSkipVerify: cfg.UpstreamInsecure,
			NextProtos:         []string{"h2", "http/1.1"},
		},
	})
	startConfigReloader(ctx, os.Args[1:], &currentConfig, server, logger)
	if err := server.Serve(ctx); err != nil && err != context.Canceled {
		logger.Error("proxy server stopped", slog.Any("error", err))
		os.Exit(1)
	}
}

func applyRuntimeConfig(server *proxy.Server, cfg *appConfig) error {
	// loadRulePolicy mutates cfg with phrase lists discovered in
	// [rules].include_dir (bannedphraselist, exceptionphraselist,
	// weightedphraselist, weightedphraseexceptions). It must run before the
	// semantic filter is built so those lists actually feed the Aho-Corasick
	// automaton instead of being silently dropped.
	policyConfig, err := loadRulePolicy(cfg)
	if err != nil {
		return err
	}

	// weightedphraseexceptions excludes phrases from scoring at config
	// build time. This is a phrase-level exclusion, not an
	// e2guardian-style phrase combination filter.
	excluded := make(map[string]struct{}, len(cfg.SemanticWeightedExceptions))
	for _, p := range cfg.SemanticWeightedExceptions {
		excluded[normalizeWeightedKey(p.Phrase)] = struct{}{}
	}
	weighted := make([]proxy.WeightedPhrase, 0, len(cfg.SemanticWeighted))
	for _, phrase := range cfg.SemanticWeighted {
		if _, skip := excluded[normalizeWeightedKey(phrase.Phrase)]; skip {
			continue
		}
		weighted = append(weighted, proxy.WeightedPhrase{
			Phrase: phrase.Phrase,
			Weight: phrase.Weight,
		})
	}
	semantic, err := proxy.NewPhraseFilterWithExceptions(
		cfg.SemanticPhrases,
		weighted,
		cfg.SemanticExceptionPhrases,
		cfg.SemanticThreshold,
	)
	if err != nil {
		return err
	}
	masking, err := proxy.NewMaskingFilter(cfg.MaskingPhrases)
	if err != nil {
		return err
	}
	htmlInjection := proxy.NewHTMLInjectionFilter(cfg.HTMLBanner)
	magic := proxy.NewMagicFilter(cfg.MagicBlockedTypes)
	var antivirus *proxy.Antivirus
	if cfg.AntivirusEnabled {
		antivirus = proxy.NewAntivirus(
			proxy.NewClamAVScanner(cfg.AntivirusClamAV, cfg.AntivirusTimeout),
			cfg.AntivirusTempDir,
			cfg.AntivirusTrickle,
		)
	}

	subRules := make(map[string]string)
	for _, rule := range cfg.Substitutions {
		subRules[rule.Search] = rule.Replace
	}
	regexSubRules := make([]proxy.RegexSubstitutionRule, 0, len(cfg.RegexSubstitutions))
	for _, rule := range cfg.RegexSubstitutions {
		regexSubRules = append(regexSubRules, proxy.RegexSubstitutionRule{
			Pattern:        rule.Pattern,
			Replace:        rule.Replace,
			MaxWindowBytes: rule.MaxWindowBytes,
			Source:         rule.Source,
		})
	}
	substitution, err := proxy.NewSubstitutionFilterWithRegex(subRules, regexSubRules)
	if err != nil {
		return err
	}

	logPhrases, err := proxy.NewPhraseFilterWithExceptions(cfg.LogPhrases, nil, cfg.ExceptionLogPhrases, 0)
	if err != nil {
		return err
	}

	filter := proxy.NewContentFilter(semantic, masking, htmlInjection, magic, substitution, antivirus).WithLogSemantic(logPhrases)
	policy, err := proxy.NewPolicy(policyConfig)
	if err != nil {
		return err
	}

	server.SetWaitTimeout(cfg.WaitTimeout)
	server.SetCertWorkers(cfg.CertWorkers)
	server.SetMaxConnections(cfg.MaxConnections)
	server.SetMITMBypass(cfg.MITMBypassHosts)
	server.SetCircuitBreaker(cfg.CircuitBreakerEnabled, cfg.CircuitBreakerFailures, cfg.CircuitBreakerTimeout)
	server.SetDNSResolver(cfg.DNSCacheEnabled, cfg.DNSCacheTTL)
	server.SetUpstreamPool(proxy.UpstreamPoolConfig{
		MaxIdlePerHost: cfg.UpstreamMaxIdlePerHost,
		IdleTimeout:    cfg.UpstreamIdleTimeout,
	})
	server.SetRelayOptions(proxy.RelayOptions{
		LogBodies:                cfg.LogBodies,
		LogBodiesSampleRate:      cfg.LogBodiesSampleRate,
		MaxCaptureBytes:          cfg.MaxCaptureBytes,
		DumpDir:                  cfg.DumpDir,
		DumpOnPolicyHit:          cfg.DumpOnPolicyHit,
		DumpCredentialsCleartext: cfg.DumpCredentialsCleartext,
		AuditKey:                 cfg.AuditKey,
		DumpMaxSizeMB:            cfg.DumpMaxSizeMB,
		DumpMaxBackups:           cfg.DumpMaxBackups,
		DumpMinFreeSpaceMB:       cfg.DumpMinFreeSpaceMB,
		DumpCompress:             cfg.DumpCompress,
		IOTimeout:                cfg.IOTimeout,
		WSIdleTimeout:            cfg.WSIdleTimeout,
		Filter:                   filter,
		RequestFilter:            filter,
		Policy:                   policy,
	})
	server.SetPolicy(policy)
	accessProfiles := make([]proxy.AccessProfile, 0, len(cfg.AccessProfiles))
	for _, profile := range cfg.AccessProfiles {
		accessProfiles = append(accessProfiles, proxy.AccessProfile{
			Name:      profile.Name,
			Clients:   profile.Clients,
			Default:   profile.Default,
			MaxConns:  profile.MaxConns,
			RateLimit: profile.RateLimit,
			RateBurst: profile.RateBurst,
		})
	}
	accessRules, err := proxy.NewAccessRules(accessProfiles)
	if err != nil {
		return err
	}
	err = accessRules.SetBanned(cfg.BannedClients)
	if err != nil {
		return err
	}
	err = accessRules.SetExceptions(cfg.ExceptionClients)
	if err != nil {
		return err
	}
	server.SetAccessRules(accessRules)
	server.SetProfileMaxConnections(accessProfiles)
	server.ResetIPRateLimiter()
	scheduleWindows := make([]proxy.ScheduleWindow, 0, len(cfg.ScheduleWindows))
	for _, window := range cfg.ScheduleWindows {
		scheduleWindows = append(scheduleWindows, proxy.ScheduleWindow{
			Profile: window.Profile,
			Days:    window.Days,
			Start:   window.Start,
			End:     window.End,
		})
	}
	schedules, err := proxy.NewScheduleRules(scheduleWindows)
	if err != nil {
		return err
	}
	server.SetScheduleRules(schedules)
	return nil
}

func startConfigReloader(ctx context.Context, args []string, current *atomic.Value, server *proxy.Server, logger *slog.Logger) {
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	go func() {
		defer signal.Stop(hup)
		for {
			select {
			case <-ctx.Done():
				return
			case <-hup:
				atomic.StoreInt32(&isReloading, 1)
				cfg, err := parseConfig(args, os.Getenv, os.Stderr)
				if err != nil {
					logger.Error("reload config parse failed", slog.Any("error", err))
					atomic.StoreInt32(&isReloading, 0)
					continue
				}
				if err := applyRuntimeConfig(server, &cfg); err != nil {
					logger.Error("reload rules failed", slog.Any("error", err))
					atomic.StoreInt32(&isReloading, 0)
					continue
				}
				server.PrewarmCertificates(cfg.MITMPrewarmHosts)
				current.Store(&cfg)
				logConfig("reloaded config", &cfg, logger)
				if cfg.DumpCredentialsCleartext {
					logger.Warn("CRITICAL WARNING: dump_credentials_cleartext = true. Plaintext credentials (passwords, tokens, cookies) will be captured and written to disk. Ensure this is an authorized forensic environment!")
				}
				atomic.StoreInt32(&isReloading, 0)
			}
		}
	}()
}

func logConfig(prefix string, cfg *appConfig, logger *slog.Logger) {
	logger.Info(prefix,
		slog.String("path", cfg.ConfigPath),
		slog.String("listen", cfg.ListenAddr),
		slog.String("cert_dir", cfg.CertDir),
		slog.Int("max_connections", cfg.MaxConnections),
		slog.Duration("io_timeout", cfg.IOTimeout),
		slog.Duration("ws_idle_timeout", cfg.WSIdleTimeout),
		slog.Duration("dial_timeout", cfg.DialTimeout),
		slog.Int("upstream_max_idle_conns_per_host", cfg.UpstreamMaxIdlePerHost),
		slog.Duration("upstream_idle_timeout", cfg.UpstreamIdleTimeout),
		slog.Duration("handshake_timeout", cfg.HandshakeTimeout),
		slog.Int("mitm_prewarm_hosts_count", len(cfg.MITMPrewarmHosts)),
		slog.Bool("log_bodies", cfg.LogBodies),
		slog.Int64("max_capture_bytes", cfg.MaxCaptureBytes),
		slog.Bool("upstream_insecure_skip_verify", cfg.UpstreamInsecure),
		slog.String("dump_dir", cfg.DumpDir),
		slog.Bool("dump_on_policy_hit", cfg.DumpOnPolicyHit),
		slog.Bool("dump_credentials_cleartext", cfg.DumpCredentialsCleartext),
		slog.Bool("audit_key_configured", cfg.AuditKey != ""),
		slog.Int("dump_max_size_mb", cfg.DumpMaxSizeMB),
		slog.Int("dump_max_backups", cfg.DumpMaxBackups),
		slog.Int64("dump_min_free_space_mb", cfg.DumpMinFreeSpaceMB),
		slog.Bool("dump_compress", cfg.DumpCompress),
		slog.Bool("metrics_enabled", cfg.MetricsEnabled),
		slog.String("metrics_listen_addr", cfg.MetricsListenAddr),
		slog.Int("include_dirs_count", len(cfg.IncludeDirs)),
		slog.Int("access_profiles_count", len(cfg.AccessProfiles)),
		slog.Int("schedule_windows_count", len(cfg.ScheduleWindows)),
		slog.Int("semantic_phrases_count", len(cfg.SemanticPhrases)),
		slog.Int("semantic_weighted_count", len(cfg.SemanticWeighted)),
		slog.Int("semantic_exception_phrases_count", len(cfg.SemanticExceptionPhrases)),
		slog.Int("semantic_weighted_exceptions_count", len(cfg.SemanticWeightedExceptions)),
		slog.Int("semantic_threshold", cfg.SemanticThreshold),
		slog.Int("masking_phrases_count", len(cfg.MaskingPhrases)),
		slog.Int("substitution_rules_count", len(cfg.Substitutions)),
		slog.Int("regex_substitution_rules_count", len(cfg.RegexSubstitutions)),
		slog.Bool("html_banner", cfg.HTMLBanner != ""),
		slog.Bool("antivirus_enabled", cfg.AntivirusEnabled),
		slog.String("antivirus_clamav_addr", cfg.AntivirusClamAV),
		slog.Bool("circuit_breaker_enabled", cfg.CircuitBreakerEnabled),
		slog.Int("circuit_breaker_failures", cfg.CircuitBreakerFailures),
		slog.Duration("circuit_breaker_timeout", cfg.CircuitBreakerTimeout),
		slog.Bool("dns_cache_enabled", cfg.DNSCacheEnabled),
		slog.Duration("dns_cache_ttl", cfg.DNSCacheTTL),
	)
}
