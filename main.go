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

	_ "go.uber.org/automaxprocs"
	utls "github.com/refraction-networking/utls"

	"lucidgate/pki"
	"lucidgate/proxy"
	"lucidgate/stealth"
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

	go func() {
		logger.Info("pprof server listening", slog.String("addr", "127.0.0.1:6060"))
		if err := http.ListenAndServe("127.0.0.1:6060", nil); err != nil {
			logger.Error("pprof server failed", slog.Any("error", err))
		}
	}()

	var currentConfig atomic.Value
	currentConfig.Store(&cfg)

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

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	leafCache := pki.NewLeafCache(ca.Certificate, ca.PrivateKey)
	server := proxy.NewServer(cfg.ListenAddr, logger, leafCache)
	server.SetHandshakeTimeout(cfg.HandshakeTimeout)
	server.SetMaxConnections(cfg.MaxConnections)
	if err := applyRuntimeConfig(server, &cfg); err != nil {
		logger.Error("load rules failed", slog.Any("error", err))
		os.Exit(1)
	}
	server.SetUpstreamDialer(stealth.Dialer{
		Timeout: cfg.DialTimeout,
		Config: &utls.Config{
			InsecureSkipVerify: cfg.UpstreamInsecure,
		},
	})
	startConfigReloader(ctx, os.Args[1:], &currentConfig, server, logger)
	if err := server.Serve(ctx); err != nil && err != context.Canceled {
		logger.Error("proxy server stopped", slog.Any("error", err))
		os.Exit(1)
	}
}

func applyRuntimeConfig(server *proxy.Server, cfg *appConfig) error {
	weighted := make([]proxy.WeightedPhrase, 0, len(cfg.SemanticWeighted))
	for _, phrase := range cfg.SemanticWeighted {
		weighted = append(weighted, proxy.WeightedPhrase{
			Phrase: phrase.Phrase,
			Weight: phrase.Weight,
		})
	}
	semantic, err := proxy.NewScoredPhraseFilter(cfg.SemanticPhrases, weighted, cfg.SemanticThreshold)
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
	substitution := proxy.NewSubstitutionFilter(subRules)

	filter := proxy.NewContentFilter(semantic, masking, htmlInjection, magic, substitution, antivirus)

	server.SetMaxConnections(cfg.MaxConnections)
	server.SetRelayOptions(proxy.RelayOptions{
		LogBodies:       cfg.LogBodies,
		MaxCaptureBytes: cfg.MaxCaptureBytes,
		DumpDir:         cfg.DumpDir,
		IOTimeout:       cfg.IOTimeout,
		Filter:          filter,
		RequestFilter:   filter,
	})
	domains, err := loadRuleDomains(cfg)
	if err != nil {
		return err
	}
	server.SetDomainRules(proxy.NewDomainRules(domains))
	accessProfiles := make([]proxy.AccessProfile, 0, len(cfg.AccessProfiles))
	for _, profile := range cfg.AccessProfiles {
		accessProfiles = append(accessProfiles, proxy.AccessProfile{
			Name:    profile.Name,
			Clients: profile.Clients,
			Default: profile.Default,
		})
	}
	accessRules, err := proxy.NewAccessRules(accessProfiles)
	if err != nil {
		return err
	}
	server.SetAccessRules(accessRules)
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

func startConfigReloader(ctx context.Context, args[]string, current *atomic.Value, server *proxy.Server, logger *slog.Logger) {
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	go func() {
		defer signal.Stop(hup)
		for {
			select {
			case <-ctx.Done():
				return
			case <-hup:
				cfg, err := parseConfig(args, os.Getenv, os.Stderr)
				if err != nil {
					logger.Error("reload config parse failed", slog.Any("error", err))
					continue
				}
				if err := applyRuntimeConfig(server, &cfg); err != nil {
					logger.Error("reload rules failed", slog.Any("error", err))
					continue
				}
				current.Store(&cfg)
				logConfig("reloaded config", &cfg, logger)
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
		slog.Duration("dial_timeout", cfg.DialTimeout),
		slog.Duration("handshake_timeout", cfg.HandshakeTimeout),
		slog.Bool("log_bodies", cfg.LogBodies),
		slog.Int64("max_capture_bytes", cfg.MaxCaptureBytes),
		slog.Bool("upstream_insecure_skip_verify", cfg.UpstreamInsecure),
		slog.String("dump_dir", cfg.DumpDir),
		slog.Int("include_dirs_count", len(cfg.IncludeDirs)),
		slog.Int("access_profiles_count", len(cfg.AccessProfiles)),
		slog.Int("schedule_windows_count", len(cfg.ScheduleWindows)),
		slog.Int("semantic_phrases_count", len(cfg.SemanticPhrases)),
		slog.Int("semantic_weighted_count", len(cfg.SemanticWeighted)),
		slog.Int("semantic_threshold", cfg.SemanticThreshold),
		slog.Int("masking_phrases_count", len(cfg.MaskingPhrases)),
		slog.Int("substitution_rules_count", len(cfg.Substitutions)),
		slog.Bool("html_banner", cfg.HTMLBanner != ""),
		slog.Bool("antivirus_enabled", cfg.AntivirusEnabled),
		slog.String("antivirus_clamav_addr", cfg.AntivirusClamAV),
	)
}
