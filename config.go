package main

import (
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/pelletier/go-toml/v2"

	"lucidgate/proxy"
)

const version = "0.1.0"

type appConfig struct {
	ConfigPath                   string
	ListenAddr                   string
	CertDir                      string
	MaxConnections               int
	IOTimeout                    time.Duration
	WSIdleTimeout                time.Duration
	DialTimeout                  time.Duration
	UpstreamMaxIdlePerHost       int
	UpstreamIdleTimeout          time.Duration
	HandshakeTimeout             time.Duration
	WaitTimeout                  time.Duration
	CertWorkers                  int
	MITMPrewarmHosts             []string
	LogBodies                    bool
	LogBodiesSampleRate          float64
	MaxCaptureBytes              int64
	UpstreamInsecure             bool
	DumpDir                      string
	DumpOnPolicyHit              bool
	DumpCredentialsCleartext     bool
	AuditKey                     string
	DumpMaxSizeMB                int
	DumpMaxBackups               int
	DumpMinFreeSpaceMB           int64
	DumpCompress                 bool
	MITMBypassHosts              []string
	IncludeDirs                  []string
	AccessProfiles               []AccessProfileConfig
	ScheduleWindows              []ScheduleWindowConfig
	SemanticPhrases              []string
	SemanticWeighted             []SemanticPhraseConfig
	SemanticThreshold            int
	SemanticBlockedPhraseLists   []string
	SemanticWeightedPhraseLists  []string
	SemanticExceptionPhraseLists []string
	SemanticExceptionPhrases     []string
	SemanticWeightedExceptions   []SemanticPhraseConfig
	MaskingPhrases               []string
	MaskingPhraseLists           []string
	HTMLBanner                   string
	MagicBlockedTypes            []string
	AntivirusEnabled             bool
	AntivirusClamAV              string
	AntivirusTempDir             string
	AntivirusTrickle             time.Duration
	AntivirusTimeout             time.Duration
	ShowVersion                  bool
	Substitutions                     []SubstitutionConfig
	SubstitutionRuleLists             []string
	RegexSubstitutions                []RegexSubstitutionConfig
	RegexSubstitutionRuleLists        []string
	RequestSubstitutions              []SubstitutionConfig
	RequestSubstitutionRuleLists      []string
	RegexRequestSubstitutions         []RegexSubstitutionConfig
	RegexRequestSubstitutionRuleLists []string
	NoCheckCertSites                  []string
	NoCheckCertSiteIPs                []string
	NoCheckCertSitesMatcher           *proxy.DomainMatcher
	NoCheckCertSiteIPsMatcher         *proxy.IPMatcher
	GreySSLSites                      []string
	GreySSLSiteIPs                    []string
	GreySSLSitesMatcher               *proxy.DomainMatcher
	GreySSLSiteIPsMatcher             *proxy.IPMatcher
	BannedClients                []string
	AccessLog                    string
	AlertLog                     string
	AlertCategories              []string
	ExceptionClients             []string
	FilterGroups                 []string
	IPGroupMappings              []IPGroupMapping
	LogPhrases                   []string
	ExceptionLogPhrases          []string
	MetricsEnabled               bool
	MetricsListenAddr            string
	ReusePort                    bool
	CircuitBreakerEnabled        bool
	CircuitBreakerFailures       int
	CircuitBreakerTimeout        time.Duration
	DNSCacheEnabled              bool
	DNSCacheTTL                  time.Duration
	HTTP3Enabled                 bool
	TracingEnabled               bool
	TracingEndpoint              string
	TracingInsecure              bool
	TracingServiceName           string
	TracingSampleRate            float64
}

type SubstitutionConfig struct {
	Search  string
	Replace string
}

type RegexSubstitutionConfig struct {
	Pattern        string
	Replace        string
	MaxWindowBytes int
	Source         string
}

type AccessProfileConfig struct {
	Name      string
	Clients   []string
	Default   bool
	MaxConns  *int
	RateLimit *float64
	RateBurst *int
}

type IPGroupMapping struct {
	Client string
	Group  string
	Source string
}

type ScheduleWindowConfig struct {
	Profile string
	Days    []string
	Start   string
	End     string
}

type SemanticPhraseConfig struct {
	Phrase string
	Weight int
}

func parseConfig(args []string, getenv func(string) string, output io.Writer) (appConfig, error) {
	cfg := appConfig{
		ConfigPath:             envString(getenv, "CONFIG", ""),
		ListenAddr:             "127.0.0.1:8080",
		CertDir:                "certs",
		MaxConnections:         1024,
		IOTimeout:              30 * time.Second,
		WSIdleTimeout:          5 * time.Minute,
		DialTimeout:            10 * time.Second,
		UpstreamMaxIdlePerHost: 32,
		UpstreamIdleTimeout:    90 * time.Second,
		HandshakeTimeout:       5 * time.Second,
		WaitTimeout:            250 * time.Millisecond,
		CertWorkers:            runtime.NumCPU(),
		LogBodies:              true,
		LogBodiesSampleRate:    1.0,
		MaxCaptureBytes:        1 << 20,
		DumpOnPolicyHit:        false,
		DumpMaxSizeMB:          100,
		DumpMaxBackups:         10,
		DumpMinFreeSpaceMB:     1024,
		DumpCompress:           true,
		AntivirusTrickle:       time.Second,
		AntivirusTimeout:       30 * time.Second,
		MetricsEnabled:         false,
		MetricsListenAddr:      "127.0.0.1:6060",
		ReusePort:              false,
		CircuitBreakerEnabled:  true,
		CircuitBreakerFailures: 5,
		CircuitBreakerTimeout:  30 * time.Second,
		DNSCacheEnabled:        true,
		DNSCacheTTL:            60 * time.Second,
		HTTP3Enabled:           false,
		TracingEnabled:         false,
		TracingEndpoint:        "localhost:4317",
		TracingInsecure:        true,
		TracingServiceName:     "lucidgate",
		TracingSampleRate:      1.0,
	}
	if path := configPathFromArgs(args); path != "" {
		cfg.ConfigPath = path
	}
	if cfg.ConfigPath == "" {
		if _, err := os.Stat("lucidgate.toml"); err == nil {
			cfg.ConfigPath = "lucidgate.toml"
		}
	}
	if cfg.ConfigPath != "" {
		if err := loadTOMLConfig(cfg.ConfigPath, &cfg); err != nil {
			return cfg, err
		}
	}
	applyEnv(&cfg, getenv)

	fs := flag.NewFlagSet("lucidgate", flag.ContinueOnError)
	fs.SetOutput(output)
	fs.StringVar(&cfg.ConfigPath, "config", cfg.ConfigPath, "path to lucidgate.toml")
	fs.StringVar(&cfg.ListenAddr, "listen", cfg.ListenAddr, "listen address for the local proxy")
	fs.StringVar(&cfg.CertDir, "cert-dir", cfg.CertDir, "directory for ca.crt and ca.key")
	fs.IntVar(&cfg.MaxConnections, "max-connections", cfg.MaxConnections, "maximum concurrent CONNECT tunnels")
	fs.DurationVar(&cfg.IOTimeout, "io-timeout", cfg.IOTimeout, "per-operation relay read/write timeout")
	fs.DurationVar(&cfg.WSIdleTimeout, "ws-idle-timeout", cfg.WSIdleTimeout, "per-direction idle timeout for raw WebSocket sessions after Upgrade")
	fs.DurationVar(&cfg.DialTimeout, "dial-timeout", cfg.DialTimeout, "upstream TCP/uTLS dial timeout")
	fs.IntVar(&cfg.UpstreamMaxIdlePerHost, "upstream-max-idle-conns-per-host", cfg.UpstreamMaxIdlePerHost, "maximum idle upstream keep-alive connections per destination; 0 disables pooling")
	fs.DurationVar(&cfg.UpstreamIdleTimeout, "upstream-idle-timeout", cfg.UpstreamIdleTimeout, "maximum time an idle upstream keep-alive connection stays pooled")
	fs.DurationVar(&cfg.HandshakeTimeout, "handshake-timeout", cfg.HandshakeTimeout, "local TLS handshake timeout")
	fs.DurationVar(&cfg.WaitTimeout, "wait-timeout", cfg.WaitTimeout, "connection admission queue wait timeout")
	fs.IntVar(&cfg.CertWorkers, "cert-workers", cfg.CertWorkers, "number of background certificate pre-generation workers")
	var mitmPrewarmHosts string
	fs.StringVar(&mitmPrewarmHosts, "mitm-prewarm-hosts", strings.Join(cfg.MITMPrewarmHosts, ","), "comma-separated popular hostnames to pre-generate MITM leaf certificates for")
	fs.BoolVar(&cfg.LogBodies, "log-bodies", cfg.LogBodies, "capture request/response bodies for byte-count logging")
	fs.Int64Var(&cfg.MaxCaptureBytes, "max-capture-bytes", cfg.MaxCaptureBytes, "maximum bytes to capture per body; 0 disables body capture")
	fs.BoolVar(&cfg.UpstreamInsecure, "upstream-insecure-skip-verify", cfg.UpstreamInsecure, "skip upstream TLS certificate verification; lab/smoke only")
	fs.StringVar(&cfg.DumpDir, "dump-dir", cfg.DumpDir, "if non-empty, write decompressed cleartext request/response bodies as JSONL into this directory")
	fs.BoolVar(&cfg.DumpOnPolicyHit, "dump-on-policy-hit", cfg.DumpOnPolicyHit, "if true, only write body dumps to dump-dir when a policy blocks or matches audit logs")
	fs.BoolVar(&cfg.DumpCredentialsCleartext, "dump-credentials-cleartext", cfg.DumpCredentialsCleartext, "if true, dump credentials in cleartext (dangerous, authorized environments only)")
	fs.StringVar(&cfg.AuditKey, "audit-key", cfg.AuditKey, "key used to HMAC credentials/secrets for forensic correlation")
	fs.IntVar(&cfg.DumpMaxSizeMB, "dump-max-size-mb", cfg.DumpMaxSizeMB, "maximum size in MB for a single dump file before rotation")
	fs.IntVar(&cfg.DumpMaxBackups, "dump-max-backups", cfg.DumpMaxBackups, "maximum number of rotated dump files to keep")
	fs.Int64Var(&cfg.DumpMinFreeSpaceMB, "dump-min-free-space-mb", cfg.DumpMinFreeSpaceMB, "minimum disk free space in MB before skipping payload dumps")
	fs.BoolVar(&cfg.DumpCompress, "dump-compress", cfg.DumpCompress, "compress rotated dump files using gzip")
	fs.BoolVar(&cfg.ReusePort, "reuseport", cfg.ReusePort, "enable SO_REUSEPORT with concurrent listeners (Linux/UNIX only)")
	fs.BoolVar(&cfg.CircuitBreakerEnabled, "circuit-breaker-enabled", cfg.CircuitBreakerEnabled, "enable upstream circuit breaker")
	fs.IntVar(&cfg.CircuitBreakerFailures, "circuit-breaker-failures", cfg.CircuitBreakerFailures, "number of consecutive failures to trip circuit breaker")
	fs.DurationVar(&cfg.CircuitBreakerTimeout, "circuit-breaker-timeout", cfg.CircuitBreakerTimeout, "duration to stay in open state before half-open transition")
	fs.BoolVar(&cfg.DNSCacheEnabled, "dns-cache-enabled", cfg.DNSCacheEnabled, "enable internal DNS caching resolver")
	fs.DurationVar(&cfg.DNSCacheTTL, "dns-cache-ttl", cfg.DNSCacheTTL, "TTL for internal DNS cached items")
	fs.BoolVar(&cfg.HTTP3Enabled, "http3-enabled", cfg.HTTP3Enabled, "enable concurrent HTTP/3 (QUIC) downstream listener on UDP port")
	fs.BoolVar(&cfg.TracingEnabled, "tracing-enabled", cfg.TracingEnabled, "enable OpenTelemetry tracing")
	fs.StringVar(&cfg.TracingEndpoint, "tracing-endpoint", cfg.TracingEndpoint, "OpenTelemetry OTLP collector endpoint (host:port)")
	fs.BoolVar(&cfg.TracingInsecure, "tracing-insecure", cfg.TracingInsecure, "enable insecure connection to OTLP collector")
	fs.StringVar(&cfg.TracingServiceName, "tracing-service-name", cfg.TracingServiceName, "OpenTelemetry service name")
	fs.Float64Var(&cfg.TracingSampleRate, "tracing-sample-rate", cfg.TracingSampleRate, "OpenTelemetry tracing sample rate (0.0 to 1.0)")
	fs.BoolVar(&cfg.ShowVersion, "version", false, "print version and exit")
	if err := fs.Parse(args); err != nil {
		return cfg, err
	}
	if fs.Lookup("mitm-prewarm-hosts").Value.String() != strings.Join(cfg.MITMPrewarmHosts, ",") {
		cfg.MITMPrewarmHosts = normalizeHostList(splitNonEmpty(mitmPrewarmHosts, ","))
	}
	return cfg, cfg.validate()
}

type tomlConfig struct {
	Server struct {
		ListenAddr             string `toml:"listen_addr"`
		CertDir                string `toml:"cert_dir"`
		HandshakeTimeout       string `toml:"handshake_timeout"`
		MaxConnections         *int   `toml:"max_connections"`
		IOTimeout              string `toml:"io_timeout"`
		WSIdleTimeout          string `toml:"ws_idle_timeout"`
		WaitTimeout            string `toml:"wait_timeout"`
		CertWorkers            *int   `toml:"cert_workers"`
		ReusePort              *bool  `toml:"reuseport"`
		CircuitBreakerEnabled  *bool  `toml:"circuit_breaker_enabled"`
		CircuitBreakerFailures *int   `toml:"circuit_breaker_failures"`
		CircuitBreakerTimeout  string `toml:"circuit_breaker_timeout"`
		DNSCacheEnabled        *bool  `toml:"dns_cache_enabled"`
		DNSCacheTTL            string `toml:"dns_cache_ttl"`
		HTTP3Enabled           *bool  `toml:"http3_enabled"`
	} `toml:"server"`
	Upstream struct {
		DialTimeout         string `toml:"dial_timeout"`
		MaxIdleConnsPerHost *int   `toml:"max_idle_conns_per_host"`
		IdleTimeout         string `toml:"idle_timeout"`
		InsecureSkipVerify  *bool  `toml:"insecure_skip_verify"`
	} `toml:"upstream"`
	MITM struct {
		PrewarmHosts []string `toml:"prewarm_hosts"`
		BypassHosts  []string `toml:"bypass_hosts"`
	} `toml:"mitm"`
	Logging struct {
		LogBodies                *bool    `toml:"log_bodies"`
		LogBodiesSampleRate      *float64 `toml:"log_bodies_sample_rate"`
		MaxCaptureBytes          *int64   `toml:"max_capture_bytes"`
		DumpDir                  string   `toml:"dump_dir"`
		DumpOnPolicyHit          *bool    `toml:"dump_on_policy_hit"`
		DumpCredentialsCleartext *bool    `toml:"dump_credentials_cleartext"`
		AuditKey                 *string  `toml:"audit_key"`
		DumpMaxSizeMB            *int     `toml:"dump_max_size_mb"`
		DumpMaxBackups           *int     `toml:"dump_max_backups"`
		DumpMinFreeSpaceMB       *int64   `toml:"dump_min_free_space_mb"`
		DumpCompress             *bool    `toml:"dump_compress"`
		AccessLog                string   `toml:"access_log"`
		AlertLog                 string   `toml:"alert_log"`
	} `toml:"logging"`
	Metrics struct {
		Enabled    *bool   `toml:"enabled"`
		ListenAddr *string `toml:"listen_addr"`
	} `toml:"metrics"`
	Rules struct {
		IncludeDir []string `toml:"include_dir"`
	} `toml:"rules"`
	Access struct {
		Profiles []struct {
			Name      string   `toml:"name"`
			Clients   []string `toml:"clients"`
			Default   bool     `toml:"default"`
			MaxConns  *int     `toml:"max_conns"`
			RateLimit *float64 `toml:"rate_limit"`
			RateBurst *int     `toml:"rate_burst"`
		} `toml:"profile"`
	} `toml:"access"`
	Schedule struct {
		Windows []struct {
			Profile string   `toml:"profile"`
			Days    []string `toml:"days"`
			Start   string   `toml:"start"`
			End     string   `toml:"end"`
		} `toml:"window"`
	} `toml:"schedule"`
	Semantic struct {
		BlockedPhrases       []string `toml:"blocked_phrases"`
		BlockedPhraseLists   []string `toml:"blocked_phrase_lists"`
		WeightedPhraseLists  []string `toml:"weighted_phrase_lists"`
		ExceptionPhraseLists []string `toml:"exception_phrase_lists"`
		ScoreThreshold       *int     `toml:"score_threshold"`
		Weighted             []struct {
			Phrase string `toml:"phrase"`
			Weight int    `toml:"weight"`
		} `toml:"weighted_phrase"`
	} `toml:"semantic"`
	Masking struct {
		Phrases     []string `toml:"phrases"`
		PhraseLists []string `toml:"phrase_lists"`
	} `toml:"masking"`
	Injection struct {
		HTMLBanner string `toml:"html_banner"`
	} `toml:"injection"`
	Magic struct {
		BlockedTypes []string `toml:"blocked_types"`
	} `toml:"magic"`
	Antivirus struct {
		Enabled         *bool  `toml:"enabled"`
		ClamAVAddr      string `toml:"clamav_addr"`
		TempDir         string `toml:"temp_dir"`
		TrickleInterval string `toml:"trickle_interval"`
		ScanTimeout     string `toml:"scan_timeout"`
	} `toml:"antivirus"`
	Substitution struct {
		RuleLists      []string `toml:"rule_lists"`
		RegexRuleLists []string `toml:"regex_rule_lists"`
		Rules          []struct {
			Search  string `toml:"search"`
			Replace string `toml:"replace"`
		} `toml:"rule"`
		RegexRules []struct {
			Pattern        string `toml:"pattern"`
			Replace        string `toml:"replace"`
			MaxWindowBytes int    `toml:"max_window_bytes"`
		} `toml:"regex_rule"`
	} `toml:"substitution"`
	RequestSubstitution struct {
		RuleLists      []string `toml:"rule_lists"`
		RegexRuleLists []string `toml:"regex_rule_lists"`
		Rules          []struct {
			Search  string `toml:"search"`
			Replace string `toml:"replace"`
		} `toml:"rule"`
		RegexRules []struct {
			Pattern        string `toml:"pattern"`
			Replace        string `toml:"replace"`
			MaxWindowBytes int    `toml:"max_window_bytes"`
		} `toml:"regex_rule"`
	} `toml:"request_substitution"`
	Tracing struct {
		Enabled     *bool    `toml:"enabled"`
		Endpoint    *string  `toml:"endpoint"`
		Insecure    *bool    `toml:"insecure"`
		ServiceName *string  `toml:"service_name"`
		SampleRate  *float64 `toml:"sample_rate"`
	} `toml:"tracing"`
}

func loadTOMLConfig(path string, cfg *appConfig) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read config %s: %w", path, err)
	}
	var raw tomlConfig
	if err := toml.Unmarshal(data, &raw); err != nil {
		return fmt.Errorf("parse config %s: %w", path, err)
	}
	if raw.Server.ListenAddr != "" {
		cfg.ListenAddr = raw.Server.ListenAddr
	}
	if raw.Server.CertDir != "" {
		cfg.CertDir = raw.Server.CertDir
	}
	if raw.Server.HandshakeTimeout != "" {
		d, err := time.ParseDuration(raw.Server.HandshakeTimeout)
		if err != nil {
			return fmt.Errorf("server.handshake_timeout: %w", err)
		}
		cfg.HandshakeTimeout = d
	}
	if raw.Server.MaxConnections != nil {
		cfg.MaxConnections = *raw.Server.MaxConnections
	}
	if raw.Server.IOTimeout != "" {
		d, err := time.ParseDuration(raw.Server.IOTimeout)
		if err != nil {
			return fmt.Errorf("server.io_timeout: %w", err)
		}
		cfg.IOTimeout = d
	}
	if raw.Server.WSIdleTimeout != "" {
		d, err := time.ParseDuration(raw.Server.WSIdleTimeout)
		if err != nil {
			return fmt.Errorf("server.ws_idle_timeout: %w", err)
		}
		cfg.WSIdleTimeout = d
	}
	if raw.Server.WaitTimeout != "" {
		d, err := time.ParseDuration(raw.Server.WaitTimeout)
		if err != nil {
			return fmt.Errorf("server.wait_timeout: %w", err)
		}
		cfg.WaitTimeout = d
	}
	if raw.Server.CertWorkers != nil {
		cfg.CertWorkers = *raw.Server.CertWorkers
	}
	if raw.Server.ReusePort != nil {
		cfg.ReusePort = *raw.Server.ReusePort
	}
	if raw.Server.CircuitBreakerEnabled != nil {
		cfg.CircuitBreakerEnabled = *raw.Server.CircuitBreakerEnabled
	}
	if raw.Server.HTTP3Enabled != nil {
		cfg.HTTP3Enabled = *raw.Server.HTTP3Enabled
	}
	if raw.Server.CircuitBreakerFailures != nil {
		cfg.CircuitBreakerFailures = *raw.Server.CircuitBreakerFailures
	}
	if raw.Server.CircuitBreakerTimeout != "" {
		d, err := time.ParseDuration(raw.Server.CircuitBreakerTimeout)
		if err != nil {
			return fmt.Errorf("server.circuit_breaker_timeout: %w", err)
		}
		cfg.CircuitBreakerTimeout = d
	}
	if raw.Server.DNSCacheEnabled != nil {
		cfg.DNSCacheEnabled = *raw.Server.DNSCacheEnabled
	}
	if raw.Server.DNSCacheTTL != "" {
		d, err := time.ParseDuration(raw.Server.DNSCacheTTL)
		if err != nil {
			return fmt.Errorf("server.dns_cache_ttl: %w", err)
		}
		cfg.DNSCacheTTL = d
	}
	if raw.Upstream.DialTimeout != "" {
		d, err := time.ParseDuration(raw.Upstream.DialTimeout)
		if err != nil {
			return fmt.Errorf("upstream.dial_timeout: %w", err)
		}
		cfg.DialTimeout = d
	}
	if raw.Upstream.MaxIdleConnsPerHost != nil {
		cfg.UpstreamMaxIdlePerHost = *raw.Upstream.MaxIdleConnsPerHost
	}
	if raw.Upstream.IdleTimeout != "" {
		d, err := time.ParseDuration(raw.Upstream.IdleTimeout)
		if err != nil {
			return fmt.Errorf("upstream.idle_timeout: %w", err)
		}
		cfg.UpstreamIdleTimeout = d
	}
	if raw.Upstream.InsecureSkipVerify != nil {
		cfg.UpstreamInsecure = *raw.Upstream.InsecureSkipVerify
	}
	if len(raw.MITM.PrewarmHosts) > 0 {
		cfg.MITMPrewarmHosts = normalizeHostList(raw.MITM.PrewarmHosts)
	}
	if len(raw.MITM.BypassHosts) > 0 {
		cfg.MITMBypassHosts = normalizeHostList(raw.MITM.BypassHosts)
	}
	if raw.Metrics.Enabled != nil {
		cfg.MetricsEnabled = *raw.Metrics.Enabled
	}
	if raw.Metrics.ListenAddr != nil {
		cfg.MetricsListenAddr = *raw.Metrics.ListenAddr
	}
	if raw.Logging.LogBodies != nil {
		cfg.LogBodies = *raw.Logging.LogBodies
	}
	if raw.Logging.LogBodiesSampleRate != nil {
		cfg.LogBodiesSampleRate = *raw.Logging.LogBodiesSampleRate
	}
	if raw.Logging.MaxCaptureBytes != nil {
		cfg.MaxCaptureBytes = *raw.Logging.MaxCaptureBytes
	}
	if raw.Logging.DumpDir != "" {
		cfg.DumpDir = raw.Logging.DumpDir
	}
	if raw.Logging.DumpOnPolicyHit != nil {
		cfg.DumpOnPolicyHit = *raw.Logging.DumpOnPolicyHit
	}
	if raw.Logging.DumpCredentialsCleartext != nil {
		cfg.DumpCredentialsCleartext = *raw.Logging.DumpCredentialsCleartext
	}
	if raw.Logging.AuditKey != nil {
		cfg.AuditKey = *raw.Logging.AuditKey
	}
	if raw.Logging.DumpMaxSizeMB != nil {
		cfg.DumpMaxSizeMB = *raw.Logging.DumpMaxSizeMB
	}
	if raw.Logging.DumpMaxBackups != nil {
		cfg.DumpMaxBackups = *raw.Logging.DumpMaxBackups
	}
	if raw.Logging.DumpMinFreeSpaceMB != nil {
		cfg.DumpMinFreeSpaceMB = *raw.Logging.DumpMinFreeSpaceMB
	}
	if raw.Logging.DumpCompress != nil {
		cfg.DumpCompress = *raw.Logging.DumpCompress
	}
	if raw.Logging.AccessLog != "" {
		cfg.AccessLog = raw.Logging.AccessLog
	}
	if raw.Logging.AlertLog != "" {
		cfg.AlertLog = raw.Logging.AlertLog
	}
	if len(raw.Rules.IncludeDir) > 0 {
		cfg.IncludeDirs = append(cfg.IncludeDirs[:0], raw.Rules.IncludeDir...)
	}
	if len(raw.Access.Profiles) > 0 {
		cfg.AccessProfiles = cfg.AccessProfiles[:0]
		for _, profile := range raw.Access.Profiles {
			cfg.AccessProfiles = append(cfg.AccessProfiles, AccessProfileConfig{
				Name:      profile.Name,
				Clients:   append([]string(nil), profile.Clients...),
				Default:   profile.Default,
				MaxConns:  profile.MaxConns,
				RateLimit: profile.RateLimit,
				RateBurst: profile.RateBurst,
			})
		}
	}
	if len(raw.Schedule.Windows) > 0 {
		cfg.ScheduleWindows = cfg.ScheduleWindows[:0]
		for _, window := range raw.Schedule.Windows {
			cfg.ScheduleWindows = append(cfg.ScheduleWindows, ScheduleWindowConfig{
				Profile: window.Profile,
				Days:    append([]string(nil), window.Days...),
				Start:   window.Start,
				End:     window.End,
			})
		}
	}
	if len(raw.Semantic.BlockedPhrases) > 0 {
		cfg.SemanticPhrases = append(cfg.SemanticPhrases[:0], raw.Semantic.BlockedPhrases...)
	}
	if raw.Semantic.ScoreThreshold != nil {
		cfg.SemanticThreshold = *raw.Semantic.ScoreThreshold
	}
	if len(raw.Semantic.Weighted) > 0 {
		cfg.SemanticWeighted = cfg.SemanticWeighted[:0]
		for _, phrase := range raw.Semantic.Weighted {
			cfg.SemanticWeighted = append(cfg.SemanticWeighted, SemanticPhraseConfig{
				Phrase: phrase.Phrase,
				Weight: phrase.Weight,
			})
		}
	}
	if len(raw.Masking.Phrases) > 0 {
		cfg.MaskingPhrases = append(cfg.MaskingPhrases[:0], raw.Masking.Phrases...)
	}
	if raw.Injection.HTMLBanner != "" {
		cfg.HTMLBanner = raw.Injection.HTMLBanner
	}
	if len(raw.Magic.BlockedTypes) > 0 {
		cfg.MagicBlockedTypes = append(cfg.MagicBlockedTypes[:0], raw.Magic.BlockedTypes...)
	}
	if raw.Antivirus.Enabled != nil {
		cfg.AntivirusEnabled = *raw.Antivirus.Enabled
	}
	if raw.Antivirus.ClamAVAddr != "" {
		cfg.AntivirusClamAV = raw.Antivirus.ClamAVAddr
	}
	if raw.Antivirus.TempDir != "" {
		cfg.AntivirusTempDir = raw.Antivirus.TempDir
	}
	if raw.Antivirus.TrickleInterval != "" {
		d, err := time.ParseDuration(raw.Antivirus.TrickleInterval)
		if err != nil {
			return fmt.Errorf("antivirus.trickle_interval: %w", err)
		}
		cfg.AntivirusTrickle = d
	}
	if raw.Antivirus.ScanTimeout != "" {
		d, err := time.ParseDuration(raw.Antivirus.ScanTimeout)
		if err != nil {
			return fmt.Errorf("antivirus.scan_timeout: %w", err)
		}
		cfg.AntivirusTimeout = d
	}
	if len(raw.Substitution.Rules) > 0 {
		cfg.Substitutions = cfg.Substitutions[:0]
		for _, rule := range raw.Substitution.Rules {
			cfg.Substitutions = append(cfg.Substitutions, SubstitutionConfig{
				Search:  rule.Search,
				Replace: rule.Replace,
			})
		}
	}
	if len(raw.Substitution.RegexRules) > 0 {
		cfg.RegexSubstitutions = cfg.RegexSubstitutions[:0]
		for _, rule := range raw.Substitution.RegexRules {
			cfg.RegexSubstitutions = append(cfg.RegexSubstitutions, RegexSubstitutionConfig{
				Pattern:        rule.Pattern,
				Replace:        rule.Replace,
				MaxWindowBytes: rule.MaxWindowBytes,
			})
		}
	}
	if len(raw.RequestSubstitution.Rules) > 0 {
		cfg.RequestSubstitutions = cfg.RequestSubstitutions[:0]
		for _, rule := range raw.RequestSubstitution.Rules {
			cfg.RequestSubstitutions = append(cfg.RequestSubstitutions, SubstitutionConfig{
				Search:  rule.Search,
				Replace: rule.Replace,
			})
		}
	}
	if len(raw.RequestSubstitution.RegexRules) > 0 {
		cfg.RegexRequestSubstitutions = cfg.RegexRequestSubstitutions[:0]
		for _, rule := range raw.RequestSubstitution.RegexRules {
			cfg.RegexRequestSubstitutions = append(cfg.RegexRequestSubstitutions, RegexSubstitutionConfig{
				Pattern:        rule.Pattern,
				Replace:        rule.Replace,
				MaxWindowBytes: rule.MaxWindowBytes,
			})
		}
	}
	if len(raw.Semantic.BlockedPhraseLists) > 0 {
		cfg.SemanticBlockedPhraseLists = append(cfg.SemanticBlockedPhraseLists[:0], raw.Semantic.BlockedPhraseLists...)
	}
	if len(raw.Semantic.WeightedPhraseLists) > 0 {
		cfg.SemanticWeightedPhraseLists = append(cfg.SemanticWeightedPhraseLists[:0], raw.Semantic.WeightedPhraseLists...)
	}
	if len(raw.Semantic.ExceptionPhraseLists) > 0 {
		cfg.SemanticExceptionPhraseLists = append(cfg.SemanticExceptionPhraseLists[:0], raw.Semantic.ExceptionPhraseLists...)
	}
	if len(raw.Masking.PhraseLists) > 0 {
		cfg.MaskingPhraseLists = append(cfg.MaskingPhraseLists[:0], raw.Masking.PhraseLists...)
	}
	if len(raw.Substitution.RuleLists) > 0 {
		cfg.SubstitutionRuleLists = append(cfg.SubstitutionRuleLists[:0], raw.Substitution.RuleLists...)
	}
	if len(raw.Substitution.RegexRuleLists) > 0 {
		cfg.RegexSubstitutionRuleLists = append(cfg.RegexSubstitutionRuleLists[:0], raw.Substitution.RegexRuleLists...)
	}
	if len(raw.RequestSubstitution.RuleLists) > 0 {
		cfg.RequestSubstitutionRuleLists = append(cfg.RequestSubstitutionRuleLists[:0], raw.RequestSubstitution.RuleLists...)
	}
	if len(raw.RequestSubstitution.RegexRuleLists) > 0 {
		cfg.RegexRequestSubstitutionRuleLists = append(cfg.RegexRequestSubstitutionRuleLists[:0], raw.RequestSubstitution.RegexRuleLists...)
	}

	if raw.Tracing.Enabled != nil {
		cfg.TracingEnabled = *raw.Tracing.Enabled
	}
	if raw.Tracing.Endpoint != nil {
		cfg.TracingEndpoint = *raw.Tracing.Endpoint
	}
	if raw.Tracing.Insecure != nil {
		cfg.TracingInsecure = *raw.Tracing.Insecure
	}
	if raw.Tracing.ServiceName != nil {
		cfg.TracingServiceName = *raw.Tracing.ServiceName
	}
	if raw.Tracing.SampleRate != nil {
		cfg.TracingSampleRate = *raw.Tracing.SampleRate
	}

	configDir := filepath.Dir(path)
	if extra, err := loadTextListFiles(configDir, cfg.SemanticBlockedPhraseLists); err != nil {
		return err
	} else {
		cfg.SemanticPhrases = appendUniqueStrings(cfg.SemanticPhrases, extra)
	}
	if extra, err := loadTextListFiles(configDir, cfg.SemanticExceptionPhraseLists); err != nil {
		return err
	} else {
		cfg.SemanticExceptionPhrases = appendUniqueStrings(cfg.SemanticExceptionPhrases, extra)
	}
	if extra, err := loadTextListFiles(configDir, cfg.MaskingPhraseLists); err != nil {
		return err
	} else {
		cfg.MaskingPhrases = appendUniqueStrings(cfg.MaskingPhrases, extra)
	}
	if extra, err := loadWeightedPhraseFiles(configDir, cfg.SemanticWeightedPhraseLists); err != nil {
		return err
	} else {
		merged, err := mergeWeightedPhrases(cfg.SemanticWeighted, extra)
		if err != nil {
			return err
		}
		cfg.SemanticWeighted = merged
	}
	if extra, err := loadSubstitutionFiles(configDir, cfg.SubstitutionRuleLists); err != nil {
		return err
	} else {
		merged, err := mergeSubstitutions(cfg.Substitutions, extra)
		if err != nil {
			return err
		}
		cfg.Substitutions = merged
	}
	if extra, err := loadRegexSubstitutionFiles(configDir, cfg.RegexSubstitutionRuleLists); err != nil {
		return err
	} else {
		merged, err := mergeRegexSubstitutions(cfg.RegexSubstitutions, extra)
		if err != nil {
			return err
		}
		cfg.RegexSubstitutions = merged
	}
	if extra, err := loadSubstitutionFiles(configDir, cfg.RequestSubstitutionRuleLists); err != nil {
		return err
	} else {
		merged, err := mergeSubstitutions(cfg.RequestSubstitutions, extra)
		if err != nil {
			return err
		}
		cfg.RequestSubstitutions = merged
	}
	if extra, err := loadRegexSubstitutionFiles(configDir, cfg.RegexRequestSubstitutionRuleLists); err != nil {
		return err
	} else {
		merged, err := mergeRegexSubstitutions(cfg.RegexRequestSubstitutions, extra)
		if err != nil {
			return err
		}
		cfg.RegexRequestSubstitutions = merged
	}
	return nil
}

func applyEnv(cfg *appConfig, getenv func(string) string) {
	cfg.ListenAddr = envString(getenv, "LISTEN_ADDR", cfg.ListenAddr)
	cfg.CertDir = envString(getenv, "CERT_DIR", cfg.CertDir)
	cfg.MaxConnections = envInt(getenv, "MAX_CONNECTIONS", cfg.MaxConnections)
	cfg.IOTimeout = envDuration(getenv, "IO_TIMEOUT", cfg.IOTimeout)
	cfg.WSIdleTimeout = envDuration(getenv, "WS_IDLE_TIMEOUT", cfg.WSIdleTimeout)
	cfg.DialTimeout = envDuration(getenv, "DIAL_TIMEOUT", cfg.DialTimeout)
	cfg.UpstreamMaxIdlePerHost = envInt(getenv, "UPSTREAM_MAX_IDLE_CONNS_PER_HOST", cfg.UpstreamMaxIdlePerHost)
	cfg.UpstreamIdleTimeout = envDuration(getenv, "UPSTREAM_IDLE_TIMEOUT", cfg.UpstreamIdleTimeout)
	cfg.HandshakeTimeout = envDuration(getenv, "HANDSHAKE_TIMEOUT", cfg.HandshakeTimeout)
	cfg.WaitTimeout = envDuration(getenv, "WAIT_TIMEOUT", cfg.WaitTimeout)
	cfg.CertWorkers = envInt(getenv, "CERT_WORKERS", cfg.CertWorkers)
	if raw := envString(getenv, "MITM_PREWARM_HOSTS", ""); raw != "" {
		cfg.MITMPrewarmHosts = normalizeHostList(splitNonEmpty(raw, ","))
	}
	if raw := envString(getenv, "MITM_BYPASS_HOSTS", ""); raw != "" {
		cfg.MITMBypassHosts = normalizeHostList(splitNonEmpty(raw, ","))
	}
	cfg.LogBodies = envBool(getenv, "LOG_BODIES", cfg.LogBodies)
	cfg.LogBodiesSampleRate = envFloat(getenv, "LOG_BODIES_SAMPLE_RATE", cfg.LogBodiesSampleRate)
	cfg.MaxCaptureBytes = envInt64(getenv, "MAX_CAPTURE_BYTES", cfg.MaxCaptureBytes)
	cfg.UpstreamInsecure = envBool(getenv, "UPSTREAM_INSECURE_SKIP_VERIFY", cfg.UpstreamInsecure)
	cfg.DumpDir = envString(getenv, "DUMP_DIR", cfg.DumpDir)
	cfg.DumpOnPolicyHit = envBool(getenv, "DUMP_ON_POLICY_HIT", cfg.DumpOnPolicyHit)
	cfg.DumpCredentialsCleartext = envBool(getenv, "DUMP_CREDENTIALS_CLEARTEXT", cfg.DumpCredentialsCleartext)
	cfg.AuditKey = envString(getenv, "AUDIT_KEY", cfg.AuditKey)
	cfg.DumpMaxSizeMB = envInt(getenv, "DUMP_MAX_SIZE_MB", cfg.DumpMaxSizeMB)
	cfg.DumpMaxBackups = envInt(getenv, "DUMP_MAX_BACKUPS", cfg.DumpMaxBackups)
	cfg.DumpMinFreeSpaceMB = envInt64(getenv, "DUMP_MIN_FREE_SPACE_MB", cfg.DumpMinFreeSpaceMB)
	cfg.DumpCompress = envBool(getenv, "DUMP_COMPRESS", cfg.DumpCompress)
	cfg.MetricsEnabled = envBool(getenv, "METRICS_ENABLED", cfg.MetricsEnabled)
	cfg.MetricsListenAddr = envString(getenv, "METRICS_LISTEN_ADDR", cfg.MetricsListenAddr)
	cfg.ReusePort = envBool(getenv, "REUSEPORT", cfg.ReusePort)
	cfg.CircuitBreakerEnabled = envBool(getenv, "CIRCUIT_BREAKER_ENABLED", cfg.CircuitBreakerEnabled)
	cfg.CircuitBreakerFailures = envInt(getenv, "CIRCUIT_BREAKER_FAILURES", cfg.CircuitBreakerFailures)
	cfg.CircuitBreakerTimeout = envDuration(getenv, "CIRCUIT_BREAKER_TIMEOUT", cfg.CircuitBreakerTimeout)
	cfg.DNSCacheEnabled = envBool(getenv, "DNS_CACHE_ENABLED", cfg.DNSCacheEnabled)
	cfg.DNSCacheTTL = envDuration(getenv, "DNS_CACHE_TTL", cfg.DNSCacheTTL)
	cfg.HTTP3Enabled = envBool(getenv, "HTTP3_ENABLED", cfg.HTTP3Enabled)
	cfg.TracingEnabled = envBool(getenv, "TRACING_ENABLED", cfg.TracingEnabled)
	cfg.TracingEndpoint = envString(getenv, "TRACING_ENDPOINT", cfg.TracingEndpoint)
	cfg.TracingInsecure = envBool(getenv, "TRACING_INSECURE", cfg.TracingInsecure)
	cfg.TracingServiceName = envString(getenv, "TRACING_SERVICE_NAME", cfg.TracingServiceName)
	cfg.TracingSampleRate = envFloat(getenv, "TRACING_SAMPLE_RATE", cfg.TracingSampleRate)
	cfg.AntivirusEnabled = envBool(getenv, "ANTIVIRUS_ENABLED", cfg.AntivirusEnabled)
	cfg.AntivirusClamAV = envString(getenv, "ANTIVIRUS_CLAMAV_ADDR", cfg.AntivirusClamAV)
	cfg.AntivirusTempDir = envString(getenv, "ANTIVIRUS_TEMP_DIR", cfg.AntivirusTempDir)
	cfg.AntivirusTrickle = envDuration(getenv, "ANTIVIRUS_TRICKLE_INTERVAL", cfg.AntivirusTrickle)
	cfg.AntivirusTimeout = envDuration(getenv, "ANTIVIRUS_SCAN_TIMEOUT", cfg.AntivirusTimeout)
}

func (c appConfig) validate() error {
	if c.ListenAddr == "" {
		return fmt.Errorf("listen address cannot be empty")
	}
	if c.CertDir == "" {
		return fmt.Errorf("cert dir cannot be empty")
	}
	if c.MaxConnections <= 0 {
		return fmt.Errorf("max connections must be positive")
	}
	if c.IOTimeout <= 0 {
		return fmt.Errorf("io timeout must be positive")
	}
	if c.WSIdleTimeout <= 0 {
		return fmt.Errorf("ws idle timeout must be positive")
	}
	if c.DialTimeout <= 0 {
		return fmt.Errorf("dial timeout must be positive")
	}
	if c.UpstreamMaxIdlePerHost < 0 {
		return fmt.Errorf("upstream max idle conns per host cannot be negative")
	}
	if c.UpstreamMaxIdlePerHost > 0 && c.UpstreamIdleTimeout <= 0 {
		return fmt.Errorf("upstream idle timeout must be positive when upstream pooling is enabled")
	}
	if c.HandshakeTimeout <= 0 {
		return fmt.Errorf("handshake timeout must be positive")
	}
	if c.WaitTimeout < 0 {
		return fmt.Errorf("wait timeout cannot be negative")
	}
	if c.CertWorkers < 0 {
		return fmt.Errorf("cert workers cannot be negative")
	}
	if c.MaxCaptureBytes < 0 {
		return fmt.Errorf("max capture bytes cannot be negative")
	}
	if c.DumpCredentialsCleartext && !c.DumpOnPolicyHit {
		return fmt.Errorf("dump_credentials_cleartext=true requires dump_on_policy_hit=true")
	}
	if c.DumpMaxSizeMB <= 0 {
		return fmt.Errorf("dump max size must be positive")
	}
	if c.DumpMaxBackups < 0 {
		return fmt.Errorf("dump max backups cannot be negative")
	}
	if c.DumpMinFreeSpaceMB < 0 {
		return fmt.Errorf("dump min free space cannot be negative")
	}
	if c.MetricsEnabled && c.MetricsListenAddr == "" {
		return fmt.Errorf("metrics listen address cannot be empty when metrics are enabled")
	}
	if c.SemanticThreshold < 0 {
		return fmt.Errorf("semantic score threshold cannot be negative")
	}
	if c.AntivirusEnabled && c.AntivirusClamAV == "" {
		return fmt.Errorf("antivirus clamav_addr cannot be empty when antivirus is enabled")
	}
	if c.AntivirusTrickle < 0 {
		return fmt.Errorf("antivirus trickle interval cannot be negative")
	}
	if c.AntivirusTimeout <= 0 {
		return fmt.Errorf("antivirus scan timeout must be positive")
	}
	for _, phrase := range c.SemanticWeighted {
		if phrase.Phrase == "" {
			return fmt.Errorf("semantic weighted phrase cannot be empty")
		}
		if phrase.Weight <= 0 {
			return fmt.Errorf("semantic weighted phrase %q weight must be positive", phrase.Phrase)
		}
	}
	if len(c.SemanticWeighted) > 0 && c.SemanticThreshold <= 0 {
		return fmt.Errorf("semantic score threshold must be positive when weighted phrases are configured")
	}
	for _, profile := range c.AccessProfiles {
		if profile.MaxConns != nil && *profile.MaxConns <= 0 {
			return fmt.Errorf("access profile %q max_conns must be positive", profile.Name)
		}
		if profile.RateLimit != nil && *profile.RateLimit <= 0 {
			return fmt.Errorf("access profile %q rate_limit must be positive", profile.Name)
		}
		if profile.RateBurst != nil && *profile.RateBurst <= 0 {
			return fmt.Errorf("access profile %q rate_burst must be positive", profile.Name)
		}
		if (profile.RateLimit != nil && profile.RateBurst == nil) || (profile.RateLimit == nil && profile.RateBurst != nil) {
			return fmt.Errorf("access profile %q: both rate_limit and rate_burst must be configured together", profile.Name)
		}
	}
	return nil
}

func envString(getenv func(string) string, key string, fallback string) string {
	if value := getenv("LUCIDGATE_" + key); value != "" {
		return value
	}
	if value := getenv("CLEARGATE_" + key); value != "" {
		return value
	}
	return fallback
}

func envBool(getenv func(string) string, key string, fallback bool) bool {
	value := getenv("LUCIDGATE_" + key)
	if value == "" {
		value = getenv("CLEARGATE_" + key)
	}
	if value == "" {
		return fallback
	}
	parsed, err := strconv.ParseBool(value)
	if err != nil {
		return fallback
	}
	return parsed
}

func envInt64(getenv func(string) string, key string, fallback int64) int64 {
	value := getenv("LUCIDGATE_" + key)
	if value == "" {
		value = getenv("CLEARGATE_" + key)
	}
	if value == "" {
		return fallback
	}
	parsed, err := strconv.ParseInt(value, 10, 64)
	if err != nil {
		return fallback
	}
	return parsed
}

func envInt(getenv func(string) string, key string, fallback int) int {
	value := getenv("LUCIDGATE_" + key)
	if value == "" {
		value = getenv("CLEARGATE_" + key)
	}
	if value == "" {
		return fallback
	}
	parsed, err := strconv.Atoi(value)
	if err != nil {
		return fallback
	}
	return parsed
}

func envDuration(getenv func(string) string, key string, fallback time.Duration) time.Duration {
	value := getenv("LUCIDGATE_" + key)
	if value == "" {
		value = getenv("CLEARGATE_" + key)
	}
	if value == "" {
		return fallback
	}
	parsed, err := time.ParseDuration(value)
	if err != nil {
		return fallback
	}
	return parsed
}

func envFloat(getenv func(string) string, key string, fallback float64) float64 {
	value := getenv("LUCIDGATE_" + key)
	if value == "" {
		value = getenv("CLEARGATE_" + key)
	}
	if value == "" {
		return fallback
	}
	parsed, err := strconv.ParseFloat(value, 64)
	if err != nil {
		return fallback
	}
	return parsed
}

func splitNonEmpty(raw, sep string) []string {
	out := []string{}
	for _, item := range strings.Split(raw, sep) {
		item = strings.TrimSpace(item)
		if item != "" {
			out = append(out, item)
		}
	}
	return out
}

func normalizeHostList(hosts []string) []string {
	out := make([]string, 0, len(hosts))
	seen := make(map[string]struct{}, len(hosts))
	for _, raw := range hosts {
		host := normalizePrewarmHost(raw)
		if host == "" {
			continue
		}
		if _, ok := seen[host]; ok {
			continue
		}
		seen[host] = struct{}{}
		out = append(out, host)
	}
	return out
}

func normalizePrewarmHost(raw string) string {
	host := strings.TrimSpace(raw)
	host = strings.TrimPrefix(host, "http://")
	host = strings.TrimPrefix(host, "https://")
	if i := strings.IndexByte(host, '/'); i >= 0 {
		host = host[:i]
	}
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	host = strings.Trim(host, "[] \t\r\n.")
	return strings.ToLower(host)
}

func configPathFromArgs(args []string) string {
	for i, arg := range args {
		if arg == "--config" && i+1 < len(args) {
			return args[i+1]
		}
		const prefix = "--config="
		if len(arg) > len(prefix) && arg[:len(prefix)] == prefix {
			return arg[len(prefix):]
		}
	}
	return ""
}
