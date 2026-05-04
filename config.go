package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"
	"time"

	"github.com/pelletier/go-toml/v2"
)

const version = "0.1.0"

type appConfig struct {
	ConfigPath        string
	ListenAddr        string
	CertDir           string
	MaxConnections    int
	IOTimeout         time.Duration
	DialTimeout       time.Duration
	HandshakeTimeout  time.Duration
	LogBodies         bool
	MaxCaptureBytes   int64
	UpstreamInsecure  bool
	DumpDir           string
	IncludeDirs       []string
	AccessProfiles    []AccessProfileConfig
	ScheduleWindows   []ScheduleWindowConfig
	SemanticPhrases   []string
	SemanticWeighted  []SemanticPhraseConfig
	SemanticThreshold int
	MaskingPhrases    []string
	HTMLBanner        string
	MagicBlockedTypes []string
	AntivirusEnabled  bool
	AntivirusClamAV   string
	AntivirusTempDir  string
	AntivirusTrickle  time.Duration
	AntivirusTimeout  time.Duration
	ShowVersion       bool
	Substitutions     []SubstitutionConfig
}

type SubstitutionConfig struct {
	Search  string
	Replace string
}

type AccessProfileConfig struct {
	Name    string
	Clients []string
	Default bool
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
		ConfigPath:       envString(getenv, "CONFIG", ""),
		ListenAddr:       "127.0.0.1:8080",
		CertDir:          "certs",
		MaxConnections:   1024,
		IOTimeout:        30 * time.Second,
		DialTimeout:      10 * time.Second,
		HandshakeTimeout: 5 * time.Second,
		LogBodies:        true,
		MaxCaptureBytes:  1 << 20,
		AntivirusTrickle: time.Second,
		AntivirusTimeout: 30 * time.Second,
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
	fs.DurationVar(&cfg.DialTimeout, "dial-timeout", cfg.DialTimeout, "upstream TCP/uTLS dial timeout")
	fs.DurationVar(&cfg.HandshakeTimeout, "handshake-timeout", cfg.HandshakeTimeout, "local TLS handshake timeout")
	fs.BoolVar(&cfg.LogBodies, "log-bodies", cfg.LogBodies, "capture request/response bodies for byte-count logging")
	fs.Int64Var(&cfg.MaxCaptureBytes, "max-capture-bytes", cfg.MaxCaptureBytes, "maximum bytes to capture per body; 0 disables body capture")
	fs.BoolVar(&cfg.UpstreamInsecure, "upstream-insecure-skip-verify", cfg.UpstreamInsecure, "skip upstream TLS certificate verification; lab/smoke only")
	fs.StringVar(&cfg.DumpDir, "dump-dir", cfg.DumpDir, "if non-empty, write decompressed cleartext request/response bodies as JSONL into this directory")
	fs.BoolVar(&cfg.ShowVersion, "version", false, "print version and exit")
	if err := fs.Parse(args); err != nil {
		return cfg, err
	}
	return cfg, cfg.validate()
}

type tomlConfig struct {
	Server struct {
		ListenAddr       string `toml:"listen_addr"`
		CertDir          string `toml:"cert_dir"`
		HandshakeTimeout string `toml:"handshake_timeout"`
		MaxConnections   *int   `toml:"max_connections"`
		IOTimeout        string `toml:"io_timeout"`
	} `toml:"server"`
	Upstream struct {
		DialTimeout        string `toml:"dial_timeout"`
		InsecureSkipVerify *bool  `toml:"insecure_skip_verify"`
	} `toml:"upstream"`
	Logging struct {
		LogBodies       *bool  `toml:"log_bodies"`
		MaxCaptureBytes *int64 `toml:"max_capture_bytes"`
		DumpDir         string `toml:"dump_dir"`
	} `toml:"logging"`
	Rules struct {
		IncludeDir []string `toml:"include_dir"`
	} `toml:"rules"`
	Access struct {
		Profiles []struct {
			Name    string   `toml:"name"`
			Clients []string `toml:"clients"`
			Default bool     `toml:"default"`
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
		BlockedPhrases []string `toml:"blocked_phrases"`
		ScoreThreshold *int     `toml:"score_threshold"`
		Weighted       []struct {
			Phrase string `toml:"phrase"`
			Weight int    `toml:"weight"`
		} `toml:"weighted_phrase"`
	} `toml:"semantic"`
	Masking struct {
		Phrases []string `toml:"phrases"`
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
		Rules []struct {
			Search  string `toml:"search"`
			Replace string `toml:"replace"`
		} `toml:"rule"`
	} `toml:"substitution"`
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
	if raw.Upstream.DialTimeout != "" {
		d, err := time.ParseDuration(raw.Upstream.DialTimeout)
		if err != nil {
			return fmt.Errorf("upstream.dial_timeout: %w", err)
		}
		cfg.DialTimeout = d
	}
	if raw.Upstream.InsecureSkipVerify != nil {
		cfg.UpstreamInsecure = *raw.Upstream.InsecureSkipVerify
	}
	if raw.Logging.LogBodies != nil {
		cfg.LogBodies = *raw.Logging.LogBodies
	}
	if raw.Logging.MaxCaptureBytes != nil {
		cfg.MaxCaptureBytes = *raw.Logging.MaxCaptureBytes
	}
	if raw.Logging.DumpDir != "" {
		cfg.DumpDir = raw.Logging.DumpDir
	}
	if len(raw.Rules.IncludeDir) > 0 {
		cfg.IncludeDirs = append(cfg.IncludeDirs[:0], raw.Rules.IncludeDir...)
	}
	if len(raw.Access.Profiles) > 0 {
		cfg.AccessProfiles = cfg.AccessProfiles[:0]
		for _, profile := range raw.Access.Profiles {
			cfg.AccessProfiles = append(cfg.AccessProfiles, AccessProfileConfig{
				Name:    profile.Name,
				Clients: append([]string(nil), profile.Clients...),
				Default: profile.Default,
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
	return nil
}

func applyEnv(cfg *appConfig, getenv func(string) string) {
	cfg.ListenAddr = envString(getenv, "LISTEN_ADDR", cfg.ListenAddr)
	cfg.CertDir = envString(getenv, "CERT_DIR", cfg.CertDir)
	cfg.MaxConnections = envInt(getenv, "MAX_CONNECTIONS", cfg.MaxConnections)
	cfg.IOTimeout = envDuration(getenv, "IO_TIMEOUT", cfg.IOTimeout)
	cfg.DialTimeout = envDuration(getenv, "DIAL_TIMEOUT", cfg.DialTimeout)
	cfg.HandshakeTimeout = envDuration(getenv, "HANDSHAKE_TIMEOUT", cfg.HandshakeTimeout)
	cfg.LogBodies = envBool(getenv, "LOG_BODIES", cfg.LogBodies)
	cfg.MaxCaptureBytes = envInt64(getenv, "MAX_CAPTURE_BYTES", cfg.MaxCaptureBytes)
	cfg.UpstreamInsecure = envBool(getenv, "UPSTREAM_INSECURE_SKIP_VERIFY", cfg.UpstreamInsecure)
	cfg.DumpDir = envString(getenv, "DUMP_DIR", cfg.DumpDir)
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
	if c.DialTimeout <= 0 {
		return fmt.Errorf("dial timeout must be positive")
	}
	if c.HandshakeTimeout <= 0 {
		return fmt.Errorf("handshake timeout must be positive")
	}
	if c.MaxCaptureBytes < 0 {
		return fmt.Errorf("max capture bytes cannot be negative")
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
