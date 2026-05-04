package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestParseConfigDefaults(t *testing.T) {
	t.Chdir(t.TempDir())
	cfg, err := parseConfig(nil, emptyEnv, &bytes.Buffer{})
	if err != nil {
		t.Fatalf("parseConfig() error = %v", err)
	}
	if cfg.ListenAddr != "127.0.0.1:8080" {
		t.Fatalf("ListenAddr = %q", cfg.ListenAddr)
	}
	if cfg.CertDir != "certs" {
		t.Fatalf("CertDir = %q", cfg.CertDir)
	}
	if cfg.MaxConnections != 1024 {
		t.Fatalf("MaxConnections = %d", cfg.MaxConnections)
	}
	if cfg.IOTimeout != 30*time.Second {
		t.Fatalf("IOTimeout = %s", cfg.IOTimeout)
	}
	if cfg.DialTimeout != 10*time.Second {
		t.Fatalf("DialTimeout = %s", cfg.DialTimeout)
	}
	if cfg.HandshakeTimeout != 5*time.Second {
		t.Fatalf("HandshakeTimeout = %s", cfg.HandshakeTimeout)
	}
	if !cfg.LogBodies {
		t.Fatal("LogBodies = false, want true")
	}
	if cfg.MaxCaptureBytes != 1<<20 {
		t.Fatalf("MaxCaptureBytes = %d", cfg.MaxCaptureBytes)
	}
	if cfg.UpstreamInsecure {
		t.Fatal("UpstreamInsecure = true, want false")
	}
}

func TestParseConfigEnvAndFlags(t *testing.T) {
	t.Chdir(t.TempDir())
	env := map[string]string{
		"CLEARGATE_LISTEN_ADDR":                   "127.0.0.1:9000",
		"CLEARGATE_CERT_DIR":                      "/tmp/ca",
		"CLEARGATE_MAX_CONNECTIONS":               "16",
		"CLEARGATE_IO_TIMEOUT":                    "11s",
		"CLEARGATE_DIAL_TIMEOUT":                  "3s",
		"CLEARGATE_HANDSHAKE_TIMEOUT":             "4s",
		"CLEARGATE_LOG_BODIES":                    "false",
		"CLEARGATE_MAX_CAPTURE_BYTES":             "128",
		"CLEARGATE_UPSTREAM_INSECURE_SKIP_VERIFY": "true",
	}
	cfg, err := parseConfig([]string{"--listen", "127.0.0.1:9999", "--max-capture-bytes", "256"}, func(key string) string {
		return env[key]
	}, &bytes.Buffer{})
	if err != nil {
		t.Fatalf("parseConfig() error = %v", err)
	}
	if cfg.ListenAddr != "127.0.0.1:9999" {
		t.Fatalf("ListenAddr = %q", cfg.ListenAddr)
	}
	if cfg.CertDir != "/tmp/ca" {
		t.Fatalf("CertDir = %q", cfg.CertDir)
	}
	if cfg.MaxConnections != 16 || cfg.IOTimeout != 11*time.Second {
		t.Fatalf("network = %d/%s", cfg.MaxConnections, cfg.IOTimeout)
	}
	if cfg.DialTimeout != 3*time.Second || cfg.HandshakeTimeout != 4*time.Second {
		t.Fatalf("timeouts = %s/%s", cfg.DialTimeout, cfg.HandshakeTimeout)
	}
	if cfg.LogBodies {
		t.Fatal("LogBodies = true, want false")
	}
	if cfg.MaxCaptureBytes != 256 {
		t.Fatalf("MaxCaptureBytes = %d", cfg.MaxCaptureBytes)
	}
	if !cfg.UpstreamInsecure {
		t.Fatal("UpstreamInsecure = false, want true")
	}
}

func TestParseConfigLoadsTOMLAndAllowsEnvAndFlagOverrides(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "lucidgate.toml")
	err := os.WriteFile(path, []byte(`
[server]
listen_addr = "127.0.0.1:7000"
cert_dir = "/var/lib/lucidgate/certs"
handshake_timeout = "7s"
max_connections = 32
io_timeout = "12s"

[upstream]
dial_timeout = "8s"
insecure_skip_verify = true

[logging]
log_bodies = false
max_capture_bytes = 4096
dump_dir = "/tmp/lucidgate-dumps"

[rules]
include_dir = ["rules.d", "profiles.d"]

[[access.profile]]
name = "students"
clients = ["192.0.2.0/24"]

[[access.profile]]
name = "default"
default = true
clients = ["127.0.0.1"]

[[schedule.window]]
profile = "students"
days = ["mon", "tue"]
start = "08:30"
end = "16:00"

[semantic]
blocked_phrases = ["malware kit", "credential dump"]
score_threshold = 100

[[semantic.weighted_phrase]]
phrase = "malware"
weight = 40

[[semantic.weighted_phrase]]
phrase = "credential dump"
weight = 70

[masking]
phrases = ["secret token", "api key"]

[injection]
html_banner = "<div>LucidGate</div>"

[magic]
blocked_types = ["executable/pe"]

[antivirus]
enabled = true
clamav_addr = "127.0.0.1:3310"
temp_dir = "/var/tmp/lucidgate-av"
trickle_interval = "2s"
scan_timeout = "15s"
`), 0o600)
	if err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	env := map[string]string{
		"LUCIDGATE_DIAL_TIMEOUT": "9s",
	}
	cfg, err := parseConfig([]string{"--config", path, "--listen", "127.0.0.1:7443"}, func(key string) string {
		return env[key]
	}, &bytes.Buffer{})
	if err != nil {
		t.Fatalf("parseConfig() error = %v", err)
	}
	if cfg.ConfigPath != path {
		t.Fatalf("ConfigPath = %q, want %q", cfg.ConfigPath, path)
	}
	if cfg.ListenAddr != "127.0.0.1:7443" {
		t.Fatalf("ListenAddr = %q", cfg.ListenAddr)
	}
	if cfg.CertDir != "/var/lib/lucidgate/certs" {
		t.Fatalf("CertDir = %q", cfg.CertDir)
	}
	if cfg.MaxConnections != 32 || cfg.IOTimeout != 12*time.Second {
		t.Fatalf("network = %d/%s", cfg.MaxConnections, cfg.IOTimeout)
	}
	if cfg.DialTimeout != 9*time.Second || cfg.HandshakeTimeout != 7*time.Second {
		t.Fatalf("timeouts = %s/%s", cfg.DialTimeout, cfg.HandshakeTimeout)
	}
	if cfg.LogBodies {
		t.Fatal("LogBodies = true, want false")
	}
	if cfg.MaxCaptureBytes != 4096 || cfg.DumpDir != "/tmp/lucidgate-dumps" {
		t.Fatalf("logging = %d/%q", cfg.MaxCaptureBytes, cfg.DumpDir)
	}
	if !cfg.UpstreamInsecure {
		t.Fatal("UpstreamInsecure = false, want true")
	}
	if len(cfg.IncludeDirs) != 2 || cfg.IncludeDirs[0] != "rules.d" || cfg.IncludeDirs[1] != "profiles.d" {
		t.Fatalf("IncludeDirs = %#v", cfg.IncludeDirs)
	}
	if len(cfg.AccessProfiles) != 2 {
		t.Fatalf("AccessProfiles = %#v, want 2 profiles", cfg.AccessProfiles)
	}
	if cfg.AccessProfiles[0].Name != "students" || cfg.AccessProfiles[0].Clients[0] != "192.0.2.0/24" {
		t.Fatalf("AccessProfiles[0] = %#v", cfg.AccessProfiles[0])
	}
	if !cfg.AccessProfiles[1].Default {
		t.Fatalf("AccessProfiles[1].Default = false, want true")
	}
	if len(cfg.ScheduleWindows) != 1 {
		t.Fatalf("ScheduleWindows = %#v, want 1 window", cfg.ScheduleWindows)
	}
	if cfg.ScheduleWindows[0].Profile != "students" || cfg.ScheduleWindows[0].Start != "08:30" || cfg.ScheduleWindows[0].End != "16:00" {
		t.Fatalf("ScheduleWindows[0] = %#v", cfg.ScheduleWindows[0])
	}
	if len(cfg.SemanticPhrases) != 2 || cfg.SemanticPhrases[0] != "malware kit" || cfg.SemanticPhrases[1] != "credential dump" {
		t.Fatalf("SemanticPhrases = %#v", cfg.SemanticPhrases)
	}
	if cfg.SemanticThreshold != 100 {
		t.Fatalf("SemanticThreshold = %d, want 100", cfg.SemanticThreshold)
	}
	if len(cfg.SemanticWeighted) != 2 || cfg.SemanticWeighted[0].Phrase != "malware" || cfg.SemanticWeighted[0].Weight != 40 || cfg.SemanticWeighted[1].Phrase != "credential dump" || cfg.SemanticWeighted[1].Weight != 70 {
		t.Fatalf("SemanticWeighted = %#v", cfg.SemanticWeighted)
	}
	if len(cfg.MaskingPhrases) != 2 || cfg.MaskingPhrases[0] != "secret token" || cfg.MaskingPhrases[1] != "api key" {
		t.Fatalf("MaskingPhrases = %#v", cfg.MaskingPhrases)
	}
	if cfg.HTMLBanner != "<div>LucidGate</div>" {
		t.Fatalf("HTMLBanner = %q", cfg.HTMLBanner)
	}
	if len(cfg.MagicBlockedTypes) != 1 || cfg.MagicBlockedTypes[0] != "executable/pe" {
		t.Fatalf("MagicBlockedTypes = %#v", cfg.MagicBlockedTypes)
	}
	if !cfg.AntivirusEnabled || cfg.AntivirusClamAV != "127.0.0.1:3310" || cfg.AntivirusTempDir != "/var/tmp/lucidgate-av" {
		t.Fatalf("antivirus config = enabled:%t clamav:%q temp:%q", cfg.AntivirusEnabled, cfg.AntivirusClamAV, cfg.AntivirusTempDir)
	}
	if cfg.AntivirusTrickle != 2*time.Second || cfg.AntivirusTimeout != 15*time.Second {
		t.Fatalf("antivirus durations = %s/%s", cfg.AntivirusTrickle, cfg.AntivirusTimeout)
	}
}

func TestParseConfigRejectsEnabledAntivirusWithoutClamAV(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "lucidgate.toml")
	err := os.WriteFile(path, []byte(`
[antivirus]
enabled = true
`), 0o600)
	if err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	_, err = parseConfig([]string{"--config", path}, emptyEnv, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "antivirus clamav_addr") {
		t.Fatalf("parseConfig() error = %v, want missing clamav_addr", err)
	}
}

func TestLoadRuleDomainsFromIncludeDirs(t *testing.T) {
	dir := t.TempDir()
	rulesDir := filepath.Join(dir, "rules.d")
	if err := os.Mkdir(rulesDir, 0o755); err != nil {
		t.Fatalf("Mkdir() error = %v", err)
	}
	err := os.WriteFile(filepath.Join(rulesDir, "blocked.txt"), []byte(`
# comments are ignored
Example.COM
.school.test.

`), 0o600)
	if err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	cfg := &appConfig{
		ConfigPath:  filepath.Join(dir, "lucidgate.toml"),
		IncludeDirs: []string{"rules.d"},
	}
	domains, err := loadRuleDomains(cfg)
	if err != nil {
		t.Fatalf("loadRuleDomains() error = %v", err)
	}
	want := []string{"example.com", "school.test"}
	if len(domains) != len(want) {
		t.Fatalf("domains = %#v, want %#v", domains, want)
	}
	for i := range want {
		if domains[i] != want[i] {
			t.Fatalf("domains = %#v, want %#v", domains, want)
		}
	}
}

func TestParseConfigRejectsInvalidValues(t *testing.T) {
	_, err := parseConfig([]string{"--max-capture-bytes", "-1"}, emptyEnv, &bytes.Buffer{})
	if err == nil {
		t.Fatal("parseConfig() error = nil, want validation error")
	}
}

func TestParseConfigRejectsInvalidSemanticScoring(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "lucidgate.toml")
	err := os.WriteFile(path, []byte(`
[semantic]
score_threshold = 0

[[semantic.weighted_phrase]]
phrase = "malware"
weight = 10
`), 0o600)
	if err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	_, err = parseConfig([]string{"--config", path}, emptyEnv, &bytes.Buffer{})
	if err == nil {
		t.Fatal("parseConfig() error = nil, want semantic threshold validation error")
	}

	path = filepath.Join(dir, "bad-weight.toml")
	err = os.WriteFile(path, []byte(`
[semantic]
score_threshold = 100

[[semantic.weighted_phrase]]
phrase = "malware"
weight = -1
`), 0o600)
	if err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	_, err = parseConfig([]string{"--config", path}, emptyEnv, &bytes.Buffer{})
	if err == nil {
		t.Fatal("parseConfig() error = nil, want semantic weight validation error")
	}
}

func emptyEnv(string) string {
	return ""
}
