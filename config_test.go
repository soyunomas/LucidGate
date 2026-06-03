package main

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"lucidgate/proxy"
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
	if cfg.WSIdleTimeout != 5*time.Minute {
		t.Fatalf("WSIdleTimeout = %s", cfg.WSIdleTimeout)
	}
	if cfg.DialTimeout != 10*time.Second {
		t.Fatalf("DialTimeout = %s", cfg.DialTimeout)
	}
	if cfg.UpstreamMaxIdlePerHost != 32 || cfg.UpstreamIdleTimeout != 90*time.Second {
		t.Fatalf("upstream pool = %d/%s", cfg.UpstreamMaxIdlePerHost, cfg.UpstreamIdleTimeout)
	}
	if cfg.HandshakeTimeout != 5*time.Second {
		t.Fatalf("HandshakeTimeout = %s", cfg.HandshakeTimeout)
	}
	if cfg.WaitTimeout != 250*time.Millisecond {
		t.Fatalf("WaitTimeout = %s", cfg.WaitTimeout)
	}
	if cfg.CertWorkers != runtime.NumCPU() {
		t.Fatalf("CertWorkers = %d", cfg.CertWorkers)
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
	if cfg.ReusePort {
		t.Fatal("ReusePort = true, want false")
	}
}

func TestParseConfigEnvAndFlags(t *testing.T) {
	t.Chdir(t.TempDir())
	env := map[string]string{
		"CLEARGATE_LISTEN_ADDR":                      "127.0.0.1:9000",
		"CLEARGATE_CERT_DIR":                         "/tmp/ca",
		"CLEARGATE_MAX_CONNECTIONS":                  "16",
		"CLEARGATE_IO_TIMEOUT":                       "11s",
		"LUCIDGATE_WS_IDLE_TIMEOUT":                  "2m",
		"CLEARGATE_DIAL_TIMEOUT":                     "3s",
		"CLEARGATE_UPSTREAM_MAX_IDLE_CONNS_PER_HOST": "12",
		"CLEARGATE_UPSTREAM_IDLE_TIMEOUT":            "45s",
		"CLEARGATE_HANDSHAKE_TIMEOUT":                "4s",
		"CLEARGATE_WAIT_TIMEOUT":                     "500ms",
		"CLEARGATE_CERT_WORKERS":                     "8",
		"CLEARGATE_LOG_BODIES":                       "false",
		"CLEARGATE_MAX_CAPTURE_BYTES":                "128",
		"CLEARGATE_UPSTREAM_INSECURE_SKIP_VERIFY":    "true",
		"CLEARGATE_METRICS_ENABLED":                  "true",
		"CLEARGATE_METRICS_LISTEN_ADDR":              "127.0.0.1:9100",
		"LUCIDGATE_REUSEPORT":                        "true",
	}
	cfg, err := parseConfig([]string{"--listen", "127.0.0.1:9999", "--max-capture-bytes", "256", "--wait-timeout", "400ms", "--cert-workers", "6", "--ws-idle-timeout", "90s", "--mitm-prewarm-hosts", "Flagged.Example:443, https://Other.test/path"}, func(key string) string {
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
	if cfg.WSIdleTimeout != 90*time.Second {
		t.Fatalf("WSIdleTimeout = %s", cfg.WSIdleTimeout)
	}
	if cfg.DialTimeout != 3*time.Second || cfg.HandshakeTimeout != 4*time.Second {
		t.Fatalf("timeouts = %s/%s", cfg.DialTimeout, cfg.HandshakeTimeout)
	}
	if cfg.UpstreamMaxIdlePerHost != 12 || cfg.UpstreamIdleTimeout != 45*time.Second {
		t.Fatalf("upstream pool = %d/%s", cfg.UpstreamMaxIdlePerHost, cfg.UpstreamIdleTimeout)
	}
	if cfg.WaitTimeout != 400*time.Millisecond {
		t.Fatalf("WaitTimeout = %s", cfg.WaitTimeout)
	}
	if cfg.CertWorkers != 6 {
		t.Fatalf("CertWorkers = %d, want 6", cfg.CertWorkers)
	}
	if got, want := strings.Join(cfg.MITMPrewarmHosts, ","), "flagged.example,other.test"; got != want {
		t.Fatalf("MITMPrewarmHosts = %q, want %q", got, want)
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
	if !cfg.MetricsEnabled || cfg.MetricsListenAddr != "127.0.0.1:9100" {
		t.Fatalf("metrics = enabled:%t addr:%q", cfg.MetricsEnabled, cfg.MetricsListenAddr)
	}
	if !cfg.ReusePort {
		t.Fatal("ReusePort = false, want true")
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
ws_idle_timeout = "3m"

[upstream]
dial_timeout = "8s"
max_idle_conns_per_host = 24
idle_timeout = "75s"
insecure_skip_verify = true

[mitm]
prewarm_hosts = ["WWW.Google.COM:443", "https://www.gstatic.com/generate_204", "www.google.com"]

[logging]
log_bodies = false
max_capture_bytes = 4096
dump_dir = "/tmp/lucidgate-dumps"

[metrics]
enabled = true
listen_addr = "127.0.0.1:6061"

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
		"LUCIDGATE_DIAL_TIMEOUT":    "9s",
		"LUCIDGATE_WS_IDLE_TIMEOUT": "4m",
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
	if cfg.WSIdleTimeout != 4*time.Minute {
		t.Fatalf("WSIdleTimeout = %s", cfg.WSIdleTimeout)
	}
	if cfg.DialTimeout != 9*time.Second || cfg.HandshakeTimeout != 7*time.Second {
		t.Fatalf("timeouts = %s/%s", cfg.DialTimeout, cfg.HandshakeTimeout)
	}
	if cfg.UpstreamMaxIdlePerHost != 24 || cfg.UpstreamIdleTimeout != 75*time.Second {
		t.Fatalf("upstream pool = %d/%s", cfg.UpstreamMaxIdlePerHost, cfg.UpstreamIdleTimeout)
	}
	if got, want := strings.Join(cfg.MITMPrewarmHosts, ","), "www.google.com,www.gstatic.com"; got != want {
		t.Fatalf("MITMPrewarmHosts = %q, want %q", got, want)
	}
	if cfg.LogBodies {
		t.Fatal("LogBodies = true, want false")
	}
	if cfg.MaxCaptureBytes != 4096 || cfg.DumpDir != "/tmp/lucidgate-dumps" {
		t.Fatalf("logging = %d/%q", cfg.MaxCaptureBytes, cfg.DumpDir)
	}
	if !cfg.MetricsEnabled || cfg.MetricsListenAddr != "127.0.0.1:6061" {
		t.Fatalf("metrics = enabled:%t addr:%q", cfg.MetricsEnabled, cfg.MetricsListenAddr)
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

func TestParseConfigRejectsEnabledMetricsWithoutListenAddr(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "lucidgate.toml")
	err := os.WriteFile(path, []byte(`
[metrics]
enabled = true
listen_addr = ""
`), 0o600)
	if err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	_, err = parseConfig([]string{"--config", path}, emptyEnv, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "metrics listen address") {
		t.Fatalf("parseConfig() error = %v, want missing metrics listen address", err)
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

func TestLoadRulePolicyRecognizesE2GuardianSiteAndURLLists(t *testing.T) {
	dir := t.TempDir()
	listsDir := filepath.Join(dir, "lists")
	writeFile(t, filepath.Join(listsDir, "bannedsitelist"), "blocked.test\nlegacy-block.test\n")
	writeFile(t, filepath.Join(listsDir, "exceptionsitelist"), "allowed.blocked.test\n")
	writeFile(t, filepath.Join(listsDir, "localexceptionsitelist"), "local-exempt.test\n")
	writeFile(t, filepath.Join(listsDir, "localgreysitelist"), "local-grey.test\n")
	writeFile(t, filepath.Join(listsDir, "localbannedsitelist"), "local-blocked.test\n")
	writeFile(t, filepath.Join(listsDir, "greysitelist"), "grey-site.test\n")
	writeFile(t, filepath.Join(listsDir, "bannedregexpsitelist"), `(^|\.)regex-blocked\.test$`+"\n")
	writeFile(t, filepath.Join(listsDir, "exceptionregexpsitelist"), `^allowed\.regex-blocked\.test$`+"\n")
	writeFile(t, filepath.Join(listsDir, "refererexceptionsitelist"), "trusted-ref.test\n")
	writeFile(t, filepath.Join(listsDir, "bannedsiteiplist"), "203.0.113.0/24\n")
	writeFile(t, filepath.Join(listsDir, "exceptionsiteiplist"), "203.0.113.42\n")
	writeFile(t, filepath.Join(listsDir, "refererexceptionsiteiplist"), "198.51.100.42\n")
	writeFile(t, filepath.Join(listsDir, "greysiteiplist"), "198.51.100.0/24\n")
	writeFile(t, filepath.Join(listsDir, "localbannedsiteiplist"), "192.0.2.0/24\n")
	writeFile(t, filepath.Join(listsDir, "localexceptionsiteiplist"), "192.0.2.42\n")
	writeFile(t, filepath.Join(listsDir, "localgreysiteiplist"), "2001:db8:ffff::/48\n")
	writeFile(t, filepath.Join(listsDir, "bannedurllist"), "http://example.test/private\n")
	writeFile(t, filepath.Join(listsDir, "exceptionurllist"), "http://example.test/private/allowed\n")
	writeFile(t, filepath.Join(listsDir, "refererexceptionurllist"), "https://partner-ref.test/allowed\n")
	writeFile(t, filepath.Join(listsDir, "localexceptionurllist"), "http://example.test/local-exempt\n")
	writeFile(t, filepath.Join(listsDir, "localgreyurllist"), "http://example.test/local-grey\n")
	writeFile(t, filepath.Join(listsDir, "localbannedurllist"), "http://example.test/local-blocked\n")
	writeFile(t, filepath.Join(listsDir, "greyurllist"), "http://example.test/grey\n")
	writeFile(t, filepath.Join(listsDir, "bannedregexpurllist"), `/blocked-by-regex($|\?)`+"\n")
	writeFile(t, filepath.Join(listsDir, "exceptionregexpurllist"), `/blocked-by-regex\?token=ok$`+"\n")
	writeFile(t, filepath.Join(listsDir, "urlregexplist"), `^https://example\.com/old/(.*) => https://example.com/new/$1`+"\n")
	writeFile(t, filepath.Join(listsDir, "urlredirectregexplist"), `^https://example\.com/redirect/google\?q=(.*) => https://www.google.com/search?q=$1`+"\n")
	writeFile(t, filepath.Join(listsDir, "bannedextensionlist"), ".exe\nzip\n")
	writeFile(t, filepath.Join(listsDir, "exceptionextensionlist"), ".ok\n")
	writeFile(t, filepath.Join(listsDir, "bannedmimetypelist"), "application/x-msdownload\n")
	writeFile(t, filepath.Join(listsDir, "exceptionmimetypelist"), "application/signed-exchange\n")
	writeFile(t, filepath.Join(listsDir, "bannedfilenamelist"), "secret.bin\n")
	writeFile(t, filepath.Join(listsDir, "exceptionfilenamelist"), "allowed.zip\n")
	writeFile(t, filepath.Join(listsDir, "bannedheaderlist"), "x-tracker: blocked\n")
	writeFile(t, filepath.Join(listsDir, "exceptionheaderlist"), "x-tracker: allowed\n")
	writeFile(t, filepath.Join(listsDir, "bannedregexpheaderlist"), `(?i)^X-Device: blocked-[0-9]+$`+"\n")
	writeFile(t, filepath.Join(listsDir, "exceptionregexpheaderlist"), `(?i)^X-Device: blocked-42$`+"\n")
	writeFile(t, filepath.Join(listsDir, "headerregexplist"), `^(?i)User-Agent:.*Chrome.* => User-Agent: Mozilla/5.0 (Stealth)`+"\n")
	writeFile(t, filepath.Join(listsDir, "addheaderregexplist"), `^https://example\.com/secure => X-Secure-Add: yes`+"\n")
	writeFile(t, filepath.Join(listsDir, "responseheaderregexplist"), `^(?i)Server:.*Apache.* => Server: LucidGate`+"\n")
	writeFile(t, filepath.Join(listsDir, "bannedcookiephraselist"), "trackid=\n")
	writeFile(t, filepath.Join(listsDir, "exceptioncookiephraselist"), "trackid=allowed\n")
	writeFile(t, filepath.Join(listsDir, "custom-legacy-domains"), "legacy.test\n")

	cfg := &appConfig{
		ConfigPath:  filepath.Join(dir, "lucidgate.toml"),
		IncludeDirs: []string{"lists"},
	}
	policyConfig, err := loadRulePolicy(cfg)
	if err != nil {
		t.Fatalf("loadRulePolicy() error = %v", err)
	}
	policy, err := proxy.NewPolicy(policyConfig)
	if err != nil {
		t.Fatalf("NewPolicy() error = %v", err)
	}
	checkReq := func(target string) *http.Request {
		req := httptest.NewRequest(http.MethodGet, target, nil)
		req.RemoteAddr = "127.0.0.1:50000"
		return req
	}
	if decision := policy.Evaluate("sub.blocked.test", nil, "http"); !decision.Blocked {
		t.Fatalf("blocked domain decision = %#v, want blocked", decision)
	}
	if decision := policy.Evaluate("allowed.blocked.test", nil, "http"); decision.Blocked {
		t.Fatalf("exception domain decision = %#v, want allowed", decision)
	}
	if decision := policy.Evaluate("www.regex-blocked.test", nil, "http"); !decision.Blocked {
		t.Fatalf("regex domain decision = %#v, want blocked", decision)
	}
	if decision := policy.Evaluate("allowed.regex-blocked.test", nil, "http"); decision.Blocked {
		t.Fatalf("regex exception domain decision = %#v, want allowed", decision)
	}
	if decision := policy.Evaluate("legacy.test", nil, "http"); !decision.Blocked {
		t.Fatalf("legacy domain decision = %#v, want blocked", decision)
	}
	if decision := policy.Evaluate("203.0.113.7", nil, "http"); !decision.Blocked || decision.MatchType != "site_ip" {
		t.Fatalf("site IP decision = %#v, want blocked", decision)
	}
	if decision := policy.Evaluate("203.0.113.42", nil, "http"); decision.Blocked {
		t.Fatalf("site IP exception decision = %#v, want allowed", decision)
	}
	if decision := policy.Evaluate("192.0.2.7", nil, "http"); !decision.Blocked || decision.MatchType != "site_ip" {
		t.Fatalf("local site IP decision = %#v, want blocked", decision)
	}
	if decision := policy.Evaluate("192.0.2.42", nil, "http"); decision.Blocked {
		t.Fatalf("local site IP exception decision = %#v, want allowed", decision)
	}
	if got, want := policyConfig.SiteIPs.Grey, []string{"198.51.100.0/24", "2001:db8:ffff::/48"}; !equalStrings(got, want) {
		t.Fatalf("SiteIPs.Grey = %#v, want %#v", got, want)
	}
	if got, want := policyConfig.Domains.LocalExceptions, []string{"local-exempt.test"}; !equalStrings(got, want) {
		t.Fatalf("Domains.LocalExceptions = %#v, want %#v", got, want)
	}
	if got, want := policyConfig.Domains.LocalGrey, []string{"local-grey.test"}; !equalStrings(got, want) {
		t.Fatalf("Domains.LocalGrey = %#v, want %#v", got, want)
	}
	if got, want := policyConfig.Domains.LocalBlocked, []string{"local-blocked.test"}; !equalStrings(got, want) {
		t.Fatalf("Domains.LocalBlocked = %#v, want %#v", got, want)
	}
	if got, want := policyConfig.Domains.Grey, []string{"grey-site.test"}; !equalStrings(got, want) {
		t.Fatalf("Domains.Grey = %#v, want %#v", got, want)
	}
	if got, want := policyConfig.URLs.LocalExceptions, []string{"http://example.test/local-exempt"}; !equalStrings(got, want) {
		t.Fatalf("URLs.LocalExceptions = %#v, want %#v", got, want)
	}
	if got, want := policyConfig.URLs.LocalGrey, []string{"http://example.test/local-grey"}; !equalStrings(got, want) {
		t.Fatalf("URLs.LocalGrey = %#v, want %#v", got, want)
	}
	if got, want := policyConfig.URLs.LocalBlocked, []string{"http://example.test/local-blocked"}; !equalStrings(got, want) {
		t.Fatalf("URLs.LocalBlocked = %#v, want %#v", got, want)
	}
	if got, want := policyConfig.URLs.Grey, []string{"http://example.test/grey"}; !equalStrings(got, want) {
		t.Fatalf("URLs.Grey = %#v, want %#v", got, want)
	}
	if got, want := policyConfig.Referer.ExceptionSites, []string{"trusted-ref.test"}; !equalStrings(got, want) {
		t.Fatalf("Referer.ExceptionSites = %#v, want %#v", got, want)
	}
	if got, want := policyConfig.Referer.ExceptionSiteIPs, []string{"198.51.100.42"}; !equalStrings(got, want) {
		t.Fatalf("Referer.ExceptionSiteIPs = %#v, want %#v", got, want)
	}
	if got, want := policyConfig.Referer.ExceptionURLs, []string{"https://partner-ref.test/allowed"}; !equalStrings(got, want) {
		t.Fatalf("Referer.ExceptionURLs = %#v, want %#v", got, want)
	}
	if got, want := policyConfig.URLs.Rewrites, []proxy.RegexRule{{Pattern: `^https://example\.com/old/(.*) => https://example.com/new/$1`, Source: filepath.Join(listsDir, "urlregexplist") + ":1"}}; len(got) != 1 || got[0].Pattern != want[0].Pattern {
		t.Fatalf("URLs.Rewrites = %#v, want %#v", got, want)
	}
	if got, want := policyConfig.URLs.Redirects, []proxy.RegexRule{{Pattern: `^https://example\.com/redirect/google\?q=(.*) => https://www.google.com/search?q=$1`, Source: filepath.Join(listsDir, "urlredirectregexplist") + ":1"}}; len(got) != 1 || got[0].Pattern != want[0].Pattern {
		t.Fatalf("URLs.Redirects = %#v, want %#v", got, want)
	}
	if got, want := policyConfig.Headers.RequestRewrites, []proxy.RegexRule{{Pattern: `^(?i)User-Agent:.*Chrome.* => User-Agent: Mozilla/5.0 (Stealth)`, Source: filepath.Join(listsDir, "headerregexplist") + ":1"}}; len(got) != 1 || got[0].Pattern != want[0].Pattern {
		t.Fatalf("Headers.RequestRewrites = %#v, want %#v", got, want)
	}
	if got, want := policyConfig.Headers.RequestAdds, []proxy.RegexRule{{Pattern: `^https://example\.com/secure => X-Secure-Add: yes`, Source: filepath.Join(listsDir, "addheaderregexplist") + ":1"}}; len(got) != 1 || got[0].Pattern != want[0].Pattern {
		t.Fatalf("Headers.RequestAdds = %#v, want %#v", got, want)
	}
	if got, want := policyConfig.Headers.ResponseRewrites, []proxy.RegexRule{{Pattern: `^(?i)Server:.*Apache.* => Server: LucidGate`, Source: filepath.Join(listsDir, "responseheaderregexplist") + ":1"}}; len(got) != 1 || got[0].Pattern != want[0].Pattern {
		t.Fatalf("Headers.ResponseRewrites = %#v, want %#v", got, want)
	}
	if decision := policy.Evaluate("example.test", checkReq("http://example.test/private/report?q=1"), "http"); !decision.Blocked {
		t.Fatalf("blocked URL decision = %#v, want blocked", decision)
	}
	if decision := policy.Evaluate("example.test", checkReq("http://example.test/private/allowed/report"), "http"); decision.Blocked {
		t.Fatalf("exception URL decision = %#v, want allowed", decision)
	}
	if decision := policy.Evaluate("example.test", checkReq("http://example.test/blocked-by-regex?x=1"), "http"); !decision.Blocked {
		t.Fatalf("regex URL decision = %#v, want blocked", decision)
	}
	if decision := policy.Evaluate("example.test", checkReq("http://example.test/blocked-by-regex?token=ok"), "http"); decision.Blocked {
		t.Fatalf("regex exception URL decision = %#v, want allowed", decision)
	}
	refererReq := checkReq("http://example.test/contains-blocked-phrase")
	refererReq.Header.Set("Referer", "https://sub.trusted-ref.test/source")
	if decision := policy.Evaluate("example.test", refererReq, "http"); !decision.BypassFilters || decision.MatchType != "referer_site_exception" {
		t.Fatalf("referer site exception decision = %#v, want bypass", decision)
	}
	refererURLReq := checkReq("http://example.test/contains-blocked-phrase")
	refererURLReq.Header.Set("Referer", "https://partner-ref.test/allowed/path")
	if decision := policy.Evaluate("example.test", refererURLReq, "http"); !decision.BypassFilters || decision.MatchType != "referer_url_exception" {
		t.Fatalf("referer URL exception decision = %#v, want bypass", decision)
	}
	refererIPReq := checkReq("http://example.test/contains-blocked-phrase")
	refererIPReq.Header.Set("Referer", "https://198.51.100.42/source")
	if decision := policy.Evaluate("example.test", refererIPReq, "http"); !decision.BypassFilters || decision.MatchType != "referer_site_ip_exception" {
		t.Fatalf("referer site IP exception decision = %#v, want bypass", decision)
	}
	if decision := policy.EvaluateRequest("example.test", checkReq("http://example.test/download/tool.exe"), "http"); !decision.Blocked || decision.MatchType != "extension" {
		t.Fatalf("extension decision = %#v, want blocked", decision)
	}
	if decision := policy.EvaluateRequest("example.test", checkReq("http://example.test/download/allowed.zip"), "http"); decision.Blocked {
		t.Fatalf("filename exception decision = %#v, want allowed", decision)
	}
	resp := &http.Response{
		StatusCode: http.StatusOK,
		Header:     make(http.Header),
		Request:    checkReq("http://example.test/download/file"),
	}
	resp.Header.Set("Content-Type", "application/x-msdownload")
	if decision := policy.EvaluateResponse(resp, "http"); !decision.Blocked || decision.MatchType != "mime" {
		t.Fatalf("MIME decision = %#v, want blocked", decision)
	}
	resp.Header.Set("Content-Type", "application/octet-stream")
	resp.Header.Set("Content-Disposition", `attachment; filename="secret.bin"`)
	if decision := policy.EvaluateResponse(resp, "http"); !decision.Blocked || decision.MatchType != "filename" {
		t.Fatalf("filename decision = %#v, want blocked", decision)
	}
	headerReq := checkReq("http://example.test/")
	headerReq.Header.Set("X-Tracker", "blocked")
	if decision := policy.EvaluateRequest("example.test", headerReq, "http"); !decision.Blocked || decision.MatchType != "header" {
		t.Fatalf("header decision = %#v, want blocked", decision)
	}
	headerReq.Header.Set("X-Tracker", "allowed")
	if decision := policy.EvaluateRequest("example.test", headerReq, "http"); decision.Blocked {
		t.Fatalf("header exception decision = %#v, want allowed", decision)
	}
	headerReq.Header.Del("X-Tracker")
	headerReq.Header.Set("X-Device", "blocked-7")
	if decision := policy.EvaluateRequest("example.test", headerReq, "http"); !decision.Blocked || decision.MatchType != "header_regex" {
		t.Fatalf("header regex decision = %#v, want blocked", decision)
	}
	headerReq.Header.Set("X-Device", "blocked-42")
	if decision := policy.EvaluateRequest("example.test", headerReq, "http"); decision.Blocked {
		t.Fatalf("header regex exception decision = %#v, want allowed", decision)
	}
	cookieReq := checkReq("http://example.test/")
	cookieReq.Header.Set("Cookie", "trackid=bad")
	if decision := policy.EvaluateRequest("example.test", cookieReq, "http"); !decision.Blocked || decision.MatchType != "cookie" {
		t.Fatalf("cookie decision = %#v, want blocked", decision)
	}
}

func TestLoadRulePolicyCompilesE2GuardianTimeListsToSchedules(t *testing.T) {
	dir := t.TempDir()
	listsDir := filepath.Join(dir, "lists")
	writeFile(t, filepath.Join(listsDir, "bannedtimelist"), "22 0 23 59 01234\n")

	cfg := &appConfig{
		ConfigPath:  filepath.Join(dir, "lucidgate.toml"),
		IncludeDirs: []string{"lists"},
		AccessProfiles: []AccessProfileConfig{
			{Name: "students", Clients: []string{"192.0.2.0/24"}},
			{Name: "staff", Default: true, Clients: []string{"127.0.0.1"}},
		},
	}
	_, err := loadRulePolicy(cfg)
	if err != nil {
		t.Fatalf("loadRulePolicy() error = %v", err)
	}
	windows := make([]proxy.ScheduleWindow, 0, len(cfg.ScheduleWindows))
	for _, window := range cfg.ScheduleWindows {
		windows = append(windows, proxy.ScheduleWindow{
			Profile: window.Profile,
			Days:    window.Days,
			Start:   window.Start,
			End:     window.End,
		})
	}
	schedules, err := proxy.NewScheduleRules(windows)
	if err != nil {
		t.Fatalf("NewScheduleRules() error = %v; windows=%#v", err, cfg.ScheduleWindows)
	}
	mondayAllowed := time.Date(2026, 6, 1, 21, 59, 0, 0, time.Local)
	mondayBlocked := time.Date(2026, 6, 1, 22, 30, 0, 0, time.Local)
	saturdayAllowed := time.Date(2026, 6, 6, 22, 30, 0, 0, time.Local)
	if !schedules.Allowed("students", mondayAllowed) {
		t.Fatal("students should be allowed before e2guardian bannedtimelist band")
	}
	if schedules.Allowed("students", mondayBlocked) {
		t.Fatal("students should be blocked inside e2guardian bannedtimelist band")
	}
	if schedules.Allowed("staff", mondayBlocked) {
		t.Fatal("staff should be blocked inside e2guardian bannedtimelist band")
	}
	if !schedules.Allowed("students", saturdayAllowed) {
		t.Fatal("students should be allowed on days not present in e2guardian bannedtimelist")
	}
}

func TestLoadRulePolicyReportsInvalidE2GuardianTimeListWithLineInfo(t *testing.T) {
	dir := t.TempDir()
	listsDir := filepath.Join(dir, "lists")
	writeFile(t, filepath.Join(listsDir, "blankettimelist"), "22 0 24 0 01234\n")

	cfg := &appConfig{
		ConfigPath:  filepath.Join(dir, "lucidgate.toml"),
		IncludeDirs: []string{"lists"},
	}
	_, err := loadRulePolicy(cfg)
	if err == nil {
		t.Fatal("loadRulePolicy() error = nil, want invalid blankettimelist error")
	}
	if !strings.Contains(err.Error(), "blankettimelist:1") || !strings.Contains(err.Error(), "invalid end hour") {
		t.Fatalf("loadRulePolicy() error = %v, want file:line invalid end hour", err)
	}
}

func TestLoadRulePolicyReportsInvalidRefererExceptionSiteIPWithLineInfo(t *testing.T) {
	dir := t.TempDir()
	listsDir := filepath.Join(dir, "lists")
	writeFile(t, filepath.Join(listsDir, "refererexceptionsiteiplist"), "198.51.100.42\nbad-ip\n")

	cfg := &appConfig{
		ConfigPath:  filepath.Join(dir, "lucidgate.toml"),
		IncludeDirs: []string{"lists"},
	}
	_, err := loadRulePolicy(cfg)
	if err == nil {
		t.Fatal("loadRulePolicy() error = nil, want invalid refererexceptionsiteiplist error")
	}
	if !strings.Contains(err.Error(), "refererexceptionsiteiplist:2") || !strings.Contains(err.Error(), "invalid IP/CIDR") {
		t.Fatalf("loadRulePolicy() error = %v, want file:line invalid IP/CIDR", err)
	}
}

func TestApplyRuntimeConfigRejectsInvalidPolicyRegexWithFileLine(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "lists", "bannedregexpurllist"), "ok\n[\n")
	cfg := appConfig{
		ConfigPath:  filepath.Join(dir, "lucidgate.toml"),
		IncludeDirs: []string{"lists"},
	}

	server := proxy.NewServer("127.0.0.1:0", nil)
	err := applyRuntimeConfig(server, &cfg)
	if err == nil || !strings.Contains(err.Error(), "bannedregexpurllist:2") {
		t.Fatalf("applyRuntimeConfig() error = %v, want file:line regex error", err)
	}
}

func TestApplyRuntimeConfigRejectsInvalidHeaderRegexWithFileLine(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "lists", "bannedregexpheaderlist"), "ok\n[\n")
	cfg := appConfig{
		ConfigPath:  filepath.Join(dir, "lucidgate.toml"),
		IncludeDirs: []string{"lists"},
	}

	server := proxy.NewServer("127.0.0.1:0", nil)
	err := applyRuntimeConfig(server, &cfg)
	if err == nil || !strings.Contains(err.Error(), "bannedregexpheaderlist:2") {
		t.Fatalf("applyRuntimeConfig() error = %v, want file:line header regex error", err)
	}
}

func TestApplyRuntimeConfigRejectsInvalidSubstitutionRegex(t *testing.T) {
	cfg := appConfig{
		RegexSubstitutions: []RegexSubstitutionConfig{
			{Pattern: `[`, Replace: "x", Source: "regex-sub.list:2"},
		},
	}
	server := proxy.NewServer("127.0.0.1:0", nil)
	err := applyRuntimeConfig(server, &cfg)
	if err == nil || !strings.Contains(err.Error(), "regex-sub.list:2") {
		t.Fatalf("applyRuntimeConfig() error = %v, want source regex error", err)
	}
}

func TestApplyRuntimeConfigRejectsInvalidRequestSubstitutionRegex(t *testing.T) {
	cfg := appConfig{
		RegexRequestSubstitutions: []RegexSubstitutionConfig{
			{Pattern: `[`, Replace: "x", Source: "req-regex-sub.list:3"},
		},
	}
	server := proxy.NewServer("127.0.0.1:0", nil)
	err := applyRuntimeConfig(server, &cfg)
	if err == nil || !strings.Contains(err.Error(), "req-regex-sub.list:3") {
		t.Fatalf("applyRuntimeConfig() error = %v, want request source regex error", err)
	}
}

func TestApplyRuntimeConfigRejectsBroadRequestSubstitutionRegex(t *testing.T) {
	cfg := appConfig{
		IOTimeout:     time.Second,
		WSIdleTimeout: time.Minute,
		DialTimeout:   time.Second,
		WaitTimeout:   time.Millisecond,
		RegexRequestSubstitutions: []RegexSubstitutionConfig{
			{
				Pattern: `(?i)token\s*[:=]\s*[A-Za-z0-9._-]+`,
				Replace: `token=[redacted]`,
				Source:  "requestregexsubstitutionlist:9",
			},
		},
	}
	server := proxy.NewServer("127.0.0.1:0", nil)
	err := applyRuntimeConfig(server, &cfg)
	if err == nil ||
		!strings.Contains(err.Error(), "requestregexsubstitutionlist:9") ||
		!strings.Contains(err.Error(), "protected canary") {
		t.Fatalf("applyRuntimeConfig() error = %v, want protected canary rejection with source", err)
	}
}

func TestValidateRequestRegexSubstitutionRejectsGenericPIIRegex(t *testing.T) {
	err := validateRequestRegexSubstitutionSafety([]RegexSubstitutionConfig{
		{
			Pattern: `\b(?:\d[ -]*?){13,19}\b`,
			Replace: `[REDACTED_CARD]`,
			Source:  "requestregexsubstitutionlist:44",
		},
	})
	if err == nil ||
		!strings.Contains(err.Error(), "requestregexsubstitutionlist:44") ||
		!strings.Contains(err.Error(), "numeric trace identifiers") {
		t.Fatalf("validateRequestRegexSubstitutionSafety() error = %v, want generic PII rejection", err)
	}
}

func TestValidateRequestRegexSubstitutionRejectsDelimiterCorruption(t *testing.T) {
	err := validateRequestRegexSubstitutionSafety([]RegexSubstitutionConfig{
		{
			Pattern: `(?i)(^|[^a-zA-Z0-9]|%[0-9a-fA-F]{2})(password|passwd|secret|api_key)((?:\s*|%20|\+)*(?::|=|%3A|%3D)(?:\s*|%20|\+|"|%22)*)([^&"'\n\r]+?)(?:%0[AaDd]|%2[267]|\n|\r|&|"|'|$)`,
			Replace: `$1$2$3[REDACTED_SECRET]`,
			Source:  "requestregexsubstitutionlist:21",
		},
	})
	if err == nil ||
		!strings.Contains(err.Error(), "requestregexsubstitutionlist:21") ||
		!strings.Contains(err.Error(), "global (?i)") {
		t.Fatalf("validateRequestRegexSubstitutionSafety() error = %v, want delimiter corruption rejection", err)
	}
}

func TestValidateRequestRegexSubstitutionAllowsSurgicalDLP(t *testing.T) {
	err := validateRequestRegexSubstitutionSafety([]RegexSubstitutionConfig{
		{Pattern: `\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b`, Replace: `[REDACTED_OPENAI_KEY]`},
		{Pattern: `\bya29\.[A-Za-z0-9_-]{20,}\b`, Replace: `[REDACTED_GCP_TOKEN]`},
		{Pattern: `\b(?:s|hvs)\.[A-Za-z0-9_-]{24,}\b`, Replace: `[REDACTED_VAULT_TOKEN]`},
		{
			Pattern: `(^|[^a-zA-Z0-9]|%[0-9a-fA-F]{2})((?i:password|passwd|secret|api_key|secret_key|auth_token|private_key))((?:\s*|%20|\+)*(?:"|%22|'|%27)?(?::|=|%3[Aa]|%3[Dd])(?:\s*|%20|\+|"|%22)*)((?:[^&%"'\n\r]+|%(?:[1-9A-Fa-f][0-9A-Fa-f]|0[0-9B-CE-Fa-f]|2[013-57-9A-Fa-f]))+)`,
			Replace: `${1}${2}${3}[REDACTED_SECRET]`,
		},
	})
	if err != nil {
		t.Fatalf("validateRequestRegexSubstitutionSafety() error = %v", err)
	}
}

func TestApplyRuntimeConfigPublishesWSIdleTimeout(t *testing.T) {
	cfg := appConfig{
		IOTimeout:        time.Second,
		WSIdleTimeout:    2 * time.Minute,
		MaxCaptureBytes:  1 << 20,
		AntivirusTimeout: 30 * time.Second,
	}
	server := proxy.NewServer("127.0.0.1:0", nil)
	if err := applyRuntimeConfig(server, &cfg); err != nil {
		t.Fatalf("applyRuntimeConfig() error = %v", err)
	}
	opts := server.RelayOptions()
	if opts.WSIdleTimeout != 2*time.Minute {
		t.Fatalf("RelayOptions.WSIdleTimeout = %s, want 2m", opts.WSIdleTimeout)
	}
}

func TestParseConfigRejectsInvalidValues(t *testing.T) {
	_, err := parseConfig([]string{"--max-capture-bytes", "-1"}, emptyEnv, &bytes.Buffer{})
	if err == nil {
		t.Fatal("parseConfig() error = nil, want validation error")
	}
	_, err = parseConfig([]string{"--ws-idle-timeout", "0"}, emptyEnv, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "ws idle timeout") {
		t.Fatalf("parseConfig() error = %v, want ws idle timeout validation error", err)
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

func TestLoadRulePolicyRecognizesE2GuardianPhraseLists(t *testing.T) {
	dir := t.TempDir()
	listsDir := filepath.Join(dir, "lists")
	writeFile(t, filepath.Join(listsDir, "bannedphraselist"), "credential dump\nmalware kit\n")
	writeFile(t, filepath.Join(listsDir, "exceptionphraselist"), "malware research\n")
	writeFile(t, filepath.Join(listsDir, "weightedphraselist"), "<phishing><60>\n<scam><40>\n")
	writeFile(t, filepath.Join(listsDir, "weightedphraseexceptions"), "<scam><40>\n")

	cfg := &appConfig{
		ConfigPath:        filepath.Join(dir, "lucidgate.toml"),
		IncludeDirs:       []string{"lists"},
		SemanticThreshold: 100,
	}
	if _, err := loadRulePolicy(cfg); err != nil {
		t.Fatalf("loadRulePolicy() error = %v", err)
	}
	if got, want := cfg.SemanticPhrases, []string{"credential dump", "malware kit"}; !equalStrings(got, want) {
		t.Fatalf("SemanticPhrases = %#v, want %#v", got, want)
	}
	if got, want := cfg.SemanticExceptionPhrases, []string{"malware research"}; !equalStrings(got, want) {
		t.Fatalf("SemanticExceptionPhrases = %#v, want %#v", got, want)
	}
	if got, want := cfg.SemanticWeighted, []SemanticPhraseConfig{{Phrase: "phishing", Weight: 60}, {Phrase: "scam", Weight: 40}}; !equalWeighted(got, want) {
		t.Fatalf("SemanticWeighted = %#v, want %#v", got, want)
	}
	if got, want := cfg.SemanticWeightedExceptions, []SemanticPhraseConfig{{Phrase: "scam", Weight: 40}}; !equalWeighted(got, want) {
		t.Fatalf("SemanticWeightedExceptions = %#v, want %#v", got, want)
	}
}

func TestLoadRulePolicyRecognizesLegacyAliases(t *testing.T) {
	dir := t.TempDir()
	listsDir := filepath.Join(dir, "lists")
	writeFile(t, filepath.Join(listsDir, "oldbannedphraselist"), "legacy hard block\n")
	writeFile(t, filepath.Join(listsDir, "oldexceptionphraselist"), "legacy exception\n")
	writeFile(t, filepath.Join(listsDir, "oldweightedphraselist"), "<legacy_weighted><70>\n")

	cfg := &appConfig{
		ConfigPath:        filepath.Join(dir, "lucidgate.toml"),
		IncludeDirs:       []string{"lists"},
		SemanticThreshold: 100,
	}
	if _, err := loadRulePolicy(cfg); err != nil {
		t.Fatalf("loadRulePolicy() error = %v", err)
	}
	if got, want := cfg.SemanticPhrases, []string{"legacy hard block"}; !equalStrings(got, want) {
		t.Fatalf("SemanticPhrases = %#v, want %#v", got, want)
	}
	if got, want := cfg.SemanticExceptionPhrases, []string{"legacy exception"}; !equalStrings(got, want) {
		t.Fatalf("SemanticExceptionPhrases = %#v, want %#v", got, want)
	}
	if got, want := cfg.SemanticWeighted, []SemanticPhraseConfig{{Phrase: "legacy_weighted", Weight: 70}}; !equalWeighted(got, want) {
		t.Fatalf("SemanticWeighted = %#v, want %#v", got, want)
	}
}

func TestLoadRulePolicyReportsWeightedPhraseParseErrorWithLineInfo(t *testing.T) {
	dir := t.TempDir()
	listsDir := filepath.Join(dir, "lists")
	writeFile(t, filepath.Join(listsDir, "weightedphraselist"), "<ok><10>\nbroken-line\n")

	cfg := &appConfig{
		ConfigPath:        filepath.Join(dir, "lucidgate.toml"),
		IncludeDirs:       []string{"lists"},
		SemanticThreshold: 50,
	}
	_, err := loadRulePolicy(cfg)
	if err == nil {
		t.Fatal("loadRulePolicy() error = nil, want parse error")
	}
	if !strings.Contains(err.Error(), "weightedphraselist:2") {
		t.Fatalf("error = %v, want file:line context", err)
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func equalWeighted(a, b []SemanticPhraseConfig) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func emptyEnv(string) string {
	return ""
}

func TestParseConfigRejectsCleartextWithoutPolicyHit(t *testing.T) {
	cfg := appConfig{
		ListenAddr:               "127.0.0.1:8080",
		CertDir:                  "certs",
		MaxConnections:           10,
		IOTimeout:                time.Second,
		WSIdleTimeout:            time.Second,
		DialTimeout:              time.Second,
		HandshakeTimeout:         time.Second,
		DumpCredentialsCleartext: true,
		DumpOnPolicyHit:          false,
	}
	err := cfg.validate()
	if err == nil {
		t.Fatal("expected validation error when dump_credentials_cleartext=true and dump_on_policy_hit=false")
	}
	if !strings.Contains(err.Error(), "dump_credentials_cleartext=true requires dump_on_policy_hit=true") {
		t.Fatalf("unexpected error message: %v", err)
	}
}

func TestLoadRulePolicyDownloadManager(t *testing.T) {
	dir := t.TempDir()
	listsDir := filepath.Join(dir, "lists")

	// Create valid downloadmanager file
	validRules := `
# some comment
banned ext exe
banned mime application/zip
exception ext dmg
exception mime application/x-shockwave-flash
`
	writeFile(t, filepath.Join(listsDir, "downloadmanager"), validRules)

	cfg := &appConfig{
		ConfigPath:  filepath.Join(dir, "lucidgate.toml"),
		IncludeDirs: []string{"lists"},
	}
	policyConfig, err := loadRulePolicy(cfg)
	if err != nil {
		t.Fatalf("loadRulePolicy() error = %v", err)
	}

	// Validate parsed fields
	if !equalStrings(policyConfig.Files.BannedExtensions, []string{"exe"}) {
		t.Errorf("BannedExtensions = %v, want [exe]", policyConfig.Files.BannedExtensions)
	}
	if !equalStrings(policyConfig.Files.BannedMIMEs, []string{"application/zip"}) {
		t.Errorf("BannedMIMEs = %v, want [application/zip]", policyConfig.Files.BannedMIMEs)
	}
	if !equalStrings(policyConfig.Files.ExceptionExtensions, []string{"dmg"}) {
		t.Errorf("ExceptionExtensions = %v, want [dmg]", policyConfig.Files.ExceptionExtensions)
	}
	if !equalStrings(policyConfig.Files.ExceptionMIMEs, []string{"application/x-shockwave-flash"}) {
		t.Errorf("ExceptionMIMEs = %v, want [application/x-shockwave-flash]", policyConfig.Files.ExceptionMIMEs)
	}

	// Test malformed actions
	t.Run("invalid action", func(t *testing.T) {
		badDir := t.TempDir()
		badListsDir := filepath.Join(badDir, "lists")
		writeFile(t, filepath.Join(badListsDir, "downloadmanager"), "unknown ext zip\n")
		badCfg := &appConfig{
			ConfigPath:  filepath.Join(badDir, "lucidgate.toml"),
			IncludeDirs: []string{"lists"},
		}
		_, err := loadRulePolicy(badCfg)
		if err == nil {
			t.Fatal("expected error with invalid action")
		}
		if !strings.Contains(err.Error(), "unsupported downloadmanager action \"unknown\"") {
			t.Errorf("unexpected error: %v", err)
		}
	})

	// Test malformed rule type
	t.Run("invalid rule type", func(t *testing.T) {
		badDir := t.TempDir()
		badListsDir := filepath.Join(badDir, "lists")
		writeFile(t, filepath.Join(badListsDir, "downloadmanager"), "banned type zip\n")
		badCfg := &appConfig{
			ConfigPath:  filepath.Join(badDir, "lucidgate.toml"),
			IncludeDirs: []string{"lists"},
		}
		_, err := loadRulePolicy(badCfg)
		if err == nil {
			t.Fatal("expected error with invalid rule type")
		}
		if !strings.Contains(err.Error(), "unsupported downloadmanager rule type \"type\"") {
			t.Errorf("unexpected error: %v", err)
		}
	})

	// Test wrong token count
	t.Run("wrong token count", func(t *testing.T) {
		badDir := t.TempDir()
		badListsDir := filepath.Join(badDir, "lists")
		writeFile(t, filepath.Join(badListsDir, "downloadmanager"), "banned ext\n")
		badCfg := &appConfig{
			ConfigPath:  filepath.Join(badDir, "lucidgate.toml"),
			IncludeDirs: []string{"lists"},
		}
		_, err := loadRulePolicy(badCfg)
		if err == nil {
			t.Fatal("expected error with wrong token count")
		}
		if !strings.Contains(err.Error(), "invalid downloadmanager rule \"banned ext\" (expected: [banned|exception] [ext|mime] [value])") {
			t.Errorf("unexpected error: %v", err)
		}
	})
}
