package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("MkdirAll(%s) error = %v", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("WriteFile(%s) error = %v", path, err)
	}
}

func TestLoadPlainListFileWithCommentsBlanksAndIncludes(t *testing.T) {
	dir := t.TempDir()
	main := filepath.Join(dir, "main.list")
	extra := filepath.Join(dir, "extra.list")
	writeFile(t, main, `# header
foo

bar # trailing comment
.Include<extra.list>
quz
`)
	writeFile(t, extra, `extra-1
extra-2
`)
	lines, err := loadPlainListFile(main, map[string]bool{})
	if err != nil {
		t.Fatalf("loadPlainListFile() error = %v", err)
	}
	got := make([]string, 0, len(lines))
	for _, l := range lines {
		got = append(got, l.Text)
	}
	want := []string{"foo", "bar", "extra-1", "extra-2", "quz"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("entries = %#v, want %#v", got, want)
	}
}

func TestLoadPlainListFileAbsoluteInclude(t *testing.T) {
	dir := t.TempDir()
	other := filepath.Join(dir, "other.list")
	writeFile(t, other, "abs-1\nabs-2\n")
	main := filepath.Join(dir, "main.list")
	writeFile(t, main, ".Include<"+other+">\nlocal\n")

	lines, err := loadPlainListFile(main, map[string]bool{})
	if err != nil {
		t.Fatalf("loadPlainListFile() error = %v", err)
	}
	if len(lines) != 3 || lines[0].Text != "abs-1" || lines[2].Text != "local" {
		t.Fatalf("entries = %#v", lines)
	}
}

func TestLoadPlainListFileDetectsCycle(t *testing.T) {
	dir := t.TempDir()
	a := filepath.Join(dir, "a.list")
	b := filepath.Join(dir, "b.list")
	writeFile(t, a, ".Include<b.list>\n")
	writeFile(t, b, ".Include<a.list>\n")

	_, err := loadPlainListFile(a, map[string]bool{})
	if err == nil || !strings.Contains(err.Error(), "include cycle") {
		t.Fatalf("loadPlainListFile() error = %v, want include cycle", err)
	}
}

func TestLoadTextListFilesDirectoryOrdering(t *testing.T) {
	dir := t.TempDir()
	listsDir := filepath.Join(dir, "phrases")
	writeFile(t, filepath.Join(listsDir, "20-second.list"), "second\n")
	writeFile(t, filepath.Join(listsDir, "10-first.list"), "first\n")

	out, err := loadTextListFiles(dir, []string{"phrases"})
	if err != nil {
		t.Fatalf("loadTextListFiles() error = %v", err)
	}
	if strings.Join(out, ",") != "first,second" {
		t.Fatalf("entries = %#v", out)
	}
}

func TestParseWeightedLine(t *testing.T) {
	cases := []struct {
		in      string
		phrase  string
		weight  int
		wantErr bool
	}{
		{"<malware><60>", "malware", 60, false},
		{"<credential dump><80>", "credential dump", 80, false},
		{"<frase con espacios><1>", "frase con espacios", 1, false},
		{"<malware>", "", 0, true},
		{"<><10>", "", 0, true},
		{"<malware><0>", "", 0, true},
		{"<malware><-5>", "", 0, true},
		{"malware<10>", "", 0, true},
	}
	for _, tc := range cases {
		phrase, weight, err := parseWeightedLine(tc.in)
		if (err != nil) != tc.wantErr {
			t.Fatalf("parseWeightedLine(%q) err = %v, wantErr = %v", tc.in, err, tc.wantErr)
		}
		if tc.wantErr {
			continue
		}
		if phrase != tc.phrase || weight != tc.weight {
			t.Fatalf("parseWeightedLine(%q) = (%q,%d), want (%q,%d)", tc.in, phrase, weight, tc.phrase, tc.weight)
		}
	}
}

func TestParseSubstitutionLine(t *testing.T) {
	cases := []struct {
		in      string
		search  string
		replace string
		wantErr bool
	}{
		{"a => b", "a", "b", false},
		{"Madrid => Barcelona", "Madrid", "Barcelona", false},
		{"a =>", "a", "", false},
		{"=> b", "", "", true},
		{"no separator", "", "", true},
	}
	for _, tc := range cases {
		s, r, err := parseSubstitutionLine(tc.in)
		if (err != nil) != tc.wantErr {
			t.Fatalf("parseSubstitutionLine(%q) err = %v, wantErr = %v", tc.in, err, tc.wantErr)
		}
		if tc.wantErr {
			continue
		}
		if s != tc.search || r != tc.replace {
			t.Fatalf("parseSubstitutionLine(%q) = (%q,%q), want (%q,%q)", tc.in, s, r, tc.search, tc.replace)
		}
	}
}

func TestLoadWeightedPhraseFilesError(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "weighted.list")
	writeFile(t, path, "<malware><60>\nbroken-line\n")
	_, err := loadWeightedPhraseFiles(dir, []string{"weighted.list"})
	if err == nil || !strings.Contains(err.Error(), "weighted.list:2") {
		t.Fatalf("loadWeightedPhraseFiles() err = %v, want file:line", err)
	}
}

func TestLoadSubstitutionFilesError(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "subs.list")
	writeFile(t, path, "Madrid => Barcelona\nbroken line\n")
	_, err := loadSubstitutionFiles(dir, []string{"subs.list"})
	if err == nil || !strings.Contains(err.Error(), "subs.list:2") {
		t.Fatalf("loadSubstitutionFiles() err = %v, want file:line", err)
	}
}

func TestLoadRegexSubstitutionFiles(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "regex-subs.list")
	writeFile(t, path, `ca.*sa\.png => carcasa.png
foo([0-9]+) => bar$1
`)
	got, err := loadRegexSubstitutionFiles(dir, []string{"regex-subs.list"})
	if err != nil {
		t.Fatalf("loadRegexSubstitutionFiles() error = %v", err)
	}
	if len(got) != 2 ||
		got[0].Pattern != `ca.*sa\.png` || got[0].Replace != "carcasa.png" || !strings.Contains(got[0].Source, "regex-subs.list:1") ||
		got[1].Pattern != `foo([0-9]+)` || got[1].Replace != "bar$1" {
		t.Fatalf("regex substitutions = %#v", got)
	}
}

func TestParseConfigCombinesEmbeddedAndExternalLists(t *testing.T) {
	dir := t.TempDir()
	listsDir := filepath.Join(dir, "lists")
	writeFile(t, filepath.Join(listsDir, "phraselists", "bannedphraselist"), "extra-banned\n")
	writeFile(t, filepath.Join(listsDir, "phraselists", "weightedphraselist"), "<extra-weight><25>\n")
	writeFile(t, filepath.Join(listsDir, "phraselists", "exceptionphraselist"), "exception-1\n")
	writeFile(t, filepath.Join(listsDir, "masking", "maskedphraselist"), "extra-mask\n")
	writeFile(t, filepath.Join(listsDir, "substitution", "substitutionlist"), "Foo => Bar\n")
	writeFile(t, filepath.Join(listsDir, "substitution", "regexsubstitutionlist"), `ca.*sa\.png => carcasa.png`+"\n")

	tomlPath := filepath.Join(dir, "lucidgate.toml")
	writeFile(t, tomlPath, `
[semantic]
blocked_phrases = ["embedded-banned"]
blocked_phrase_lists = ["lists/phraselists/bannedphraselist"]
weighted_phrase_lists = ["lists/phraselists/weightedphraselist"]
exception_phrase_lists = ["lists/phraselists/exceptionphraselist"]
score_threshold = 100

[[semantic.weighted_phrase]]
phrase = "embedded-weight"
weight = 50

[masking]
phrases = ["embedded-mask"]
phrase_lists = ["lists/masking/maskedphraselist"]

[substitution]
rule_lists = ["lists/substitution/substitutionlist"]
regex_rule_lists = ["lists/substitution/regexsubstitutionlist"]

[[substitution.rule]]
search = "Madrid"
replace = "Barcelona"

[[substitution.regex_rule]]
pattern = "foo[0-9]+"
replace = "bar"
max_window_bytes = 4096
`)

	cfg, err := parseConfig([]string{"--config", tomlPath}, emptyEnv, &bytes.Buffer{})
	if err != nil {
		t.Fatalf("parseConfig() error = %v", err)
	}
	if got := cfg.SemanticPhrases; len(got) != 2 || got[0] != "embedded-banned" || got[1] != "extra-banned" {
		t.Fatalf("SemanticPhrases = %#v", got)
	}
	if got := cfg.SemanticExceptionPhrases; len(got) != 1 || got[0] != "exception-1" {
		t.Fatalf("SemanticExceptionPhrases = %#v", got)
	}
	if got := cfg.MaskingPhrases; len(got) != 2 || got[0] != "embedded-mask" || got[1] != "extra-mask" {
		t.Fatalf("MaskingPhrases = %#v", got)
	}
	if got := cfg.SemanticWeighted; len(got) != 2 ||
		got[0].Phrase != "embedded-weight" || got[0].Weight != 50 ||
		got[1].Phrase != "extra-weight" || got[1].Weight != 25 {
		t.Fatalf("SemanticWeighted = %#v", got)
	}
	if got := cfg.Substitutions; len(got) != 2 ||
		got[0].Search != "Madrid" || got[0].Replace != "Barcelona" ||
		got[1].Search != "Foo" || got[1].Replace != "Bar" {
		t.Fatalf("Substitutions = %#v", got)
	}
	if got := cfg.RegexSubstitutions; len(got) != 2 ||
		got[0].Pattern != "foo[0-9]+" || got[0].Replace != "bar" || got[0].MaxWindowBytes != 4096 ||
		got[1].Pattern != `ca.*sa\.png` || got[1].Replace != "carcasa.png" {
		t.Fatalf("RegexSubstitutions = %#v", got)
	}
}

func TestParseConfigRejectsConflictingWeightedDuplicates(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "lists", "weighted.list"), "<malware><99>\n")
	tomlPath := filepath.Join(dir, "lucidgate.toml")
	writeFile(t, tomlPath, `
[semantic]
score_threshold = 100
weighted_phrase_lists = ["lists/weighted.list"]

[[semantic.weighted_phrase]]
phrase = "malware"
weight = 50
`)
	_, err := parseConfig([]string{"--config", tomlPath}, emptyEnv, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "duplicate weighted phrase") {
		t.Fatalf("parseConfig() err = %v, want duplicate weighted phrase", err)
	}
}

func TestParseConfigRejectsDuplicateSubstitution(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "lists", "subs.list"), "Madrid => Sevilla\n")
	tomlPath := filepath.Join(dir, "lucidgate.toml")
	writeFile(t, tomlPath, `
[substitution]
rule_lists = ["lists/subs.list"]

[[substitution.rule]]
search = "Madrid"
replace = "Barcelona"
`)
	_, err := parseConfig([]string{"--config", tomlPath}, emptyEnv, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "duplicate substitution search") {
		t.Fatalf("parseConfig() err = %v, want duplicate substitution search", err)
	}
}

func TestParseConfigRejectsDuplicateRegexSubstitution(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "lists", "regex-subs.list"), `ca.*sa\.png => carcasa.png`+"\n")
	tomlPath := filepath.Join(dir, "lucidgate.toml")
	writeFile(t, tomlPath, `
[substitution]
regex_rule_lists = ["lists/regex-subs.list"]

[[substitution.regex_rule]]
pattern = "ca.*sa\\.png"
replace = "other.png"
`)
	_, err := parseConfig([]string{"--config", tomlPath}, emptyEnv, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "duplicate regex substitution pattern") {
		t.Fatalf("parseConfig() err = %v, want duplicate regex substitution pattern", err)
	}
}

func TestParseConfigWithE2GuardianClientAndGroupRules(t *testing.T) {
	dir := t.TempDir()
	listsDir := filepath.Join(dir, "lists")

	// Create mockup e2guardian files
	writeFile(t, filepath.Join(listsDir, "bannedclientiplist"), "10.0.0.1\n192.168.1.0/24\n")
	writeFile(t, filepath.Join(listsDir, "exceptionclientiplist"), "192.168.1.100\n")
	writeFile(t, filepath.Join(listsDir, "filtergroupslist"), "students\nteachers\n")
	writeFile(t, filepath.Join(listsDir, "e2guardianipgroups"), "192.168.1.20=2\n10.0.0.5=admin\n")

	tomlPath := filepath.Join(dir, "lucidgate.toml")
	writeFile(t, tomlPath, `
[server]
listen_addr = "127.0.0.1:8080"

[rules]
include_dir = ["lists"]

[[access.profile]]
name = "admin"
clients = ["127.0.0.1/32"]
`)

	cfg, err := parseConfig([]string{"--config", tomlPath}, emptyEnv, &bytes.Buffer{})
	if err != nil {
		t.Fatalf("parseConfig() error = %v", err)
	}

	_, err = loadRulePolicy(&cfg)
	if err != nil {
		t.Fatalf("loadRulePolicy() error = %v", err)
	}

	// Verify BannedClients & ExceptionClients
	if len(cfg.BannedClients) != 2 || cfg.BannedClients[0] != "10.0.0.1" || cfg.BannedClients[1] != "192.168.1.0/24" {
		t.Fatalf("BannedClients = %#v, want [10.0.0.1, 192.168.1.0/24]", cfg.BannedClients)
	}
	if len(cfg.ExceptionClients) != 1 || cfg.ExceptionClients[0] != "192.168.1.100" {
		t.Fatalf("ExceptionClients = %#v, want [192.168.1.100]", cfg.ExceptionClients)
	}

	// Verify dynamically resolved AccessProfiles
	// Expected:
	// - "admin" profile should now have: "127.0.0.1/32" (TOML) + "10.0.0.5" (e2guardianipgroups)
	// - "teachers" profile should be created with: "192.168.1.20" (from 192.168.1.20=2, mapped via index 2)
	var foundAdmin, foundTeachers bool
	for _, p := range cfg.AccessProfiles {
		switch p.Name {
		case "admin":
			foundAdmin = true
			if len(p.Clients) != 2 || p.Clients[0] != "127.0.0.1/32" || p.Clients[1] != "10.0.0.5" {
				t.Fatalf("Admin clients = %#v, want [127.0.0.1/32, 10.0.0.5]", p.Clients)
			}
		case "teachers":
			foundTeachers = true
			if len(p.Clients) != 1 || p.Clients[0] != "192.168.1.20" {
				t.Fatalf("Teachers clients = %#v, want [192.168.1.20]", p.Clients)
			}
		}
	}
	if !foundAdmin {
		t.Error("profile 'admin' not found in AccessProfiles")
	}
	if !foundTeachers {
		t.Error("profile 'teachers' not found in AccessProfiles")
	}
}

func TestParseConfigRejectsInvalidE2GuardianClientIP(t *testing.T) {
	dir := t.TempDir()
	listsDir := filepath.Join(dir, "lists")

	// Create invalid e2guardian banned IP file
	writeFile(t, filepath.Join(listsDir, "bannedclientiplist"), "10.0.0.1\nnot-an-ip\n")

	tomlPath := filepath.Join(dir, "lucidgate.toml")
	writeFile(t, tomlPath, `
[rules]
include_dir = ["lists"]
`)

	cfg, err := parseConfig([]string{"--config", tomlPath}, emptyEnv, &bytes.Buffer{})
	if err != nil {
		t.Fatalf("parseConfig() error = %v", err)
	}

	_, err = loadRulePolicy(&cfg)
	if err == nil || !strings.Contains(err.Error(), "bannedclientiplist:2") {
		t.Fatalf("loadRulePolicy() error = %v, want bannedclientiplist:2 formatting error", err)
	}
}

func TestParseConfigWithE2GuardianLoggingLists(t *testing.T) {
	dir := t.TempDir()
	listsDir := filepath.Join(dir, "lists")

	// Create mockup e2guardian logging list files
	writeFile(t, filepath.Join(listsDir, "logsitelist"), "audit.example\n")
	writeFile(t, filepath.Join(listsDir, "logsiteiplist"), "203.0.113.10\n2001:db8::/32\n")
	writeFile(t, filepath.Join(listsDir, "logurllist"), "example.com/log\n")
	writeFile(t, filepath.Join(listsDir, "exceptionlogurllist"), "example.com/log/except\n")
	writeFile(t, filepath.Join(listsDir, "logregexpurllist"), "/log-rx-[0-9]+\n")
	writeFile(t, filepath.Join(listsDir, "exceptionlogregexpurllist"), "/no-log-rx-[0-9]+\n")
	writeFile(t, filepath.Join(listsDir, "logregexpsitelist"), "^logsite\\.org$\n")
	writeFile(t, filepath.Join(listsDir, "exceptionlogregexpsitelist"), "^exceptsite\\.org$\n")
	writeFile(t, filepath.Join(listsDir, "nologsitelist"), "static.example\n")
	writeFile(t, filepath.Join(listsDir, "nologsiteiplist"), "198.51.100.0/24\n")
	writeFile(t, filepath.Join(listsDir, "nologurllist"), "example.com/private\n")
	writeFile(t, filepath.Join(listsDir, "nologregexpurllist"), "/quiet-[0-9]+\n")
	writeFile(t, filepath.Join(listsDir, "nologextensionlist"), ".png\n")
	writeFile(t, filepath.Join(listsDir, "logphraselist"), "log phrase\n")
	writeFile(t, filepath.Join(listsDir, "exceptionlogphraselist"), "except log phrase\n")

	tomlPath := filepath.Join(dir, "lucidgate.toml")
	writeFile(t, tomlPath, `
[rules]
include_dir = ["lists"]
`)

	cfg, err := parseConfig([]string{"--config", tomlPath}, emptyEnv, &bytes.Buffer{})
	if err != nil {
		t.Fatalf("parseConfig() error = %v", err)
	}

	policy, err := loadRulePolicy(&cfg)
	if err != nil {
		t.Fatalf("loadRulePolicy() error = %v", err)
	}

	// Verify URL and Site logging configs loaded correctly
	if len(policy.Log.LogSites) != 1 || policy.Log.LogSites[0] != "audit.example" {
		t.Fatalf("LogSites = %#v, want [audit.example]", policy.Log.LogSites)
	}
	if len(policy.Log.LogSiteIPs) != 2 || policy.Log.LogSiteIPs[0] != "203.0.113.10" || policy.Log.LogSiteIPs[1] != "2001:db8::/32" {
		t.Fatalf("LogSiteIPs = %#v, want [203.0.113.10 2001:db8::/32]", policy.Log.LogSiteIPs)
	}
	if len(policy.Log.LogURLs) != 1 || policy.Log.LogURLs[0] != "example.com/log" {
		t.Fatalf("LogURLs = %#v, want [example.com/log]", policy.Log.LogURLs)
	}
	if len(policy.Log.ExceptionLogURLs) != 1 || policy.Log.ExceptionLogURLs[0] != "example.com/log/except" {
		t.Fatalf("ExceptionLogURLs = %#v, want [example.com/log/except]", policy.Log.ExceptionLogURLs)
	}
	if len(policy.Log.LogRegexURLs) != 1 || policy.Log.LogRegexURLs[0].Pattern != "/log-rx-[0-9]+" {
		t.Fatalf("LogRegexURLs = %#v, want pattern '/log-rx-[0-9]+'", policy.Log.LogRegexURLs)
	}
	if len(policy.Log.ExceptionLogRegexURLs) != 1 || policy.Log.ExceptionLogRegexURLs[0].Pattern != "/no-log-rx-[0-9]+" {
		t.Fatalf("ExceptionLogRegexURLs = %#v, want pattern '/no-log-rx-[0-9]+'", policy.Log.ExceptionLogRegexURLs)
	}
	if len(policy.Log.LogRegexSites) != 1 || policy.Log.LogRegexSites[0].Pattern != "^logsite\\.org$" {
		t.Fatalf("LogRegexSites = %#v, want pattern '^logsite\\.org$'", policy.Log.LogRegexSites)
	}
	if len(policy.Log.ExceptionLogRegexSites) != 1 || policy.Log.ExceptionLogRegexSites[0].Pattern != "^exceptsite\\.org$" {
		t.Fatalf("ExceptionLogRegexSites = %#v, want pattern '^exceptsite\\.org$'", policy.Log.ExceptionLogRegexSites)
	}
	if len(policy.Log.NoLogSites) != 1 || policy.Log.NoLogSites[0] != "static.example" {
		t.Fatalf("NoLogSites = %#v, want [static.example]", policy.Log.NoLogSites)
	}
	if len(policy.Log.NoLogSiteIPs) != 1 || policy.Log.NoLogSiteIPs[0] != "198.51.100.0/24" {
		t.Fatalf("NoLogSiteIPs = %#v, want [198.51.100.0/24]", policy.Log.NoLogSiteIPs)
	}
	if len(policy.Log.NoLogURLs) != 1 || policy.Log.NoLogURLs[0] != "example.com/private" {
		t.Fatalf("NoLogURLs = %#v, want [example.com/private]", policy.Log.NoLogURLs)
	}
	if len(policy.Log.NoLogRegexURLs) != 1 || policy.Log.NoLogRegexURLs[0].Pattern != "/quiet-[0-9]+" {
		t.Fatalf("NoLogRegexURLs = %#v, want pattern '/quiet-[0-9]+'", policy.Log.NoLogRegexURLs)
	}
	if len(policy.Log.NoLogExtensions) != 1 || policy.Log.NoLogExtensions[0] != ".png" {
		t.Fatalf("NoLogExtensions = %#v, want [.png]", policy.Log.NoLogExtensions)
	}

	// Verify LogPhrases and ExceptionLogPhrases in appConfig
	if len(cfg.LogPhrases) != 1 || cfg.LogPhrases[0] != "log phrase" {
		t.Fatalf("LogPhrases = %#v, want [log phrase]", cfg.LogPhrases)
	}
	if len(cfg.ExceptionLogPhrases) != 1 || cfg.ExceptionLogPhrases[0] != "except log phrase" {
		t.Fatalf("ExceptionLogPhrases = %#v, want [except log phrase]", cfg.ExceptionLogPhrases)
	}
}

func TestLoadRulePolicyReportsLogSiteIPParseErrorWithLineInfo(t *testing.T) {
	dir := t.TempDir()
	listsDir := filepath.Join(dir, "lists")
	writeFile(t, filepath.Join(listsDir, "logsiteiplist"), "203.0.113.10\nbad-ip\n")

	cfg := &appConfig{
		ConfigPath:  filepath.Join(dir, "lucidgate.toml"),
		IncludeDirs: []string{"lists"},
	}
	_, err := loadRulePolicy(cfg)
	if err == nil || !strings.Contains(err.Error(), "logsiteiplist:2") {
		t.Fatalf("loadRulePolicy() error = %v, want logsiteiplist:2", err)
	}
}

func TestLoadRulePolicyReportsSiteIPParseErrorWithLineInfo(t *testing.T) {
	dir := t.TempDir()
	listsDir := filepath.Join(dir, "lists")
	writeFile(t, filepath.Join(listsDir, "bannedsiteiplist"), "203.0.113.0/24\nbad-ip\n")

	cfg := &appConfig{
		ConfigPath:  filepath.Join(dir, "lucidgate.toml"),
		IncludeDirs: []string{"lists"},
	}
	_, err := loadRulePolicy(cfg)
	if err == nil || !strings.Contains(err.Error(), "bannedsiteiplist:2") {
		t.Fatalf("loadRulePolicy() error = %v, want bannedsiteiplist:2", err)
	}
}
