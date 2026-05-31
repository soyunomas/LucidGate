package main

import (
	"fmt"
	"net/netip"
	"path/filepath"
	"strings"

	"lucidgate/proxy"
)

func loadRuleDomains(cfg *appConfig) ([]string, error) {
	policy, err := loadRulePolicy(cfg)
	if err != nil {
		return nil, err
	}
	return policy.Domains.Blocked, nil
}

func loadRulePolicy(cfg *appConfig) (proxy.PolicyConfig, error) {
	if cfg == nil || len(cfg.IncludeDirs) == 0 {
		return proxy.PolicyConfig{}, nil
	}
	baseDir := "."
	if cfg.ConfigPath != "" {
		baseDir = filepath.Dir(cfg.ConfigPath)
	}
	files, err := expandListPaths(baseDir, cfg.IncludeDirs)
	if err != nil {
		return proxy.PolicyConfig{}, err
	}

	var policy proxy.PolicyConfig
	for _, path := range files {
		lines, err := loadPlainListFile(path, map[string]bool{})
		if err != nil {
			return proxy.PolicyConfig{}, err
		}
		switch filepath.Base(path) {
		case "bannedsitelist":
			policy.Domains.Blocked = append(policy.Domains.Blocked, domainListValues(lines)...)
		case "exceptionsitelist":
			policy.Domains.Exceptions = append(policy.Domains.Exceptions, domainListValues(lines)...)
		case "bannedregexpsitelist":
			policy.Domains.BlockRegex = append(policy.Domains.BlockRegex, regexListValues(lines)...)
		case "exceptionregexpsitelist":
			policy.Domains.AllowRegex = append(policy.Domains.AllowRegex, regexListValues(lines)...)
		case "bannedurllist":
			policy.URLs.Blocked = append(policy.URLs.Blocked, textListValues(lines)...)
		case "exceptionurllist":
			policy.URLs.Exceptions = append(policy.URLs.Exceptions, textListValues(lines)...)
		case "bannedregexpurllist":
			policy.URLs.BlockRegex = append(policy.URLs.BlockRegex, regexListValues(lines)...)
		case "exceptionregexpurllist":
			policy.URLs.AllowRegex = append(policy.URLs.AllowRegex, regexListValues(lines)...)
		case "bannedextensionlist":
			policy.Files.BannedExtensions = append(policy.Files.BannedExtensions, textListValues(lines)...)
		case "exceptionextensionlist":
			policy.Files.ExceptionExtensions = append(policy.Files.ExceptionExtensions, textListValues(lines)...)
		case "bannedmimetypelist":
			policy.Files.BannedMIMEs = append(policy.Files.BannedMIMEs, textListValues(lines)...)
		case "exceptionmimetypelist":
			policy.Files.ExceptionMIMEs = append(policy.Files.ExceptionMIMEs, textListValues(lines)...)
		case "bannedfilenamelist":
			policy.Files.BannedFilenames = append(policy.Files.BannedFilenames, textListValues(lines)...)
		case "exceptionfilenamelist":
			policy.Files.ExceptionFilenames = append(policy.Files.ExceptionFilenames, textListValues(lines)...)
		case "downloadmanager":
			err := parseDownloadManagerFile(lines, &policy)
			if err != nil {
				return proxy.PolicyConfig{}, err
			}
		case "bannedheaderlist":
			policy.Headers.Banned = append(policy.Headers.Banned, textListValues(lines)...)
		case "exceptionheaderlist":
			policy.Headers.Exception = append(policy.Headers.Exception, textListValues(lines)...)
		case "bannedcookiephraselist":
			policy.Cookies.Banned = append(policy.Cookies.Banned, textListValues(lines)...)
		case "exceptioncookiephraselist":
			policy.Cookies.Exception = append(policy.Cookies.Exception, textListValues(lines)...)
		case "bannedphraselist":
			cfg.SemanticPhrases = appendUniqueStrings(cfg.SemanticPhrases, textListValues(lines))
		case "exceptionphraselist":
			cfg.SemanticExceptionPhrases = appendUniqueStrings(cfg.SemanticExceptionPhrases, textListValues(lines))
		case "weightedphraselist":
			parsed, err := parseWeightedLines(lines)
			if err != nil {
				return proxy.PolicyConfig{}, err
			}
			merged, err := mergeWeightedPhrases(cfg.SemanticWeighted, parsed)
			if err != nil {
				return proxy.PolicyConfig{}, err
			}
			cfg.SemanticWeighted = merged
		case "weightedphraseexceptions":
			parsed, err := parseWeightedLines(lines)
			if err != nil {
				return proxy.PolicyConfig{}, err
			}
			merged, err := mergeWeightedPhrases(cfg.SemanticWeightedExceptions, parsed)
			if err != nil {
				return proxy.PolicyConfig{}, err
			}
			cfg.SemanticWeightedExceptions = merged
		case "logurllist":
			policy.Log.LogURLs = append(policy.Log.LogURLs, textListValues(lines)...)
		case "exceptionlogurllist":
			policy.Log.ExceptionLogURLs = append(policy.Log.ExceptionLogURLs, textListValues(lines)...)
		case "logregexpurllist":
			policy.Log.LogRegexURLs = append(policy.Log.LogRegexURLs, regexListValues(lines)...)
		case "exceptionlogregexpurllist":
			policy.Log.ExceptionLogRegexURLs = append(policy.Log.ExceptionLogRegexURLs, regexListValues(lines)...)
		case "logregexpsitelist":
			policy.Log.LogRegexSites = append(policy.Log.LogRegexSites, regexListValues(lines)...)
		case "exceptionlogregexpsitelist":
			policy.Log.ExceptionLogRegexSites = append(policy.Log.ExceptionLogRegexSites, regexListValues(lines)...)
		case "logphraselist":
			cfg.LogPhrases = appendUniqueStrings(cfg.LogPhrases, textListValues(lines))
		case "exceptionlogphraselist":
			cfg.ExceptionLogPhrases = appendUniqueStrings(cfg.ExceptionLogPhrases, textListValues(lines))
		case "bannedclientiplist":
			for _, ln := range lines {
				if ln.Text == "" {
					continue
				}
				_, errPrefix := netip.ParsePrefix(ln.Text)
				if errPrefix != nil {
					_, errAddr := netip.ParseAddr(ln.Text)
					if errAddr != nil {
						return proxy.PolicyConfig{}, fmt.Errorf("%s:%d: invalid banned client IP/CIDR %q: %w", ln.Path, ln.Line, ln.Text, errPrefix)
					}
				}
				cfg.BannedClients = appendUniqueStrings(cfg.BannedClients, []string{ln.Text})
			}
		case "exceptionclientiplist":
			for _, ln := range lines {
				if ln.Text == "" {
					continue
				}
				_, errPrefix := netip.ParsePrefix(ln.Text)
				if errPrefix != nil {
					_, errAddr := netip.ParseAddr(ln.Text)
					if errAddr != nil {
						return proxy.PolicyConfig{}, fmt.Errorf("%s:%d: invalid exception client IP/CIDR %q: %w", ln.Path, ln.Line, ln.Text, errPrefix)
					}
				}
				cfg.ExceptionClients = appendUniqueStrings(cfg.ExceptionClients, []string{ln.Text})
			}
		case "filtergroupslist":
			cfg.FilterGroups = appendUniqueStrings(cfg.FilterGroups, textListValues(lines))
		case "e2guardianipgroups":
			for _, ln := range lines {
				parts := strings.Split(ln.Text, "=")
				if len(parts) != 2 {
					return proxy.PolicyConfig{}, fmt.Errorf("%s:%d: invalid IP group line (missing '='): %q", ln.Path, ln.Line, ln.Text)
				}
				client := strings.TrimSpace(parts[0])
				group := strings.TrimSpace(parts[1])
				if client == "" || group == "" {
					return proxy.PolicyConfig{}, fmt.Errorf("%s:%d: invalid IP group line (empty IP or group): %q", ln.Path, ln.Line, ln.Text)
				}
				cfg.IPGroupMappings = append(cfg.IPGroupMappings, IPGroupMapping{
					Client: client,
					Group:  group,
					Source: fmt.Sprintf("%s:%d", ln.Path, ln.Line),
				})
			}
		default:
			policy.Domains.Blocked = append(policy.Domains.Blocked, domainListValues(lines)...)
		}
	}

	// Resolve IP to Group mappings from e2guardianipgroups
	if len(cfg.IPGroupMappings) > 0 {
		for _, mapping := range cfg.IPGroupMappings {
			groupName := mapping.Group

			// Validate IP/CIDR structure of the client prefix
			_, errPrefix := netip.ParsePrefix(mapping.Client)
			if errPrefix != nil {
				_, errAddr := netip.ParseAddr(mapping.Client)
				if errAddr != nil {
					return proxy.PolicyConfig{}, fmt.Errorf("%s: invalid client IP/CIDR %q: %w", mapping.Source, mapping.Client, errPrefix)
				}
			}

			// If it's a numeric index (1-based), try to resolve it against FilterGroups
			var idx int
			if _, err := fmt.Sscanf(groupName, "%d", &idx); err == nil && idx > 0 {
				if idx <= len(cfg.FilterGroups) {
					groupName = cfg.FilterGroups[idx-1]
				} else {
					groupName = fmt.Sprintf("group%d", idx)
				}
			}

			// Find or create AccessProfileConfig in cfg.AccessProfiles
			found := false
			for i := range cfg.AccessProfiles {
				if cfg.AccessProfiles[i].Name == groupName {
					// Check if client is already in the profile
					alreadyIn := false
					for _, c := range cfg.AccessProfiles[i].Clients {
						if c == mapping.Client {
							alreadyIn = true
							break
						}
					}
					if !alreadyIn {
						cfg.AccessProfiles[i].Clients = append(cfg.AccessProfiles[i].Clients, mapping.Client)
					}
					found = true
					break
				}
			}
			if !found {
				cfg.AccessProfiles = append(cfg.AccessProfiles, AccessProfileConfig{
					Name:    groupName,
					Clients: []string{mapping.Client},
					Default: false,
				})
			}
		}
	}

	return policy, nil
}

// parseWeightedLines parses e2guardian-style `<phrase><weight>` entries from
// already-loaded list lines. Errors include the source file:line.
func parseWeightedLines(lines []listLine) ([]SemanticPhraseConfig, error) {
	out := make([]SemanticPhraseConfig, 0, len(lines))
	for _, ln := range lines {
		phrase, weight, err := parseWeightedLine(ln.Text)
		if err != nil {
			return nil, fmt.Errorf("%s:%d: %w", ln.Path, ln.Line, err)
		}
		out = append(out, SemanticPhraseConfig{Phrase: phrase, Weight: weight})
	}
	return out, nil
}

func textListValues(lines []listLine) []string {
	out := make([]string, 0, len(lines))
	for _, line := range lines {
		if line.Text != "" {
			out = append(out, line.Text)
		}
	}
	return out
}

func domainListValues(lines []listLine) []string {
	out := make([]string, 0, len(lines))
	for _, line := range lines {
		domain := normalizeRuleDomain(line.Text)
		if domain != "" {
			out = append(out, domain)
		}
	}
	return out
}

func regexListValues(lines []listLine) []proxy.RegexRule {
	out := make([]proxy.RegexRule, 0, len(lines))
	for _, line := range lines {
		if line.Text == "" {
			continue
		}
		out = append(out, proxy.RegexRule{
			Pattern: line.Text,
			Source:  fmt.Sprintf("%s:%d", line.Path, line.Line),
		})
	}
	return out
}

// normalizeWeightedKey produces the canonical form used to compare phrases
// across `weightedphraselist` and `weightedphraseexceptions`. Mirrors the
// case-insensitive matching of the Aho-Corasick filter so config-time
// exclusion and runtime detection use the same key space.
func normalizeWeightedKey(phrase string) string {
	return strings.ToLower(strings.TrimSpace(phrase))
}

func normalizeRuleDomain(domain string) string {
	domain = strings.TrimSpace(strings.ToLower(domain))
	domain = strings.TrimPrefix(domain, ".")
	domain = strings.TrimSuffix(domain, ".")
	if domain == "" || strings.Contains(domain, "/") {
		return ""
	}
	return domain
}

func parseDownloadManagerFile(lines []listLine, policy *proxy.PolicyConfig) error {
	for _, ln := range lines {
		parts := strings.Fields(ln.Text)
		if len(parts) != 3 {
			return fmt.Errorf("%s:%d: invalid downloadmanager rule %q (expected: [banned|exception] [ext|mime] [value])", ln.Path, ln.Line, ln.Text)
		}
		action := strings.ToLower(parts[0])
		ruleType := strings.ToLower(parts[1])
		value := parts[2]

		if action != "banned" && action != "exception" {
			return fmt.Errorf("%s:%d: unsupported downloadmanager action %q (must be 'banned' or 'exception')", ln.Path, ln.Line, parts[0])
		}

		switch ruleType {
		case "ext":
			if action == "banned" {
				policy.Files.BannedExtensions = append(policy.Files.BannedExtensions, value)
			} else {
				policy.Files.ExceptionExtensions = append(policy.Files.ExceptionExtensions, value)
			}
		case "mime":
			if action == "banned" {
				policy.Files.BannedMIMEs = append(policy.Files.BannedMIMEs, value)
			} else {
				policy.Files.ExceptionMIMEs = append(policy.Files.ExceptionMIMEs, value)
			}
		default:
			return fmt.Errorf("%s:%d: unsupported downloadmanager rule type %q (must be 'ext' or 'mime')", ln.Path, ln.Line, parts[1])
		}
	}
	return nil
}
