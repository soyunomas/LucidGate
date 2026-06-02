package main

import (
	"fmt"
	"net/netip"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"lucidgate/proxy"
)

type e2TimeBand struct {
	path  string
	line  int
	days  [7]bool
	start int
	end   int
}

type scheduleInterval struct {
	start int
	end   int
}

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
	var timeBands []e2TimeBand
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
		case "localexceptionsitelist":
			policy.Domains.LocalExceptions = append(policy.Domains.LocalExceptions, domainListValues(lines)...)
		case "localgreysitelist", "localsemiexceptionsitelist":
			policy.Domains.LocalGrey = append(policy.Domains.LocalGrey, domainListValues(lines)...)
		case "localbannedsitelist":
			policy.Domains.LocalBlocked = append(policy.Domains.LocalBlocked, domainListValues(lines)...)
		case "greysitelist", "semiexceptionsitelist":
			policy.Domains.Grey = append(policy.Domains.Grey, domainListValues(lines)...)
		case "bannedregexpsitelist":
			policy.Domains.BlockRegex = append(policy.Domains.BlockRegex, regexListValues(lines)...)
		case "exceptionregexpsitelist":
			policy.Domains.AllowRegex = append(policy.Domains.AllowRegex, regexListValues(lines)...)
		case "refererexceptionsitelist":
			policy.Referer.ExceptionSites = append(policy.Referer.ExceptionSites, domainListValues(lines)...)
		case "bannedsiteiplist", "localbannedsiteiplist":
			ips, err := ipListValues(lines)
			if err != nil {
				return proxy.PolicyConfig{}, err
			}
			policy.SiteIPs.Blocked = append(policy.SiteIPs.Blocked, ips...)
		case "exceptionsiteiplist", "localexceptionsiteiplist":
			ips, err := ipListValues(lines)
			if err != nil {
				return proxy.PolicyConfig{}, err
			}
			policy.SiteIPs.Exceptions = append(policy.SiteIPs.Exceptions, ips...)
		case "refererexceptionsiteiplist":
			ips, err := ipListValues(lines)
			if err != nil {
				return proxy.PolicyConfig{}, err
			}
			policy.Referer.ExceptionSiteIPs = append(policy.Referer.ExceptionSiteIPs, ips...)
		case "greysiteiplist", "localgreysiteiplist", "semiexceptionsiteiplist", "localsemiexceptionsiteiplist":
			ips, err := ipListValues(lines)
			if err != nil {
				return proxy.PolicyConfig{}, err
			}
			policy.SiteIPs.Grey = append(policy.SiteIPs.Grey, ips...)
		case "bannedurllist":
			policy.URLs.Blocked = append(policy.URLs.Blocked, textListValues(lines)...)
		case "exceptionurllist":
			policy.URLs.Exceptions = append(policy.URLs.Exceptions, textListValues(lines)...)
		case "refererexceptionurllist":
			policy.Referer.ExceptionURLs = append(policy.Referer.ExceptionURLs, textListValues(lines)...)
		case "localexceptionurllist":
			policy.URLs.LocalExceptions = append(policy.URLs.LocalExceptions, textListValues(lines)...)
		case "localgreyurllist":
			policy.URLs.LocalGrey = append(policy.URLs.LocalGrey, textListValues(lines)...)
		case "localbannedurllist":
			policy.URLs.LocalBlocked = append(policy.URLs.LocalBlocked, textListValues(lines)...)
		case "greyurllist":
			policy.URLs.Grey = append(policy.URLs.Grey, textListValues(lines)...)
		case "bannedregexpurllist":
			policy.URLs.BlockRegex = append(policy.URLs.BlockRegex, regexListValues(lines)...)
		case "exceptionregexpurllist":
			policy.URLs.AllowRegex = append(policy.URLs.AllowRegex, regexListValues(lines)...)
		case "urlregexplist":
			policy.URLs.Rewrites = append(policy.URLs.Rewrites, regexListValues(lines)...)
		case "urlredirectregexplist":
			policy.URLs.Redirects = append(policy.URLs.Redirects, regexListValues(lines)...)
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
		case "bannedregexpheaderlist":
			policy.Headers.BlockRegex = append(policy.Headers.BlockRegex, regexListValues(lines)...)
		case "exceptionregexpheaderlist":
			policy.Headers.ExceptionRegex = append(policy.Headers.ExceptionRegex, regexListValues(lines)...)
		case "headerregexplist":
			policy.Headers.RequestRewrites = append(policy.Headers.RequestRewrites, regexListValues(lines)...)
		case "addheaderregexplist":
			policy.Headers.RequestAdds = append(policy.Headers.RequestAdds, regexListValues(lines)...)
		case "responseheaderregexplist":
			policy.Headers.ResponseRewrites = append(policy.Headers.ResponseRewrites, regexListValues(lines)...)
		case "bannedcookiephraselist":
			policy.Cookies.Banned = append(policy.Cookies.Banned, textListValues(lines)...)
		case "exceptioncookiephraselist":
			policy.Cookies.Exception = append(policy.Cookies.Exception, textListValues(lines)...)
		case "bannedphraselist", "oldbannedphraselist":
			cfg.SemanticPhrases = appendUniqueStrings(cfg.SemanticPhrases, textListValues(lines))
		case "exceptionphraselist", "oldexceptionphraselist":
			cfg.SemanticExceptionPhrases = appendUniqueStrings(cfg.SemanticExceptionPhrases, textListValues(lines))
		case "weightedphraselist", "oldweightedphraselist":
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
		case "logsitelist":
			policy.Log.LogSites = append(policy.Log.LogSites, domainListValues(lines)...)
		case "logsiteiplist":
			ips, err := ipListValues(lines)
			if err != nil {
				return proxy.PolicyConfig{}, err
			}
			policy.Log.LogSiteIPs = append(policy.Log.LogSiteIPs, ips...)
		case "nologsitelist":
			policy.Log.NoLogSites = append(policy.Log.NoLogSites, domainListValues(lines)...)
		case "nologsiteiplist":
			ips, err := ipListValues(lines)
			if err != nil {
				return proxy.PolicyConfig{}, err
			}
			policy.Log.NoLogSiteIPs = append(policy.Log.NoLogSiteIPs, ips...)
		case "nologurllist":
			policy.Log.NoLogURLs = append(policy.Log.NoLogURLs, textListValues(lines)...)
		case "nologregexpurllist":
			policy.Log.NoLogRegexURLs = append(policy.Log.NoLogRegexURLs, regexListValues(lines)...)
		case "nologextensionlist":
			policy.Log.NoLogExtensions = append(policy.Log.NoLogExtensions, textListValues(lines)...)
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
		case "nocheckcertsitelist":
			cfg.NoCheckCertSites = appendUniqueStrings(cfg.NoCheckCertSites, domainListValues(lines))
		case "nocheckcertsiteiplist":
			ips, err := ipListValues(lines)
			if err != nil {
				return proxy.PolicyConfig{}, err
			}
			cfg.NoCheckCertSiteIPs = appendUniqueStrings(cfg.NoCheckCertSiteIPs, ips)
		case "greysslsitelist", "localgreysslsitelist":
			cfg.GreySSLSites = appendUniqueStrings(cfg.GreySSLSites, domainListValues(lines))
		case "greysslsiteiplist", "localgreysslsiteiplist":
			ips, err := ipListValues(lines)
			if err != nil {
				return proxy.PolicyConfig{}, err
			}
			cfg.GreySSLSiteIPs = appendUniqueStrings(cfg.GreySSLSiteIPs, ips)
		case "alertcategorylist":
			cfg.AlertCategories = appendUniqueStrings(cfg.AlertCategories, textListValues(lines))
		case "allowedtldlist":
			policy.Domains.AllowedTLDs = append(policy.Domains.AllowedTLDs, domainListValues(lines)...)
		case "blanketblocktldlist":
			policy.Domains.BlanketBlockTLDs = append(policy.Domains.BlanketBlockTLDs, domainListValues(lines)...)
		case "blankettimelist", "bannedtimelist":
			parsed, err := parseE2GuardianTimeBands(lines)
			if err != nil {
				return proxy.PolicyConfig{}, err
			}
			timeBands = append(timeBands, parsed...)
		default:
			policy.Domains.Blocked = append(policy.Domains.Blocked, domainListValues(lines)...)
		}
	}
	if len(timeBands) > 0 {
		windows, err := restrictScheduleWindowsByTimeBands(cfg.ScheduleWindows, cfg.AccessProfiles, timeBands)
		if err != nil {
			return proxy.PolicyConfig{}, err
		}
		cfg.ScheduleWindows = windows
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

func ipListValues(lines []listLine) ([]string, error) {
	out := make([]string, 0, len(lines))
	for _, ln := range lines {
		value := strings.TrimSpace(ln.Text)
		if value == "" {
			continue
		}
		_, errPrefix := netip.ParsePrefix(value)
		if errPrefix != nil {
			_, errAddr := netip.ParseAddr(value)
			if errAddr != nil {
				return nil, fmt.Errorf("%s:%d: invalid IP/CIDR %q: %w", ln.Path, ln.Line, value, errPrefix)
			}
		}
		out = append(out, value)
	}
	return out, nil
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

func parseE2GuardianTimeBands(lines []listLine) ([]e2TimeBand, error) {
	out := make([]e2TimeBand, 0, len(lines))
	for _, ln := range lines {
		if ln.Text == "" {
			continue
		}
		fields := strings.Fields(ln.Text)
		if len(fields) != 5 {
			return nil, fmt.Errorf("%s:%d: invalid timelist rule %q (expected: start_hour start_min end_hour end_min days)", ln.Path, ln.Line, ln.Text)
		}
		startHour, err := parseE2TimePart(fields[0], 0, 23)
		if err != nil {
			return nil, fmt.Errorf("%s:%d: invalid start hour %q: %w", ln.Path, ln.Line, fields[0], err)
		}
		startMin, err := parseE2TimePart(fields[1], 0, 59)
		if err != nil {
			return nil, fmt.Errorf("%s:%d: invalid start minute %q: %w", ln.Path, ln.Line, fields[1], err)
		}
		endHour, err := parseE2TimePart(fields[2], 0, 23)
		if err != nil {
			return nil, fmt.Errorf("%s:%d: invalid end hour %q: %w", ln.Path, ln.Line, fields[2], err)
		}
		endMin, err := parseE2TimePart(fields[3], 0, 59)
		if err != nil {
			return nil, fmt.Errorf("%s:%d: invalid end minute %q: %w", ln.Path, ln.Line, fields[3], err)
		}
		var days [7]bool
		for _, ch := range fields[4] {
			day, ok := e2GuardianDayToWeekday(ch)
			if !ok {
				return nil, fmt.Errorf("%s:%d: invalid timelist day %q in %q", ln.Path, ln.Line, ch, fields[4])
			}
			days[day] = true
		}
		if days == [7]bool{} {
			return nil, fmt.Errorf("%s:%d: timelist days cannot be empty", ln.Path, ln.Line)
		}
		out = append(out, e2TimeBand{
			path:  ln.Path,
			line:  ln.Line,
			days:  days,
			start: startHour*60 + startMin,
			end:   endHour*60 + endMin + 1,
		})
	}
	return out, nil
}

func parseE2TimePart(raw string, min, max int) (int, error) {
	value, err := strconv.Atoi(raw)
	if err != nil {
		return 0, err
	}
	if value < min || value > max {
		return 0, fmt.Errorf("value must be between %d and %d", min, max)
	}
	return value, nil
}

func e2GuardianDayToWeekday(ch rune) (int, bool) {
	switch ch {
	case '0':
		return int(time.Monday), true
	case '1':
		return int(time.Tuesday), true
	case '2':
		return int(time.Wednesday), true
	case '3':
		return int(time.Thursday), true
	case '4':
		return int(time.Friday), true
	case '5':
		return int(time.Saturday), true
	case '6':
		return int(time.Sunday), true
	default:
		return 0, false
	}
}

func restrictScheduleWindowsByTimeBands(windows []ScheduleWindowConfig, profiles []AccessProfileConfig, bands []e2TimeBand) ([]ScheduleWindowConfig, error) {
	profileNames := scheduleProfileNames(windows, profiles)
	blocked := blockedIntervalsByDay(bands)
	out := make([]ScheduleWindowConfig, 0, len(windows)+len(profileNames)*7)
	for _, profile := range profileNames {
		allowed, err := allowedIntervalsByDay(profile, windows)
		if err != nil {
			return nil, err
		}
		for day := range allowed {
			allowed[day] = subtractIntervals(allowed[day], blocked[day])
			for _, interval := range allowed[day] {
				if interval.start >= interval.end {
					continue
				}
				out = append(out, ScheduleWindowConfig{
					Profile: profile,
					Days:    []string{weekdayName(day)},
					Start:   minuteClock(interval.start),
					End:     minuteClock(interval.end),
				})
			}
		}
	}
	return out, nil
}

func scheduleProfileNames(windows []ScheduleWindowConfig, profiles []AccessProfileConfig) []string {
	seen := make(map[string]bool, len(windows)+len(profiles)+1)
	out := make([]string, 0, len(windows)+len(profiles)+1)
	add := func(profile string) {
		profile = strings.TrimSpace(profile)
		if profile == "" || seen[profile] {
			return
		}
		seen[profile] = true
		out = append(out, profile)
	}
	for _, profile := range profiles {
		add(profile.Name)
	}
	for _, window := range windows {
		add(window.Profile)
	}
	if len(out) == 0 {
		add("default")
	}
	return out
}

func blockedIntervalsByDay(bands []e2TimeBand) [7][]scheduleInterval {
	var blocked [7][]scheduleInterval
	for _, band := range bands {
		for day, active := range band.days {
			if !active {
				continue
			}
			if band.end > band.start {
				blocked[day] = append(blocked[day], scheduleInterval{start: band.start, end: minInt(band.end, 24*60)})
				continue
			}
			blocked[day] = append(blocked[day], scheduleInterval{start: band.start, end: 24 * 60})
			nextDay := (day + 1) % 7
			if band.end > 0 {
				blocked[nextDay] = append(blocked[nextDay], scheduleInterval{start: 0, end: band.end})
			}
		}
	}
	return blocked
}

func allowedIntervalsByDay(profile string, windows []ScheduleWindowConfig) ([7][]scheduleInterval, error) {
	var allowed [7][]scheduleInterval
	var hasProfileWindows bool
	for _, window := range windows {
		if window.Profile != profile {
			continue
		}
		hasProfileWindows = true
		start, startOK := parseScheduleClockMinute(window.Start)
		end, endOK := parseScheduleClockMinute(window.End)
		if !startOK || !endOK || end <= start {
			return allowed, fmt.Errorf("schedule profile %s: invalid window %s-%s", profile, window.Start, window.End)
		}
		days, err := scheduleWindowDays(window.Days)
		if err != nil {
			return allowed, fmt.Errorf("schedule profile %s: %w", profile, err)
		}
		for day, active := range days {
			if active {
				allowed[day] = append(allowed[day], scheduleInterval{start: start, end: end})
			}
		}
	}
	if !hasProfileWindows {
		for day := range allowed {
			allowed[day] = []scheduleInterval{{start: 0, end: 24 * 60}}
		}
	}
	return allowed, nil
}

func scheduleWindowDays(days []string) ([7]bool, error) {
	var out [7]bool
	if len(days) == 0 {
		for day := range out {
			out[day] = true
		}
		return out, nil
	}
	for _, raw := range days {
		if day, ok := scheduleWeekday(raw); ok {
			out[day] = true
			continue
		}
		return out, fmt.Errorf("invalid weekday %q", raw)
	}
	return out, nil
}

func scheduleWeekday(value string) (int, bool) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "sun", "sunday":
		return int(time.Sunday), true
	case "mon", "monday":
		return int(time.Monday), true
	case "tue", "tues", "tuesday":
		return int(time.Tuesday), true
	case "wed", "wednesday":
		return int(time.Wednesday), true
	case "thu", "thur", "thurs", "thursday":
		return int(time.Thursday), true
	case "fri", "friday":
		return int(time.Friday), true
	case "sat", "saturday":
		return int(time.Saturday), true
	default:
		return 0, false
	}
}

func subtractIntervals(allowed, blocked []scheduleInterval) []scheduleInterval {
	out := append([]scheduleInterval(nil), allowed...)
	for _, block := range blocked {
		next := out[:0]
		for _, cur := range out {
			if block.end <= cur.start || block.start >= cur.end {
				next = append(next, cur)
				continue
			}
			if block.start > cur.start {
				next = append(next, scheduleInterval{start: cur.start, end: block.start})
			}
			if block.end < cur.end {
				next = append(next, scheduleInterval{start: block.end, end: cur.end})
			}
		}
		out = append([]scheduleInterval(nil), next...)
	}
	return out
}

func parseScheduleClockMinute(value string) (int, bool) {
	hourText, minuteText, ok := strings.Cut(strings.TrimSpace(value), ":")
	if !ok {
		return 0, false
	}
	hour, err := strconv.Atoi(hourText)
	if err != nil {
		return 0, false
	}
	minute, err := strconv.Atoi(minuteText)
	if err != nil {
		return 0, false
	}
	if hour == 24 && minute == 0 {
		return 24 * 60, true
	}
	if hour < 0 || hour > 23 || minute < 0 || minute > 59 {
		return 0, false
	}
	return hour*60 + minute, true
}

func weekdayName(day int) string {
	switch time.Weekday(day) {
	case time.Sunday:
		return "sun"
	case time.Monday:
		return "mon"
	case time.Tuesday:
		return "tue"
	case time.Wednesday:
		return "wed"
	case time.Thursday:
		return "thu"
	case time.Friday:
		return "fri"
	case time.Saturday:
		return "sat"
	default:
		return ""
	}
}

func minuteClock(minute int) string {
	if minute >= 24*60 {
		return "24:00"
	}
	return fmt.Sprintf("%02d:%02d", minute/60, minute%60)
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
