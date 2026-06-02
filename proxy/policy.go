package proxy

import (
	"errors"
	"fmt"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"path"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/gaissmai/bart"
)

type PolicyConfig struct {
	Domains DomainRulesConfig
	SiteIPs SiteIPRulesConfig
	URLs    URLRulesConfig
	Files   FileRulesConfig
	Headers HeaderRulesConfig
	Cookies CookieRulesConfig
	Log     LogRulesConfig
	Referer RefererRulesConfig
}

type Policy struct {
	domains *DomainRules
	siteIPs *SiteIPRules
	urls    *URLRules
	files   *FileRules
	headers *HeaderRules
	cookies *CookieRules
	log     *LogRules
	referer *RefererRules
}

type PolicyDecision struct {
	Blocked       bool
	Redirect      bool
	RedirectURL   string
	MatchType     string
	Value         string
	BypassFilters bool
}

type policyBlockError struct {
	decision PolicyDecision
}

func (e *policyBlockError) Error() string {
	return fmt.Sprintf("policy block %s=%s", e.decision.MatchType, e.decision.Value)
}

var ErrSecretExfiltrationBlocked = &policyBlockError{
	decision: PolicyDecision{
		Blocked:   true,
		MatchType: "exfiltration preventer",
		Value:     "sensitive data exfiltration blocked",
	},
}

func policyDecisionFromError(err error) (PolicyDecision, bool) {
	var blockErr *policyBlockError
	if errors.As(err, &blockErr) {
		return blockErr.decision, true
	}
	return PolicyDecision{}, false
}

func NewPolicy(cfg PolicyConfig) (*Policy, error) {
	domains, err := NewDomainRulesConfig(cfg.Domains)
	if err != nil {
		return nil, err
	}
	siteIPs, err := NewSiteIPRules(cfg.SiteIPs)
	if err != nil {
		return nil, err
	}
	urls, err := NewURLRules(cfg.URLs)
	if err != nil {
		return nil, err
	}
	files := NewFileRules(cfg.Files)
	headers, err := NewHeaderRules(cfg.Headers)
	if err != nil {
		return nil, err
	}
	cookies := NewCookieRules(cfg.Cookies)
	referer, err := NewRefererRules(cfg.Referer)
	if err != nil {
		return nil, err
	}
	log, err := NewLogRules(cfg.Log)
	if err != nil {
		return nil, err
	}
	return &Policy{
		domains: domains,
		siteIPs: siteIPs,
		urls:    urls,
		files:   files,
		headers: headers,
		cookies: cookies,
		log:     log,
		referer: referer,
	}, nil
}

func (p *Policy) RequiresResolvedSiteIP() bool {
	return p != nil && p.siteIPs != nil && p.siteIPs.hasEntries
}

func (p *Policy) EvaluateResolvedDestinationIP(host string) PolicyDecision {
	if p == nil || p.siteIPs == nil {
		return PolicyDecision{}
	}
	return p.siteIPs.Decision(host)
}

func (p *Policy) Evaluate(host string, req *http.Request, scheme string) PolicyDecision {
	return p.EvaluateRequest(host, req, scheme)
}

func (p *Policy) EvaluateRequest(host string, req *http.Request, scheme string) PolicyDecision {
	if p == nil {
		return PolicyDecision{}
	}

	var finalDecision PolicyDecision

	if p.domains != nil {
		if d := p.domains.Decision(host); d.Blocked {
			return d
		} else if d.BypassFilters {
			finalDecision = d
		}
	}
	if p.siteIPs != nil {
		if d := p.siteIPs.Decision(host); d.Blocked {
			return d
		} else if d.BypassFilters && !finalDecision.BypassFilters {
			finalDecision = d
		}
	}
	if req == nil {
		return finalDecision
	}
	rawURL := canonicalPolicyURL(req, scheme)
	if p.urls != nil {
		if d := p.urls.Decision(rawURL); d.Blocked {
			return d
		} else if d.BypassFilters && !finalDecision.BypassFilters {
			finalDecision = d
		}
	}
	if p.files != nil {
		if d := p.files.Decision(fileMatchInput{
			URL:      rawURL,
			Filename: filenameFromURL(req.URL),
		}); d.Blocked {
			return d
		} else if d.BypassFilters && !finalDecision.BypassFilters {
			finalDecision = d
		}
	}
	if p.headers != nil {
		if d := p.headers.Decision(req.Header); d.Blocked {
			return d
		} else if d.BypassFilters && !finalDecision.BypassFilters {
			finalDecision = d
		}
	}
	if p.cookies != nil {
		if d := p.cookies.Decision(requestCookieValues(req.Header)); d.Blocked {
			return d
		} else if d.BypassFilters && !finalDecision.BypassFilters {
			finalDecision = d
		}
	}
	if p.referer != nil && !finalDecision.BypassFilters {
		if d := p.referer.Decision(req.Header.Get("Referer")); d.BypassFilters {
			finalDecision = d
		}
	}
	return finalDecision
}

func (p *Policy) EvaluateResponse(resp *http.Response, scheme string) PolicyDecision {
	if p == nil || resp == nil {
		return PolicyDecision{}
	}
	filename := responseFilename(resp)
	rawURL := ""
	if resp.Request != nil {
		rawURL = canonicalPolicyURL(resp.Request, scheme)
		if filename == "" {
			filename = filenameFromURL(resp.Request.URL)
		}
	}

	var finalDecision PolicyDecision

	if p.files != nil {
		if d := p.files.Decision(fileMatchInput{
			URL:         rawURL,
			Filename:    filename,
			ContentType: resp.Header.Get("Content-Type"),
		}); d.Blocked {
			return d
		} else if d.BypassFilters {
			finalDecision = d
		}
	}
	if p.headers != nil {
		if d := p.headers.Decision(resp.Header); d.Blocked {
			return d
		} else if d.BypassFilters && !finalDecision.BypassFilters {
			finalDecision = d
		}
	}
	if p.cookies != nil {
		if d := p.cookies.Decision(responseCookieValues(resp.Header)); d.Blocked {
			return d
		} else if d.BypassFilters && !finalDecision.BypassFilters {
			finalDecision = d
		}
	}
	return finalDecision
}

type HeaderRewriteRule struct {
	Regex   *regexp.Regexp
	Replace string
}

type HeaderAddRule struct {
	UrlRegex *regexp.Regexp
	Key      string
	Val      string
}

type HeaderRulesConfig struct {
	Banned           []string
	Exception        []string
	BlockRegex       []RegexRule
	ExceptionRegex   []RegexRule
	RequestRewrites  []RegexRule
	ResponseRewrites []RegexRule
	RequestAdds      []RegexRule
}

type HeaderRules struct {
	banned           []string
	exception        []string
	blockRegex       []*regexp.Regexp
	exceptionRegex   []*regexp.Regexp
	requestRewrites  []HeaderRewriteRule
	responseRewrites []HeaderRewriteRule
	requestAdds      []HeaderAddRule
}

func NewHeaderRules(cfg HeaderRulesConfig) (*HeaderRules, error) {
	rules := &HeaderRules{
		banned:    normalizedPhrases(cfg.Banned),
		exception: normalizedPhrases(cfg.Exception),
	}
	for _, rule := range cfg.BlockRegex {
		compiled, err := compilePolicyRegex(rule)
		if err != nil {
			return nil, err
		}
		rules.blockRegex = append(rules.blockRegex, compiled)
	}
	for _, rule := range cfg.ExceptionRegex {
		compiled, err := compilePolicyRegex(rule)
		if err != nil {
			return nil, err
		}
		rules.exceptionRegex = append(rules.exceptionRegex, compiled)
	}
	for _, rule := range cfg.RequestRewrites {
		idx := strings.Index(rule.Pattern, "=>")
		var pattern, replace string
		if idx >= 0 {
			pattern = strings.TrimSpace(rule.Pattern[:idx])
			replace = strings.TrimSpace(rule.Pattern[idx+2:])
		} else {
			pattern = rule.Pattern
		}
		compiled, err := compilePolicyRegex(RegexRule{Pattern: pattern, Source: rule.Source})
		if err != nil {
			return nil, err
		}
		rules.requestRewrites = append(rules.requestRewrites, HeaderRewriteRule{Regex: compiled, Replace: replace})
	}
	for _, rule := range cfg.ResponseRewrites {
		idx := strings.Index(rule.Pattern, "=>")
		var pattern, replace string
		if idx >= 0 {
			pattern = strings.TrimSpace(rule.Pattern[:idx])
			replace = strings.TrimSpace(rule.Pattern[idx+2:])
		} else {
			pattern = rule.Pattern
		}
		compiled, err := compilePolicyRegex(RegexRule{Pattern: pattern, Source: rule.Source})
		if err != nil {
			return nil, err
		}
		rules.responseRewrites = append(rules.responseRewrites, HeaderRewriteRule{Regex: compiled, Replace: replace})
	}
	for _, rule := range cfg.RequestAdds {
		idx := strings.Index(rule.Pattern, "=>")
		var pattern, headerStr string
		if idx >= 0 {
			pattern = strings.TrimSpace(rule.Pattern[:idx])
			headerStr = strings.TrimSpace(rule.Pattern[idx+2:])
		} else {
			headerStr = rule.Pattern
		}

		colonIdx := strings.Index(headerStr, ":")
		if colonIdx <= 0 {
			return nil, fmt.Errorf("%s: invalid add header format (missing ':'): %q", rule.Source, rule.Pattern)
		}
		key := strings.TrimSpace(headerStr[:colonIdx])
		val := strings.TrimSpace(headerStr[colonIdx+1:])

		var compiled *regexp.Regexp
		if pattern != "" {
			var err error
			compiled, err = compilePolicyRegex(RegexRule{Pattern: pattern, Source: rule.Source})
			if err != nil {
				return nil, err
			}
		}
		rules.requestAdds = append(rules.requestAdds, HeaderAddRule{UrlRegex: compiled, Key: key, Val: val})
	}
	return rules, nil
}

func (r *HeaderRules) Decision(headers http.Header) PolicyDecision {
	if r == nil || len(headers) == 0 {
		return PolicyDecision{}
	}
	for key, values := range headers {
		for _, value := range values {
			rawLine := key + ": " + value
			normalizedLine := strings.ToLower(rawLine)
			if phraseListMatches(r.exception, normalizedLine) || regexListMatches(r.exceptionRegex, rawLine) {
				continue
			}
			if match := firstPhraseMatch(r.banned, normalizedLine); match != "" {
				return PolicyDecision{Blocked: true, MatchType: "header", Value: match}
			}
			for _, rx := range r.blockRegex {
				if rx.MatchString(rawLine) {
					return PolicyDecision{Blocked: true, MatchType: "header_regex", Value: rx.String()}
				}
			}
		}
	}
	return PolicyDecision{}
}

type CookieRulesConfig struct {
	Banned    []string
	Exception []string
}

type CookieRules struct {
	banned    []string
	exception []string
}

func NewCookieRules(cfg CookieRulesConfig) *CookieRules {
	return &CookieRules{
		banned:    normalizedPhrases(cfg.Banned),
		exception: normalizedPhrases(cfg.Exception),
	}
}

func (r *CookieRules) Decision(values []string) PolicyDecision {
	if r == nil || len(values) == 0 {
		return PolicyDecision{}
	}
	for _, value := range values {
		value = strings.ToLower(value)
		if phraseListMatches(r.exception, value) {
			continue
		}
		if match := firstPhraseMatch(r.banned, value); match != "" {
			return PolicyDecision{Blocked: true, MatchType: "cookie", Value: match}
		}
	}
	return PolicyDecision{}
}

func normalizedPhrases(values []string) []string {
	out := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		value = strings.ToLower(strings.TrimSpace(value))
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
}

func phraseListMatches(phrases []string, haystack string) bool {
	return firstPhraseMatch(phrases, haystack) != ""
}

func firstPhraseMatch(phrases []string, haystack string) string {
	for _, phrase := range phrases {
		if strings.Contains(haystack, phrase) {
			return phrase
		}
	}
	return ""
}

func regexListMatches(regexes []*regexp.Regexp, haystack string) bool {
	for _, rx := range regexes {
		if rx.MatchString(haystack) {
			return true
		}
	}
	return false
}

func requestCookieValues(headers http.Header) []string {
	return headers.Values("Cookie")
}

func responseCookieValues(headers http.Header) []string {
	return headers.Values("Set-Cookie")
}

type SiteIPRulesConfig struct {
	Blocked    []string
	Exceptions []string
	Grey       []string
}

type SiteIPRules struct {
	blocked    bart.Table[bool]
	exceptions bart.Table[bool]
	grey       bart.Table[bool]
	hasEntries bool
}

func NewSiteIPRules(cfg SiteIPRulesConfig) (*SiteIPRules, error) {
	rules := &SiteIPRules{
		hasEntries: len(cfg.Blocked)+len(cfg.Exceptions)+len(cfg.Grey) > 0,
	}
	if err := insertIPPrefixes(&rules.blocked, cfg.Blocked); err != nil {
		return nil, fmt.Errorf("bannedsiteiplist: %w", err)
	}
	if err := insertIPPrefixes(&rules.exceptions, cfg.Exceptions); err != nil {
		return nil, fmt.Errorf("exceptionsiteiplist: %w", err)
	}
	if err := insertIPPrefixes(&rules.grey, cfg.Grey); err != nil {
		return nil, fmt.Errorf("greysiteiplist: %w", err)
	}
	return rules, nil
}

func (r *SiteIPRules) Decision(host string) PolicyDecision {
	if r == nil {
		return PolicyDecision{}
	}
	host = normalizedPolicyHost(host)
	if host == "" {
		return PolicyDecision{}
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return PolicyDecision{}
	}
	if _, ok := r.exceptions.Lookup(addr); ok {
		return PolicyDecision{BypassFilters: true, MatchType: "site_ip_exception", Value: addr.String()}
	}
	if _, ok := r.grey.Lookup(addr); ok {
		return PolicyDecision{BypassFilters: false, MatchType: "site_ip_grey", Value: addr.String()}
	}
	if _, ok := r.blocked.Lookup(addr); ok {
		return PolicyDecision{Blocked: true, MatchType: "site_ip", Value: addr.String()}
	}
	return PolicyDecision{}
}

type FileRulesConfig struct {
	BannedExtensions    []string
	ExceptionExtensions []string
	BannedMIMEs         []string
	ExceptionMIMEs      []string
	BannedFilenames     []string
	ExceptionFilenames  []string
}

type FileRules struct {
	bannedExtensions    map[string]struct{}
	exceptionExtensions map[string]struct{}
	bannedMIMEs         map[string]struct{}
	exceptionMIMEs      map[string]struct{}
	bannedFilenames     map[string]struct{}
	exceptionFilenames  map[string]struct{}
}

type fileMatchInput struct {
	URL         string
	Filename    string
	ContentType string
}

func NewFileRules(cfg FileRulesConfig) *FileRules {
	return &FileRules{
		bannedExtensions:    normalizedSet(cfg.BannedExtensions, normalizeExtensionRule),
		exceptionExtensions: normalizedSet(cfg.ExceptionExtensions, normalizeExtensionRule),
		bannedMIMEs:         normalizedSet(cfg.BannedMIMEs, normalizeMIMEType),
		exceptionMIMEs:      normalizedSet(cfg.ExceptionMIMEs, normalizeMIMEType),
		bannedFilenames:     normalizedSet(cfg.BannedFilenames, normalizeFilenameRule),
		exceptionFilenames:  normalizedSet(cfg.ExceptionFilenames, normalizeFilenameRule),
	}
}

func (r *FileRules) Decision(in fileMatchInput) PolicyDecision {
	if r == nil {
		return PolicyDecision{}
	}
	filename := normalizeFilenameRule(in.Filename)
	ext := normalizeExtensionRule(filepath.Ext(filename))
	mimeType := normalizeMIMEType(in.ContentType)

	if filename != "" {
		if _, ok := r.exceptionFilenames[filename]; ok {
			return PolicyDecision{}
		}
	}
	if ext != "" {
		if _, ok := r.exceptionExtensions[ext]; ok {
			return PolicyDecision{}
		}
	}
	if mimeType != "" && mimeSetMatches(r.exceptionMIMEs, mimeType) {
		return PolicyDecision{}
	}

	if filename != "" {
		if _, ok := r.bannedFilenames[filename]; ok {
			return PolicyDecision{Blocked: true, MatchType: "filename", Value: filename}
		}
	}
	if ext != "" {
		if _, ok := r.bannedExtensions[ext]; ok {
			return PolicyDecision{Blocked: true, MatchType: "extension", Value: ext}
		}
	}
	if mimeType != "" && mimeSetMatches(r.bannedMIMEs, mimeType) {
		return PolicyDecision{Blocked: true, MatchType: "mime", Value: mimeType}
	}
	return PolicyDecision{}
}

func normalizedSet(values []string, normalize func(string) string) map[string]struct{} {
	out := make(map[string]struct{}, len(values))
	for _, value := range values {
		value = normalize(value)
		if value != "" {
			out[value] = struct{}{}
		}
	}
	return out
}

func normalizeExtensionRule(ext string) string {
	ext = strings.TrimSpace(strings.ToLower(ext))
	if ext == "" {
		return ""
	}
	ext = strings.TrimPrefix(ext, "*")
	if !strings.HasPrefix(ext, ".") {
		ext = "." + ext
	}
	return ext
}

func normalizeFilenameRule(filename string) string {
	filename = strings.TrimSpace(strings.ToLower(filename))
	if filename == "" || filename == "." || filename == "/" {
		return ""
	}
	filename = path.Base(strings.ReplaceAll(filename, "\\", "/"))
	if filename == "." || filename == "/" {
		return ""
	}
	return filename
}

func normalizeMIMEType(value string) string {
	value = strings.TrimSpace(strings.ToLower(value))
	if value == "" {
		return ""
	}
	if mediaType, _, err := mime.ParseMediaType(value); err == nil {
		value = mediaType
	}
	return value
}

func mimeSetMatches(set map[string]struct{}, value string) bool {
	if _, ok := set[value]; ok {
		return true
	}
	major, _, ok := strings.Cut(value, "/")
	if !ok || major == "" {
		return false
	}
	_, ok = set[major+"/*"]
	return ok
}

func filenameFromURL(u *url.URL) string {
	if u == nil {
		return ""
	}
	escaped := u.EscapedPath()
	if escaped == "" || escaped == "/" {
		return ""
	}
	unescaped, err := url.PathUnescape(escaped)
	if err != nil {
		unescaped = escaped
	}
	return normalizeFilenameRule(unescaped)
}

func responseFilename(resp *http.Response) string {
	if resp == nil {
		return ""
	}
	cd := resp.Header.Get("Content-Disposition")
	if cd == "" {
		return ""
	}
	_, params, err := mime.ParseMediaType(cd)
	if err != nil {
		return ""
	}
	if filename := params["filename"]; filename != "" {
		return normalizeFilenameRule(filename)
	}
	if filename := params["filename*"]; filename != "" {
		return normalizeFilenameRule(filename)
	}
	return ""
}

func (p *Policy) evaluateDomain(host string) PolicyDecision {
	if p == nil || p.domains == nil {
		return PolicyDecision{}
	}
	if decision := p.domains.Decision(host); decision.Blocked {
		return decision
	}
	return PolicyDecision{}
}

type URLRewriteRule struct {
	Regex   *regexp.Regexp
	Replace string
}

type URLRedirectRule struct {
	Regex   *regexp.Regexp
	Replace string
	Status  int
}

type URLRulesConfig struct {
	LocalExceptions []string
	LocalGrey       []string
	LocalBlocked    []string
	Exceptions      []string
	Grey            []string
	Blocked         []string
	BlockRegex      []RegexRule
	AllowRegex      []RegexRule
	Rewrites        []RegexRule
	Redirects       []RegexRule
}

type URLRules struct {
	localExceptions []string
	localGrey       []string
	localBlocked    []string
	exceptions      []string
	grey            []string
	blocked         []string
	blockRegex      []*regexp.Regexp
	allowRegex      []*regexp.Regexp
	rewrites        []URLRewriteRule
	redirects       []URLRedirectRule
}

func NewURLRules(cfg URLRulesConfig) (*URLRules, error) {
	rules := &URLRules{
		localExceptions: normalizePolicyURLs(cfg.LocalExceptions),
		localGrey:       normalizePolicyURLs(cfg.LocalGrey),
		localBlocked:    normalizePolicyURLs(cfg.LocalBlocked),
		exceptions:      normalizePolicyURLs(cfg.Exceptions),
		grey:            normalizePolicyURLs(cfg.Grey),
		blocked:         normalizePolicyURLs(cfg.Blocked),
	}
	for _, rule := range cfg.BlockRegex {
		compiled, err := compilePolicyRegex(rule)
		if err != nil {
			return nil, err
		}
		rules.blockRegex = append(rules.blockRegex, compiled)
	}
	for _, rule := range cfg.AllowRegex {
		compiled, err := compilePolicyRegex(rule)
		if err != nil {
			return nil, err
		}
		rules.allowRegex = append(rules.allowRegex, compiled)
	}
	for _, rule := range cfg.Rewrites {
		idx := strings.Index(rule.Pattern, "=>")
		var pattern, replace string
		if idx >= 0 {
			pattern = strings.TrimSpace(rule.Pattern[:idx])
			replace = strings.TrimSpace(rule.Pattern[idx+2:])
		} else {
			pattern = rule.Pattern
		}
		compiled, err := compilePolicyRegex(RegexRule{Pattern: pattern, Source: rule.Source})
		if err != nil {
			return nil, err
		}
		rules.rewrites = append(rules.rewrites, URLRewriteRule{Regex: compiled, Replace: replace})
	}
	for _, rule := range cfg.Redirects {
		idx := strings.Index(rule.Pattern, "=>")
		var pattern, replace string
		if idx >= 0 {
			pattern = strings.TrimSpace(rule.Pattern[:idx])
			replace = strings.TrimSpace(rule.Pattern[idx+2:])
		} else {
			pattern = rule.Pattern
		}
		compiled, err := compilePolicyRegex(RegexRule{Pattern: pattern, Source: rule.Source})
		if err != nil {
			return nil, err
		}
		rules.redirects = append(rules.redirects, URLRedirectRule{Regex: compiled, Replace: replace, Status: http.StatusFound})
	}
	return rules, nil
}

func (r *URLRules) Decision(rawURL string) PolicyDecision {
	if r == nil || rawURL == "" {
		return PolicyDecision{}
	}

	// 1. local exception
	for _, entry := range r.localExceptions {
		if urlRuleMatches(rawURL, entry) {
			return PolicyDecision{BypassFilters: true, MatchType: "url_local_exception", Value: entry}
		}
	}

	// 2. local grey
	for _, entry := range r.localGrey {
		if urlRuleMatches(rawURL, entry) {
			return PolicyDecision{BypassFilters: false, MatchType: "url_local_grey", Value: entry}
		}
	}

	// 3. local banned
	for _, entry := range r.localBlocked {
		if urlRuleMatches(rawURL, entry) {
			return PolicyDecision{Blocked: true, MatchType: "url_local", Value: entry}
		}
	}

	// 4. main exception
	for _, entry := range r.exceptions {
		if urlRuleMatches(rawURL, entry) {
			return PolicyDecision{BypassFilters: true, MatchType: "url_exception", Value: entry}
		}
	}
	for _, rx := range r.allowRegex {
		if rx.MatchString(rawURL) {
			return PolicyDecision{BypassFilters: true, MatchType: "url_exception_regex", Value: rx.String()}
		}
	}

	// 5. main grey
	for _, entry := range r.grey {
		if urlRuleMatches(rawURL, entry) {
			return PolicyDecision{BypassFilters: false, MatchType: "url_grey", Value: entry}
		}
	}

	// 6. main banned
	for _, entry := range r.blocked {
		if urlRuleMatches(rawURL, entry) {
			return PolicyDecision{Blocked: true, MatchType: "url", Value: entry}
		}
	}
	for _, rx := range r.blockRegex {
		if rx.MatchString(rawURL) {
			return PolicyDecision{Blocked: true, MatchType: "url_regex", Value: rx.String()}
		}
	}

	return PolicyDecision{}
}

func normalizePolicyURLs(entries []string) []string {
	out := make([]string, 0, len(entries))
	for _, entry := range entries {
		normalized := strings.TrimSpace(entry)
		if normalized == "" {
			continue
		}
		if parsed, err := url.Parse(normalized); err == nil && parsed.Scheme != "" && parsed.Host != "" {
			normalized = parsed.Scheme + "://" + strings.ToLower(parsed.Host) + parsed.EscapedPath()
			if parsed.RawQuery != "" {
				normalized += "?" + parsed.RawQuery
			}
		}
		out = append(out, normalized)
	}
	return out
}

func urlRuleMatches(rawURL, rule string) bool {
	return rawURL == rule || strings.HasPrefix(rawURL, rule)
}

func canonicalPolicyURL(req *http.Request, fallbackScheme string) string {
	if req == nil || req.URL == nil {
		return ""
	}
	scheme := strings.ToLower(req.URL.Scheme)
	if scheme == "" {
		scheme = strings.ToLower(strings.TrimSpace(fallbackScheme))
	}
	if scheme == "" {
		scheme = "http"
	}

	host := req.URL.Host
	if host == "" {
		host = req.Host
	}
	if host == "" {
		return ""
	}
	host = strings.ToLower(host)
	if splitHost, port, err := net.SplitHostPort(host); err == nil {
		splitHost = strings.ToLower(splitHost)
		if (scheme == "http" && port == "80") || (scheme == "https" && port == "443") {
			host = splitHost
		} else {
			host = net.JoinHostPort(splitHost, port)
		}
	}

	path := req.URL.EscapedPath()
	if path == "" {
		path = "/"
	}
	rawURL := scheme + "://" + host + path
	if req.URL.RawQuery != "" {
		rawURL += "?" + req.URL.RawQuery
	}
	return rawURL
}

type LogRulesConfig struct {
	LogURLs                []string
	ExceptionLogURLs       []string
	LogSites               []string
	LogSiteIPs             []string
	LogRegexURLs           []RegexRule
	ExceptionLogRegexURLs  []RegexRule
	LogRegexSites          []RegexRule
	ExceptionLogRegexSites []RegexRule
	NoLogSites             []string
	NoLogSiteIPs           []string
	NoLogURLs              []string
	NoLogRegexURLs         []RegexRule
	NoLogExtensions        []string
}

type LogRules struct {
	logURLs                []string
	exceptionLogURLs       []string
	logSites               domainTrie
	logSiteIPs             bart.Table[bool]
	logRegexURLs           []*regexp.Regexp
	exceptionLogRegexURLs  []*regexp.Regexp
	logRegexSites          []*regexp.Regexp
	exceptionLogRegexSites []*regexp.Regexp
	noLogSites             domainTrie
	noLogSiteIPs           bart.Table[bool]
	noLogURLs              []string
	noLogRegexURLs         []*regexp.Regexp
	noLogExtensions        map[string]struct{}
}

func NewLogRules(cfg LogRulesConfig) (*LogRules, error) {
	rules := &LogRules{
		logURLs:          normalizePolicyURLs(cfg.LogURLs),
		exceptionLogURLs: normalizePolicyURLs(cfg.ExceptionLogURLs),
		noLogURLs:        normalizePolicyURLs(cfg.NoLogURLs),
		noLogExtensions:  normalizedSet(cfg.NoLogExtensions, normalizeExtensionRule),
	}
	for _, site := range cfg.LogSites {
		rules.logSites.Add(site)
	}
	rules.logSites.Compile()
	for _, site := range cfg.NoLogSites {
		rules.noLogSites.Add(site)
	}
	rules.noLogSites.Compile()
	if err := insertIPPrefixes(&rules.logSiteIPs, cfg.LogSiteIPs); err != nil {
		return nil, fmt.Errorf("logsiteiplist: %w", err)
	}
	if err := insertIPPrefixes(&rules.noLogSiteIPs, cfg.NoLogSiteIPs); err != nil {
		return nil, fmt.Errorf("nologsiteiplist: %w", err)
	}
	for _, rule := range cfg.LogRegexURLs {
		compiled, err := compilePolicyRegex(rule)
		if err != nil {
			return nil, err
		}
		rules.logRegexURLs = append(rules.logRegexURLs, compiled)
	}
	for _, rule := range cfg.ExceptionLogRegexURLs {
		compiled, err := compilePolicyRegex(rule)
		if err != nil {
			return nil, err
		}
		rules.exceptionLogRegexURLs = append(rules.exceptionLogRegexURLs, compiled)
	}
	for _, rule := range cfg.LogRegexSites {
		compiled, err := compilePolicyRegex(rule)
		if err != nil {
			return nil, err
		}
		rules.logRegexSites = append(rules.logRegexSites, compiled)
	}
	for _, rule := range cfg.ExceptionLogRegexSites {
		compiled, err := compilePolicyRegex(rule)
		if err != nil {
			return nil, err
		}
		rules.exceptionLogRegexSites = append(rules.exceptionLogRegexSites, compiled)
	}
	for _, rule := range cfg.NoLogRegexURLs {
		compiled, err := compilePolicyRegex(rule)
		if err != nil {
			return nil, err
		}
		rules.noLogRegexURLs = append(rules.noLogRegexURLs, compiled)
	}
	return rules, nil
}

func (p *Policy) EvaluateLogging(host string, req *http.Request, scheme string) (shouldLog bool, suppressed bool, matchType string, listName string, matchVal string) {
	if p == nil || p.log == nil {
		return false, false, "", "", ""
	}
	rawURL := canonicalPolicyURL(req, scheme)
	host = normalizedPolicyHost(host)

	// 1. Check suppressors (exceptionlog* and e2guardian nolog* lists).
	for _, entry := range p.log.exceptionLogURLs {
		if urlRuleMatches(rawURL, entry) {
			return false, true, "url", "exceptionlogurllist", entry
		}
	}
	for _, rx := range p.log.exceptionLogRegexURLs {
		if rx.MatchString(rawURL) {
			return false, true, "url_regex", "exceptionlogregexpurllist", rx.String()
		}
	}
	for _, rx := range p.log.exceptionLogRegexSites {
		if rx.MatchString(host) {
			return false, true, "site_regex", "exceptionlogregexpsitelist", rx.String()
		}
	}
	if p.log.noLogSites.Match(host) {
		return false, true, "site", "nologsitelist", host
	}
	if ipPrefixTableMatches(&p.log.noLogSiteIPs, host) {
		return false, true, "site_ip", "nologsiteiplist", host
	}
	for _, entry := range p.log.noLogURLs {
		if urlRuleMatches(rawURL, entry) {
			return false, true, "url", "nologurllist", entry
		}
	}
	for _, rx := range p.log.noLogRegexURLs {
		if rx.MatchString(rawURL) {
			return false, true, "url_regex", "nologregexpurllist", rx.String()
		}
	}
	if ext := requestURLExtension(req); ext != "" {
		if _, ok := p.log.noLogExtensions[ext]; ok {
			return false, true, "extension", "nologextensionlist", ext
		}
	}

	// 2. Check Logs (logsitelist, logsiteiplist, logurllist, logregexpurllist, logregexpsitelist)
	if p.log.logSites.Match(host) {
		return true, false, "site", "logsitelist", host
	}
	if ipPrefixTableMatches(&p.log.logSiteIPs, host) {
		return true, false, "site_ip", "logsiteiplist", host
	}
	for _, entry := range p.log.logURLs {
		if urlRuleMatches(rawURL, entry) {
			return true, false, "url", "logurllist", entry
		}
	}
	for _, rx := range p.log.logRegexURLs {
		if rx.MatchString(rawURL) {
			return true, false, "url_regex", "logregexpurllist", rx.String()
		}
	}
	for _, rx := range p.log.logRegexSites {
		if rx.MatchString(host) {
			return true, false, "site_regex", "logregexpsitelist", rx.String()
		}
	}

	return false, false, "", "", ""
}

func normalizedPolicyHost(host string) string {
	host = strings.TrimSpace(host)
	if host == "" {
		return ""
	}
	if splitHost, _, err := net.SplitHostPort(host); err == nil {
		host = splitHost
	}
	host = strings.TrimPrefix(host, "[")
	host = strings.TrimSuffix(host, "]")
	return normalizedDomain(host)
}

func insertIPPrefixes(table *bart.Table[bool], entries []string) error {
	for _, entry := range entries {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		prefix, err := netip.ParsePrefix(entry)
		if err != nil {
			addr, addrErr := netip.ParseAddr(entry)
			if addrErr != nil {
				return fmt.Errorf("%q: %w", entry, err)
			}
			prefix = netip.PrefixFrom(addr, addr.BitLen())
		}
		table.Insert(prefix.Masked(), true)
	}
	return nil
}

func ipPrefixTableMatches(table *bart.Table[bool], host string) bool {
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return false
	}
	_, ok := table.Lookup(addr)
	return ok
}

func requestURLExtension(req *http.Request) string {
	if req == nil || req.URL == nil {
		return ""
	}
	return normalizeExtensionRule(filepath.Ext(filenameFromURL(req.URL)))
}

func (p *Policy) RewriteRequestHeaders(header http.Header) {
	if p == nil || p.headers == nil || len(p.headers.requestRewrites) == 0 {
		return
	}
	keys := make([]string, 0, len(header))
	for k := range header {
		keys = append(keys, k)
	}

	modified := false
	newHeader := make(http.Header)

	for _, key := range keys {
		isFraming := isDangerousRequestFramingHeader(key)
		values := header[key]
		for _, val := range values {
			line := key + ": " + val
			newLine := line

			if !isFraming {
				for _, rule := range p.headers.requestRewrites {
					if rule.Regex.MatchString(newLine) {
						newLine = rule.Regex.ReplaceAllString(newLine, rule.Replace)
						modified = true
					}
				}
			}

			newLine = strings.TrimSpace(newLine)
			if newLine == "" {
				modified = true
				continue
			}

			idx := strings.Index(newLine, ":")
			if idx > 0 {
				newKey := strings.TrimSpace(newLine[:idx])
				newVal := strings.TrimSpace(newLine[idx+1:])
				newHeader.Add(newKey, newVal)
			} else {
				modified = true
			}
		}
	}

	if modified {
		for k := range header {
			header.Del(k)
		}
		for k, v := range newHeader {
			header[k] = v
		}
	}
}

func (p *Policy) RewriteResponseHeaders(header http.Header) {
	if p == nil || p.headers == nil || len(p.headers.responseRewrites) == 0 {
		return
	}
	keys := make([]string, 0, len(header))
	for k := range header {
		keys = append(keys, k)
	}

	modified := false
	newHeader := make(http.Header)

	for _, key := range keys {
		isFraming := isDangerousResponseFramingHeader(key)
		values := header[key]
		for _, val := range values {
			line := key + ": " + val
			newLine := line

			if !isFraming {
				for _, rule := range p.headers.responseRewrites {
					if rule.Regex.MatchString(newLine) {
						newLine = rule.Regex.ReplaceAllString(newLine, rule.Replace)
						modified = true
					}
				}
			}

			newLine = strings.TrimSpace(newLine)
			if newLine == "" {
				modified = true
				continue
			}

			idx := strings.Index(newLine, ":")
			if idx > 0 {
				newKey := strings.TrimSpace(newLine[:idx])
				newVal := strings.TrimSpace(newLine[idx+1:])
				newHeader.Add(newKey, newVal)
			} else {
				modified = true
			}
		}
	}

	if modified {
		for k := range header {
			header.Del(k)
		}
		for k, v := range newHeader {
			header[k] = v
		}
	}
}

func (p *Policy) AddRequestHeaders(header http.Header, rawURL string) {
	if p == nil || p.headers == nil || len(p.headers.requestAdds) == 0 {
		return
	}
	for _, rule := range p.headers.requestAdds {
		if rule.UrlRegex != nil && !rule.UrlRegex.MatchString(rawURL) {
			continue
		}
		// Avoid duplicate header values for non-idempotent headers
		if header.Get(rule.Key) == rule.Val {
			continue
		}
		// Prevent adding dangerous framing headers
		if isDangerousRequestFramingHeader(rule.Key) {
			continue
		}
		header.Add(rule.Key, rule.Val)
	}
}

func isDangerousRequestFramingHeader(key string) bool {
	canonicalKey := http.CanonicalHeaderKey(key)
	return canonicalKey == "Content-Length" ||
		canonicalKey == "Transfer-Encoding" ||
		canonicalKey == "Host" ||
		canonicalKey == "Connection" ||
		canonicalKey == "Upgrade"
}

func isDangerousResponseFramingHeader(key string) bool {
	canonicalKey := http.CanonicalHeaderKey(key)
	return canonicalKey == "Content-Length" ||
		canonicalKey == "Transfer-Encoding" ||
		canonicalKey == "Connection" ||
		canonicalKey == "Upgrade"
}

func (r *URLRules) RewriteURL(rawURL string) (string, bool) {
	if r == nil || len(r.rewrites) == 0 {
		return rawURL, false
	}
	modified := false
	currentURL := rawURL
	for _, rule := range r.rewrites {
		if rule.Regex.MatchString(currentURL) {
			newURL := rule.Regex.ReplaceAllString(currentURL, rule.Replace)
			// Enforce same-host guardrail
			if getHost(newURL) == getHost(rawURL) {
				currentURL = newURL
				modified = true
			}
		}
	}
	return currentURL, modified
}

func (r *URLRules) RedirectDecision(rawURL string) (PolicyDecision, bool) {
	if r == nil || len(r.redirects) == 0 {
		return PolicyDecision{}, false
	}
	for _, rule := range r.redirects {
		if rule.Regex.MatchString(rawURL) {
			targetURL := rule.Regex.ReplaceAllString(rawURL, rule.Replace)
			status := rule.Status
			if status == 0 {
				status = http.StatusFound // 302
			}
			return PolicyDecision{
				Redirect:    true,
				RedirectURL: targetURL,
				MatchType:   "url_redirect",
				Value:       rule.Regex.String(),
			}, true
		}
	}
	return PolicyDecision{}, false
}

func getHost(rawURL string) string {
	if parsed, err := url.Parse(rawURL); err == nil {
		return strings.ToLower(parsed.Host)
	}
	return ""
}

type RefererRulesConfig struct {
	ExceptionSites   []string
	ExceptionSiteIPs []string
	ExceptionURLs    []string
}

type RefererRules struct {
	exceptionSites   *DomainMatcher
	exceptionSiteIPs bart.Table[bool]
	exceptionURLs    []string
}

func NewRefererRules(cfg RefererRulesConfig) (*RefererRules, error) {
	rules := &RefererRules{
		exceptionSites: NewDomainMatcher(cfg.ExceptionSites),
		exceptionURLs:  normalizePolicyURLs(cfg.ExceptionURLs),
	}
	if err := insertIPPrefixes(&rules.exceptionSiteIPs, cfg.ExceptionSiteIPs); err != nil {
		return nil, fmt.Errorf("refererexceptionsiteiplist: %w", err)
	}
	return rules, nil
}

func (r *RefererRules) Decision(referer string) PolicyDecision {
	if r == nil {
		return PolicyDecision{}
	}
	rawURL, host := canonicalRefererURLAndHost(referer)
	if rawURL == "" || host == "" {
		return PolicyDecision{}
	}
	if r.exceptionSites.Match(host) {
		return PolicyDecision{BypassFilters: true, MatchType: "referer_site_exception", Value: host}
	}
	if ipPrefixTableMatches(&r.exceptionSiteIPs, host) {
		return PolicyDecision{BypassFilters: true, MatchType: "referer_site_ip_exception", Value: host}
	}
	for _, entry := range r.exceptionURLs {
		if urlRuleMatches(rawURL, entry) {
			return PolicyDecision{BypassFilters: true, MatchType: "referer_url_exception", Value: entry}
		}
	}
	return PolicyDecision{}
}

func canonicalRefererURLAndHost(rawReferer string) (string, string) {
	rawReferer = strings.TrimSpace(rawReferer)
	if rawReferer == "" {
		return "", ""
	}
	parsed, err := url.Parse(rawReferer)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return "", ""
	}
	scheme := strings.ToLower(parsed.Scheme)
	host := normalizedPolicyHost(parsed.Host)
	if host == "" {
		return "", ""
	}
	urlHost := host
	if strings.Contains(host, ":") {
		urlHost = "[" + host + "]"
	}
	if splitHost, port, err := net.SplitHostPort(parsed.Host); err == nil {
		splitHost = normalizedPolicyHost(splitHost)
		if splitHost == "" {
			return "", ""
		}
		host = splitHost
		urlHost = host
		if strings.Contains(host, ":") {
			urlHost = "[" + host + "]"
		}
		if !((scheme == "http" && port == "80") || (scheme == "https" && port == "443")) {
			urlHost = net.JoinHostPort(host, port)
		}
	}
	canonical := scheme + "://" + urlHost + parsed.EscapedPath()
	if parsed.RawQuery != "" {
		canonical += "?" + parsed.RawQuery
	}
	return canonical, host
}
