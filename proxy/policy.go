package proxy

import (
	"mime"
	"net"
	"net/http"
	"net/url"
	"path"
	"path/filepath"
	"regexp"
	"strings"
)

type PolicyConfig struct {
	Domains DomainRulesConfig
	URLs    URLRulesConfig
	Files   FileRulesConfig
	Headers HeaderRulesConfig
	Cookies CookieRulesConfig
	Log     LogRulesConfig
}

type Policy struct {
	domains *DomainRules
	urls    *URLRules
	files   *FileRules
	headers *HeaderRules
	cookies *CookieRules
	log     *LogRules
}

type PolicyDecision struct {
	Blocked   bool
	MatchType string
	Value     string
}

func NewPolicy(cfg PolicyConfig) (*Policy, error) {
	domains, err := NewDomainRulesConfig(cfg.Domains)
	if err != nil {
		return nil, err
	}
	urls, err := NewURLRules(cfg.URLs)
	if err != nil {
		return nil, err
	}
	files := NewFileRules(cfg.Files)
	headers := NewHeaderRules(cfg.Headers)
	cookies := NewCookieRules(cfg.Cookies)
	log, err := NewLogRules(cfg.Log)
	if err != nil {
		return nil, err
	}
	return &Policy{
		domains: domains,
		urls:    urls,
		files:   files,
		headers: headers,
		cookies: cookies,
		log:     log,
	}, nil
}

func (p *Policy) Evaluate(host string, req *http.Request, scheme string) PolicyDecision {
	return p.EvaluateRequest(host, req, scheme)
}

func (p *Policy) EvaluateRequest(host string, req *http.Request, scheme string) PolicyDecision {
	if p == nil {
		return PolicyDecision{}
	}
	if p.domains != nil {
		if decision := p.domains.Decision(host); decision.Blocked {
			return decision
		}
	}
	if req == nil {
		return PolicyDecision{}
	}
	rawURL := canonicalPolicyURL(req, scheme)
	if p.urls != nil {
		if decision := p.urls.Decision(rawURL); decision.Blocked {
			return decision
		}
	}
	if p.files != nil {
		if decision := p.files.Decision(fileMatchInput{
			URL:      rawURL,
			Filename: filenameFromURL(req.URL),
		}); decision.Blocked {
			return decision
		}
	}
	if p.headers != nil {
		if decision := p.headers.Decision(req.Header); decision.Blocked {
			return decision
		}
	}
	if p.cookies != nil {
		if decision := p.cookies.Decision(requestCookieValues(req.Header)); decision.Blocked {
			return decision
		}
	}
	return PolicyDecision{}
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
	if p.files != nil {
		if decision := p.files.Decision(fileMatchInput{
			URL:         rawURL,
			Filename:    filename,
			ContentType: resp.Header.Get("Content-Type"),
		}); decision.Blocked {
			return decision
		}
	}
	if p.headers != nil {
		if decision := p.headers.Decision(resp.Header); decision.Blocked {
			return decision
		}
	}
	if p.cookies != nil {
		if decision := p.cookies.Decision(responseCookieValues(resp.Header)); decision.Blocked {
			return decision
		}
	}
	return PolicyDecision{}
}

type HeaderRulesConfig struct {
	Banned    []string
	Exception []string
}

type HeaderRules struct {
	banned    []string
	exception []string
}

func NewHeaderRules(cfg HeaderRulesConfig) *HeaderRules {
	return &HeaderRules{
		banned:    normalizedPhrases(cfg.Banned),
		exception: normalizedPhrases(cfg.Exception),
	}
}

func (r *HeaderRules) Decision(headers http.Header) PolicyDecision {
	if r == nil || len(headers) == 0 {
		return PolicyDecision{}
	}
	for key, values := range headers {
		for _, value := range values {
			line := strings.ToLower(key + ": " + value)
			if phraseListMatches(r.exception, line) {
				continue
			}
			if match := firstPhraseMatch(r.banned, line); match != "" {
				return PolicyDecision{Blocked: true, MatchType: "header", Value: match}
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

func requestCookieValues(headers http.Header) []string {
	return headers.Values("Cookie")
}

func responseCookieValues(headers http.Header) []string {
	return headers.Values("Set-Cookie")
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

type URLRulesConfig struct {
	Blocked    []string
	Exceptions []string
	BlockRegex []RegexRule
	AllowRegex []RegexRule
}

type URLRules struct {
	blocked    []string
	exceptions []string
	blockRegex []*regexp.Regexp
	allowRegex []*regexp.Regexp
}

func NewURLRules(cfg URLRulesConfig) (*URLRules, error) {
	rules := &URLRules{
		blocked:    normalizePolicyURLs(cfg.Blocked),
		exceptions: normalizePolicyURLs(cfg.Exceptions),
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
	return rules, nil
}

func (r *URLRules) Decision(rawURL string) PolicyDecision {
	if r == nil || rawURL == "" {
		return PolicyDecision{}
	}
	for _, entry := range r.exceptions {
		if urlRuleMatches(rawURL, entry) {
			return PolicyDecision{}
		}
	}
	for _, rx := range r.allowRegex {
		if rx.MatchString(rawURL) {
			return PolicyDecision{}
		}
	}
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
	LogRegexURLs           []RegexRule
	ExceptionLogRegexURLs  []RegexRule
	LogRegexSites          []RegexRule
	ExceptionLogRegexSites []RegexRule
}

type LogRules struct {
	logURLs                []string
	exceptionLogURLs       []string
	logRegexURLs           []*regexp.Regexp
	exceptionLogRegexURLs  []*regexp.Regexp
	logRegexSites          []*regexp.Regexp
	exceptionLogRegexSites []*regexp.Regexp
}

func NewLogRules(cfg LogRulesConfig) (*LogRules, error) {
	rules := &LogRules{
		logURLs:          normalizePolicyURLs(cfg.LogURLs),
		exceptionLogURLs: normalizePolicyURLs(cfg.ExceptionLogURLs),
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
	return rules, nil
}

func (p *Policy) EvaluateLogging(host string, req *http.Request, scheme string) (shouldLog bool, suppressed bool, matchType string, listName string, matchVal string) {
	if p == nil || p.log == nil {
		return false, false, "", "", ""
	}
	rawURL := canonicalPolicyURL(req, scheme)

	// 1. Check Exceptions (exceptionlogurllist, exceptionlogregexpurllist, exceptionlogregexpsitelist)
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

	// 2. Check Logs (logurllist, logregexpurllist, logregexpsitelist)
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
