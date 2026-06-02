package proxy

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestPolicyGreyAndExceptionBypass(t *testing.T) {
	policy, err := NewPolicy(PolicyConfig{
		Domains: DomainRulesConfig{
			Exceptions: []string{"exception.com"},
			Grey:       []string{"grey.com"},
			Blocked:    []string{"banned.com"},
		},
		URLs: URLRulesConfig{
			Exceptions: []string{"https://example.com/bypass"},
			Grey:       []string{"https://example.com/grey"},
			Blocked:    []string{"https://example.com/banned"},
		},
	})
	if err != nil {
		t.Fatalf("NewPolicy() error = %v", err)
	}

	// 1. Exception domain (should have BypassFilters: true)
	req1 := httptest.NewRequest(http.MethodGet, "https://exception.com/page", nil)
	dec1 := policy.Evaluate("exception.com", req1, "https")
	if dec1.Blocked {
		t.Errorf("exception.com should NOT be blocked")
	}
	if !dec1.BypassFilters {
		t.Errorf("exception.com should have BypassFilters: true")
	}

	// 2. Grey domain (should have BypassFilters: false)
	req2 := httptest.NewRequest(http.MethodGet, "https://grey.com/page", nil)
	dec2 := policy.Evaluate("grey.com", req2, "https")
	if dec2.Blocked {
		t.Errorf("grey.com should NOT be blocked")
	}
	if dec2.BypassFilters {
		t.Errorf("grey.com should have BypassFilters: false")
	}

	// 3. Exception URL (should have BypassFilters: true)
	req3 := httptest.NewRequest(http.MethodGet, "https://example.com/bypass", nil)
	dec3 := policy.Evaluate("example.com", req3, "https")
	if dec3.Blocked {
		t.Errorf("example.com/bypass should NOT be blocked")
	}
	if !dec3.BypassFilters {
		t.Errorf("example.com/bypass should have BypassFilters: true")
	}

	// 4. Grey URL (should have BypassFilters: false)
	req4 := httptest.NewRequest(http.MethodGet, "https://example.com/grey", nil)
	dec4 := policy.Evaluate("example.com", req4, "https")
	if dec4.Blocked {
		t.Errorf("example.com/grey should NOT be blocked")
	}
	if dec4.BypassFilters {
		t.Errorf("example.com/grey should have BypassFilters: false")
	}
}

func TestPolicyRefererExceptionsBypassFilters(t *testing.T) {
	policy, err := NewPolicy(PolicyConfig{
		Domains: DomainRulesConfig{
			Blocked: []string{"blocked.test"},
		},
		Referer: RefererRulesConfig{
			ExceptionSites:   []string{"trusted-ref.test"},
			ExceptionSiteIPs: []string{"198.51.100.0/24", "2001:db8::/32"},
			ExceptionURLs:    []string{"https://partner.test/allowed"},
		},
	})
	if err != nil {
		t.Fatalf("NewPolicy() error = %v", err)
	}

	reqSite := httptest.NewRequest(http.MethodGet, "https://target.test/page", nil)
	reqSite.Header.Set("Referer", "https://sub.trusted-ref.test/source")
	if decision := policy.Evaluate("target.test", reqSite, "https"); !decision.BypassFilters || decision.MatchType != "referer_site_exception" {
		t.Fatalf("site referer decision = %#v, want referer bypass", decision)
	}

	reqURL := httptest.NewRequest(http.MethodGet, "https://target.test/page", nil)
	reqURL.Header.Set("Referer", "https://partner.test/allowed/path?q=1")
	if decision := policy.Evaluate("target.test", reqURL, "https"); !decision.BypassFilters || decision.MatchType != "referer_url_exception" {
		t.Fatalf("url referer decision = %#v, want referer bypass", decision)
	}

	reqIP := httptest.NewRequest(http.MethodGet, "https://target.test/page", nil)
	reqIP.Header.Set("Referer", "https://198.51.100.42/source")
	if decision := policy.Evaluate("target.test", reqIP, "https"); !decision.BypassFilters || decision.MatchType != "referer_site_ip_exception" {
		t.Fatalf("ip referer decision = %#v, want referer bypass", decision)
	}

	reqIPv6 := httptest.NewRequest(http.MethodGet, "https://target.test/page", nil)
	reqIPv6.Header.Set("Referer", "https://[2001:db8::42]/source")
	if decision := policy.Evaluate("target.test", reqIPv6, "https"); !decision.BypassFilters || decision.MatchType != "referer_site_ip_exception" {
		t.Fatalf("ipv6 referer decision = %#v, want referer bypass", decision)
	}

	reqBlocked := httptest.NewRequest(http.MethodGet, "https://blocked.test/page", nil)
	reqBlocked.Header.Set("Referer", "https://trusted-ref.test/source")
	if decision := policy.Evaluate("blocked.test", reqBlocked, "https"); !decision.Blocked || decision.MatchType != "domain" {
		t.Fatalf("blocked host decision = %#v, want domain block to win", decision)
	}

	reqMalformed := httptest.NewRequest(http.MethodGet, "https://target.test/page", nil)
	reqMalformed.Header.Set("Referer", "/relative-only")
	if decision := policy.Evaluate("target.test", reqMalformed, "https"); decision.BypassFilters || decision.Blocked {
		t.Fatalf("malformed referer decision = %#v, want no decision", decision)
	}
}

func TestPolicyURLExceptionsOverrideBans(t *testing.T) {
	policy, err := NewPolicy(PolicyConfig{
		URLs: URLRulesConfig{
			Blocked:    []string{"https://example.com/private"},
			Exceptions: []string{"https://example.com/private/allowed"},
			BlockRegex: []RegexRule{{Pattern: `/classified($|\?)`}},
			AllowRegex: []RegexRule{{Pattern: `/classified\?ticket=ok$`}},
		},
	})
	if err != nil {
		t.Fatalf("NewPolicy() error = %v", err)
	}

	blockedReq := httptest.NewRequest(http.MethodGet, "https://example.com/private/report?q=1", nil)
	if decision := policy.Evaluate("example.com", blockedReq, "https"); !decision.Blocked || decision.MatchType != "url" {
		t.Fatalf("private decision = %#v, want URL block", decision)
	}
	allowedReq := httptest.NewRequest(http.MethodGet, "https://example.com/private/allowed/report", nil)
	if decision := policy.Evaluate("example.com", allowedReq, "https"); decision.Blocked {
		t.Fatalf("allowed decision = %#v, want allowed", decision)
	}
	regexBlockedReq := httptest.NewRequest(http.MethodGet, "https://example.com/classified?x=1", nil)
	if decision := policy.Evaluate("example.com", regexBlockedReq, "https"); !decision.Blocked || decision.MatchType != "url_regex" {
		t.Fatalf("regex decision = %#v, want regex block", decision)
	}
	regexAllowedReq := httptest.NewRequest(http.MethodGet, "https://example.com/classified?ticket=ok", nil)
	if decision := policy.Evaluate("example.com", regexAllowedReq, "https"); decision.Blocked {
		t.Fatalf("regex allowed decision = %#v, want allowed", decision)
	}
}

func TestPolicyCanonicalURLUsesHostForOriginForm(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/path?q=1", nil)
	req.Host = "Example.COM:443"

	got := canonicalPolicyURL(req, "https")
	want := "https://example.com/path?q=1"
	if got != want {
		t.Fatalf("canonicalPolicyURL() = %q, want %q", got, want)
	}
}

func TestPolicyFileRulesBlockAndAllowByExtensionMIMEAndFilename(t *testing.T) {
	policy, err := NewPolicy(PolicyConfig{
		Files: FileRulesConfig{
			BannedExtensions:    []string{".exe", "zip"},
			ExceptionExtensions: []string{".ok"},
			BannedMIMEs:         []string{"application/x-msdownload", "application/zip"},
			ExceptionMIMEs:      []string{"application/signed-exchange"},
			BannedFilenames:     []string{"secret.bin"},
			ExceptionFilenames:  []string{"allowed.zip"},
		},
	})
	if err != nil {
		t.Fatalf("NewPolicy() error = %v", err)
	}

	exeReq := httptest.NewRequest(http.MethodGet, "http://example.test/download/tool.exe", nil)
	if decision := policy.EvaluateRequest("example.test", exeReq, "http"); !decision.Blocked || decision.MatchType != "extension" {
		t.Fatalf("exe decision = %#v, want extension block", decision)
	}
	allowedReq := httptest.NewRequest(http.MethodGet, "http://example.test/download/allowed.zip", nil)
	if decision := policy.EvaluateRequest("example.test", allowedReq, "http"); decision.Blocked {
		t.Fatalf("allowed filename decision = %#v, want allowed", decision)
	}
	filenameReq := httptest.NewRequest(http.MethodGet, "http://example.test/download/secret.bin", nil)
	if decision := policy.EvaluateRequest("example.test", filenameReq, "http"); !decision.Blocked || decision.MatchType != "filename" {
		t.Fatalf("filename decision = %#v, want filename block", decision)
	}

	resp := &http.Response{
		StatusCode: http.StatusOK,
		Header:     make(http.Header),
		Request:    httptest.NewRequest(http.MethodGet, "http://example.test/download/file", nil),
	}
	resp.Header.Set("Content-Type", "application/x-msdownload; charset=binary")
	if decision := policy.EvaluateResponse(resp, "http"); !decision.Blocked || decision.MatchType != "mime" {
		t.Fatalf("mime decision = %#v, want MIME block", decision)
	}
	resp.Header.Set("Content-Type", "application/signed-exchange")
	if decision := policy.EvaluateResponse(resp, "http"); decision.Blocked {
		t.Fatalf("exception MIME decision = %#v, want allowed", decision)
	}
	resp.Header.Set("Content-Disposition", `attachment; filename="secret.bin"`)
	resp.Header.Set("Content-Type", "application/octet-stream")
	if decision := policy.EvaluateResponse(resp, "http"); !decision.Blocked || decision.MatchType != "filename" {
		t.Fatalf("content-disposition decision = %#v, want filename block", decision)
	}
}

func TestPolicyHeaderAndCookieRules(t *testing.T) {
	policy, err := NewPolicy(PolicyConfig{
		Headers: HeaderRulesConfig{
			Banned:         []string{"x-tracker: blocked"},
			Exception:      []string{"x-tracker: allowed"},
			BlockRegex:     []RegexRule{{Pattern: `(?i)^X-Device: blocked-[0-9]+$`}},
			ExceptionRegex: []RegexRule{{Pattern: `(?i)^X-Device: blocked-42$`}},
		},
		Cookies: CookieRulesConfig{
			Banned:    []string{"trackid="},
			Exception: []string{"trackid=allowed"},
		},
	})
	if err != nil {
		t.Fatalf("NewPolicy() error = %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "http://example.test/", nil)
	req.Header.Set("X-Tracker", "blocked")
	if decision := policy.EvaluateRequest("example.test", req, "http"); !decision.Blocked || decision.MatchType != "header" {
		t.Fatalf("header decision = %#v, want header block", decision)
	}
	req.Header.Set("X-Tracker", "allowed")
	if decision := policy.EvaluateRequest("example.test", req, "http"); decision.Blocked {
		t.Fatalf("header exception decision = %#v, want allowed", decision)
	}
	req.Header.Del("X-Tracker")
	req.Header.Set("X-Device", "blocked-7")
	if decision := policy.EvaluateRequest("example.test", req, "http"); !decision.Blocked || decision.MatchType != "header_regex" {
		t.Fatalf("header regex decision = %#v, want header_regex block", decision)
	}
	req.Header.Set("X-Device", "blocked-42")
	if decision := policy.EvaluateRequest("example.test", req, "http"); decision.Blocked {
		t.Fatalf("header regex exception decision = %#v, want allowed", decision)
	}

	cookieReq := httptest.NewRequest(http.MethodGet, "http://example.test/", nil)
	cookieReq.Header.Set("Cookie", "session=ok; trackid=bad")
	if decision := policy.EvaluateRequest("example.test", cookieReq, "http"); !decision.Blocked || decision.MatchType != "cookie" {
		t.Fatalf("cookie decision = %#v, want cookie block", decision)
	}
	cookieReq.Header.Set("Cookie", "session=ok; trackid=allowed")
	if decision := policy.EvaluateRequest("example.test", cookieReq, "http"); decision.Blocked {
		t.Fatalf("cookie exception decision = %#v, want allowed", decision)
	}

	resp := &http.Response{
		StatusCode: http.StatusOK,
		Header:     make(http.Header),
		Request:    httptest.NewRequest(http.MethodGet, "http://example.test/", nil),
	}
	resp.Header.Set("X-Device", "blocked-9")
	if decision := policy.EvaluateResponse(resp, "http"); !decision.Blocked || decision.MatchType != "header_regex" {
		t.Fatalf("response header regex decision = %#v, want header_regex block", decision)
	}
	resp.Header.Set("X-Device", "blocked-42")
	if decision := policy.EvaluateResponse(resp, "http"); decision.Blocked {
		t.Fatalf("response header regex exception decision = %#v, want allowed", decision)
	}
	resp.Header.Del("X-Device")
	resp.Header.Set("Set-Cookie", "trackid=response")
	if decision := policy.EvaluateResponse(resp, "http"); !decision.Blocked || decision.MatchType != "cookie" {
		t.Fatalf("response cookie decision = %#v, want cookie block", decision)
	}
}

func TestPolicyRejectsInvalidHeaderRegex(t *testing.T) {
	_, err := NewPolicy(PolicyConfig{
		Headers: HeaderRulesConfig{
			BlockRegex: []RegexRule{{Pattern: `[`, Source: "bannedregexpheaderlist:2"}},
		},
	})
	if err == nil || !strings.Contains(err.Error(), "bannedregexpheaderlist:2") {
		t.Fatalf("NewPolicy() error = %v, want header regex source", err)
	}
}

func TestPolicySiteIPRules(t *testing.T) {
	policy, err := NewPolicy(PolicyConfig{
		SiteIPs: SiteIPRulesConfig{
			Blocked:    []string{"203.0.113.0/24", "2001:db8::/32"},
			Exceptions: []string{"203.0.113.42"},
			Grey:       []string{"198.51.100.0/24"},
		},
	})
	if err != nil {
		t.Fatalf("NewPolicy() error = %v", err)
	}

	if decision := policy.Evaluate("203.0.113.7", nil, "http"); !decision.Blocked || decision.MatchType != "site_ip" || decision.Value != "203.0.113.7" {
		t.Fatalf("site IP decision = %#v, want site_ip block", decision)
	}
	if decision := policy.Evaluate("203.0.113.42", nil, "http"); decision.Blocked {
		t.Fatalf("site IP exception decision = %#v, want allowed", decision)
	}
	if decision := policy.Evaluate("[2001:db8::1]:443", nil, "https"); !decision.Blocked || decision.MatchType != "site_ip" || decision.Value != "2001:db8::1" {
		t.Fatalf("site IPv6 decision = %#v, want site_ip block", decision)
	}
	if decision := policy.Evaluate("example.test", nil, "http"); decision.Blocked {
		t.Fatalf("domain host decision = %#v, want allowed until DNS-resolved IP policy is wired", decision)
	}
	if decision := policy.Evaluate("198.51.100.7", nil, "http"); decision.Blocked {
		t.Fatalf("grey site IP decision = %#v, want allowed with content inspection", decision)
	}
}

func TestPolicyRejectsInvalidSiteIPRule(t *testing.T) {
	_, err := NewPolicy(PolicyConfig{
		SiteIPs: SiteIPRulesConfig{
			Blocked: []string{"not-an-ip"},
		},
	})
	if err == nil || !strings.Contains(err.Error(), "bannedsiteiplist") {
		t.Fatalf("NewPolicy() error = %v, want bannedsiteiplist source", err)
	}
}

func TestPolicyLogRules(t *testing.T) {
	policy, err := NewPolicy(PolicyConfig{
		Log: LogRulesConfig{
			LogURLs:                []string{"https://example.com/logme"},
			ExceptionLogURLs:       []string{"https://example.com/logme/except"},
			LogSites:               []string{"audited.example"},
			LogSiteIPs:             []string{"203.0.113.10", "2001:db8::/32"},
			LogRegexURLs:           []RegexRule{{Pattern: `/logregex($|\?)`}},
			ExceptionLogRegexURLs:  []RegexRule{{Pattern: `/no-log`}},
			LogRegexSites:          []RegexRule{{Pattern: `^logsite\.com$`}},
			ExceptionLogRegexSites: []RegexRule{{Pattern: `^no-log\.com$`}},
			NoLogSites:             []string{"static.example"},
			NoLogSiteIPs:           []string{"198.51.100.0/24"},
			NoLogURLs:              []string{"https://example.com/private"},
			NoLogRegexURLs:         []RegexRule{{Pattern: `/quiet-[0-9]+`}},
			NoLogExtensions:        []string{".png"},
		},
	})
	if err != nil {
		t.Fatalf("NewPolicy() error = %v", err)
	}

	// 1. URL log match
	reqLog := httptest.NewRequest(http.MethodGet, "https://example.com/logme?q=1", nil)
	shouldLog, suppressed, matchType, listName, matchVal := policy.EvaluateLogging("example.com", reqLog, "https")
	if !shouldLog || suppressed || matchType != "url" || listName != "logurllist" || matchVal != "https://example.com/logme" {
		t.Fatalf("url log matched incorrectly: shouldLog=%v, suppressed=%v, matchType=%v, listName=%v, matchVal=%v", shouldLog, suppressed, matchType, listName, matchVal)
	}

	// 2. URL log exception match
	reqExcept := httptest.NewRequest(http.MethodGet, "https://example.com/logme/except", nil)
	shouldLog, suppressed, matchType, listName, matchVal = policy.EvaluateLogging("example.com", reqExcept, "https")
	if shouldLog || !suppressed || listName != "exceptionlogurllist" {
		t.Fatalf("url log exception matched incorrectly: shouldLog=%v, suppressed=%v, listName=%v", shouldLog, suppressed, listName)
	}

	// 3. Regex URL log match
	reqRegex := httptest.NewRequest(http.MethodGet, "https://example.com/logregex?foo=bar", nil)
	shouldLog, suppressed, matchType, listName, matchVal = policy.EvaluateLogging("example.com", reqRegex, "https")
	if !shouldLog || suppressed || matchType != "url_regex" || listName != "logregexpurllist" {
		t.Fatalf("url regex log matched incorrectly: shouldLog=%v, suppressed=%v, listName=%v", shouldLog, suppressed, listName)
	}

	// 4. Regex Site log match
	reqSite := httptest.NewRequest(http.MethodGet, "https://logsite.com/some/path", nil)
	shouldLog, suppressed, matchType, listName, matchVal = policy.EvaluateLogging("logsite.com", reqSite, "https")
	if !shouldLog || suppressed || matchType != "site_regex" || listName != "logregexpsitelist" {
		t.Fatalf("site regex log matched incorrectly: shouldLog=%v, suppressed=%v, listName=%v", shouldLog, suppressed, listName)
	}

	// 5. Literal site log match
	reqLiteralSite := httptest.NewRequest(http.MethodGet, "https://child.audited.example/path", nil)
	shouldLog, suppressed, matchType, listName, matchVal = policy.EvaluateLogging("child.audited.example", reqLiteralSite, "https")
	if !shouldLog || suppressed || matchType != "site" || listName != "logsitelist" || matchVal != "child.audited.example" {
		t.Fatalf("literal site log matched incorrectly: shouldLog=%v, suppressed=%v, matchType=%v, listName=%v, matchVal=%v", shouldLog, suppressed, matchType, listName, matchVal)
	}

	// 6. Literal IP log match, including bracketed IPv6 host input.
	reqIP := httptest.NewRequest(http.MethodGet, "https://203.0.113.10/path", nil)
	shouldLog, suppressed, matchType, listName, matchVal = policy.EvaluateLogging("203.0.113.10", reqIP, "https")
	if !shouldLog || suppressed || matchType != "site_ip" || listName != "logsiteiplist" || matchVal != "203.0.113.10" {
		t.Fatalf("site IP log matched incorrectly: shouldLog=%v, suppressed=%v, matchType=%v, listName=%v, matchVal=%v", shouldLog, suppressed, matchType, listName, matchVal)
	}
	reqIPv6 := httptest.NewRequest(http.MethodGet, "https://[2001:db8::1]/path", nil)
	shouldLog, suppressed, matchType, listName, matchVal = policy.EvaluateLogging("[2001:db8::1]:443", reqIPv6, "https")
	if !shouldLog || suppressed || matchType != "site_ip" || listName != "logsiteiplist" || matchVal != "2001:db8::1" {
		t.Fatalf("site IPv6 log matched incorrectly: shouldLog=%v, suppressed=%v, matchType=%v, listName=%v, matchVal=%v", shouldLog, suppressed, matchType, listName, matchVal)
	}

	// 7. nolog suppressors win before positive log lists.
	reqNoLogSite := httptest.NewRequest(http.MethodGet, "https://static.example/logregex", nil)
	shouldLog, suppressed, _, listName, _ = policy.EvaluateLogging("static.example", reqNoLogSite, "https")
	if shouldLog || !suppressed || listName != "nologsitelist" {
		t.Fatalf("nolog site suppression failed: shouldLog=%v suppressed=%v listName=%v", shouldLog, suppressed, listName)
	}
	reqNoLogIP := httptest.NewRequest(http.MethodGet, "https://198.51.100.7/logregex", nil)
	shouldLog, suppressed, _, listName, _ = policy.EvaluateLogging("198.51.100.7", reqNoLogIP, "https")
	if shouldLog || !suppressed || listName != "nologsiteiplist" {
		t.Fatalf("nolog site IP suppression failed: shouldLog=%v suppressed=%v listName=%v", shouldLog, suppressed, listName)
	}
	reqNoLogURL := httptest.NewRequest(http.MethodGet, "https://example.com/private/logme", nil)
	shouldLog, suppressed, _, listName, _ = policy.EvaluateLogging("example.com", reqNoLogURL, "https")
	if shouldLog || !suppressed || listName != "nologurllist" {
		t.Fatalf("nolog URL suppression failed: shouldLog=%v suppressed=%v listName=%v", shouldLog, suppressed, listName)
	}
	reqNoLogRegex := httptest.NewRequest(http.MethodGet, "https://example.com/quiet-42", nil)
	shouldLog, suppressed, _, listName, _ = policy.EvaluateLogging("example.com", reqNoLogRegex, "https")
	if shouldLog || !suppressed || listName != "nologregexpurllist" {
		t.Fatalf("nolog regex URL suppression failed: shouldLog=%v suppressed=%v listName=%v", shouldLog, suppressed, listName)
	}
	reqNoLogExt := httptest.NewRequest(http.MethodGet, "https://example.com/logme/image.png", nil)
	shouldLog, suppressed, _, listName, _ = policy.EvaluateLogging("example.com", reqNoLogExt, "https")
	if shouldLog || !suppressed || listName != "nologextensionlist" {
		t.Fatalf("nolog extension suppression failed: shouldLog=%v suppressed=%v listName=%v", shouldLog, suppressed, listName)
	}
}

func TestPolicyLocalAliasesPrecedence(t *testing.T) {
	policy, err := NewPolicy(PolicyConfig{
		Domains: DomainRulesConfig{
			LocalExceptions: []string{"local-exempt.com"},
			LocalGrey:       []string{"local-grey.com"},
			LocalBlocked:    []string{"local-blocked.com", "local-grey.com"}, // local-grey.com is both, grey should win
			Exceptions:      []string{"exempt.com", "local-blocked.com"},     // local-blocked.com is both, local-blocked should win
			Grey:            []string{"grey.com", "exempt.com"},              // exempt.com is both, exempt should win
			Blocked:         []string{"blocked.com", "grey.com"},             // grey.com is both, grey should win
		},
		URLs: URLRulesConfig{
			LocalExceptions: []string{"https://example.com/local-exempt"},
			LocalGrey:       []string{"https://example.com/local-grey"},
			LocalBlocked:    []string{"https://example.com/local-blocked", "https://example.com/local-grey"},
			Exceptions:      []string{"https://example.com/exempt", "https://example.com/local-blocked"},
			Grey:            []string{"https://example.com/grey", "https://example.com/exempt"},
			Blocked:         []string{"https://example.com/blocked", "https://example.com/grey"},
		},
	})
	if err != nil {
		t.Fatalf("NewPolicy() error = %v", err)
	}

	// Domain Tests
	// 1. local exception wins over local blocked
	d1 := policy.Evaluate("local-exempt.com", nil, "http")
	if d1.Blocked {
		t.Fatalf("local-exempt.com should be allowed (local exception wins)")
	}

	// 2. local grey wins over local blocked
	d2 := policy.Evaluate("local-grey.com", nil, "http")
	if d2.Blocked {
		t.Fatalf("local-grey.com should be allowed (local grey wins over local blocked)")
	}

	// 3. local blocked wins over main exception
	d3 := policy.Evaluate("local-blocked.com", nil, "http")
	if !d3.Blocked || d3.MatchType != "domain_local" {
		t.Fatalf("local-blocked.com should be blocked with MatchType domain_local: %#v", d3)
	}

	// 4. main exception wins over main grey
	d4 := policy.Evaluate("exempt.com", nil, "http")
	if d4.Blocked {
		t.Fatalf("exempt.com should be allowed (main exception wins over main grey)")
	}

	// 5. main grey wins over main blocked
	d5 := policy.Evaluate("grey.com", nil, "http")
	if d5.Blocked {
		t.Fatalf("grey.com should be allowed (main grey wins over main blocked)")
	}

	// 6. main blocked works
	d6 := policy.Evaluate("blocked.com", nil, "http")
	if !d6.Blocked || d6.MatchType != "domain" {
		t.Fatalf("blocked.com should be blocked with MatchType domain: %#v", d6)
	}

	// URL Tests
	// 1. local exception wins over local blocked
	req1 := httptest.NewRequest(http.MethodGet, "https://example.com/local-exempt", nil)
	u1 := policy.Evaluate("example.com", req1, "https")
	if u1.Blocked {
		t.Fatalf("/local-exempt should be allowed")
	}

	// 2. local grey wins over local blocked
	req2 := httptest.NewRequest(http.MethodGet, "https://example.com/local-grey", nil)
	u2 := policy.Evaluate("example.com", req2, "https")
	if u2.Blocked {
		t.Fatalf("/local-grey should be allowed")
	}

	// 3. local blocked wins over main exception
	req3 := httptest.NewRequest(http.MethodGet, "https://example.com/local-blocked", nil)
	u3 := policy.Evaluate("example.com", req3, "https")
	if !u3.Blocked || u3.MatchType != "url_local" {
		t.Fatalf("/local-blocked should be blocked with MatchType url_local: %#v", u3)
	}

	// 4. main exception wins over main grey
	req4 := httptest.NewRequest(http.MethodGet, "https://example.com/exempt", nil)
	u4 := policy.Evaluate("example.com", req4, "https")
	if u4.Blocked {
		t.Fatalf("/exempt should be allowed")
	}

	// 5. main grey wins over main blocked
	req5 := httptest.NewRequest(http.MethodGet, "https://example.com/grey", nil)
	u5 := policy.Evaluate("example.com", req5, "https")
	if u5.Blocked {
		t.Fatalf("/grey should be allowed")
	}

	// 6. main blocked works
	req6 := httptest.NewRequest(http.MethodGet, "https://example.com/blocked", nil)
	u6 := policy.Evaluate("example.com", req6, "https")
	if !u6.Blocked || u6.MatchType != "url" {
		t.Fatalf("/blocked should be blocked with MatchType url: %#v", u6)
	}
}

func TestPolicyHeaderRewritesAndAdds(t *testing.T) {
	policy, err := NewPolicy(PolicyConfig{
		Headers: HeaderRulesConfig{
			RequestRewrites: []RegexRule{
				{Pattern: `^(?i)User-Agent:.*Chrome.* => User-Agent: Mozilla/5.0 (Stealth)`},
				{Pattern: `^(?i)Cookie:.*bad-cookie.* => `},                    // empty replacement = delete
				{Pattern: `^(?i)Content-Length: 1000 => Content-Length: 9999`}, // dangerous framing header - should be ignored
			},
			ResponseRewrites: []RegexRule{
				{Pattern: `^(?i)Server:.*Apache.* => Server: LucidGate`},
				{Pattern: `^(?i)X-Unwanted:.* => `},                                     // delete
				{Pattern: `^(?i)Transfer-Encoding: chunked => Transfer-Encoding: none`}, // dangerous - ignore
			},
			RequestAdds: []RegexRule{
				{Pattern: `^https://example\.com/secure => X-Secure-Add: yes`},
				{Pattern: `X-Always-Add: always`}, // unconditional
				{Pattern: `Host: example.com`},    // dangerous framing add - should be blocked
			},
		},
	})
	if err != nil {
		t.Fatalf("NewPolicy() error = %v", err)
	}

	// 1. Test Request Header Rewrites
	reqHeaders := http.Header{}
	reqHeaders.Set("User-Agent", "Mozilla/5.0 Chrome/120.0")
	reqHeaders.Set("Cookie", "bad-cookie=123")
	reqHeaders.Set("Content-Length", "1000")
	reqHeaders.Set("X-Normal", "ok")

	policy.RewriteRequestHeaders(reqHeaders)

	if reqHeaders.Get("User-Agent") != "Mozilla/5.0 (Stealth)" {
		t.Fatalf("User-Agent rewrite failed: %q", reqHeaders.Get("User-Agent"))
	}
	if reqHeaders.Get("Cookie") != "" {
		t.Fatalf("Cookie was not deleted: %q", reqHeaders.Get("Cookie"))
	}
	if reqHeaders.Get("Content-Length") != "1000" {
		t.Fatalf("Dangerous Content-Length was mutated: %q", reqHeaders.Get("Content-Length"))
	}
	if reqHeaders.Get("X-Normal") != "ok" {
		t.Fatalf("X-Normal was mutated: %q", reqHeaders.Get("X-Normal"))
	}

	// 2. Test Request Header Adds
	addHeaders := http.Header{}
	policy.AddRequestHeaders(addHeaders, "https://example.com/secure/report")

	if addHeaders.Get("X-Secure-Add") != "yes" {
		t.Fatalf("Conditional X-Secure-Add failed: %q", addHeaders.Get("X-Secure-Add"))
	}
	if addHeaders.Get("X-Always-Add") != "always" {
		t.Fatalf("Unconditional X-Always-Add failed: %q", addHeaders.Get("X-Always-Add"))
	}
	if addHeaders.Get("Host") != "" {
		t.Fatalf("Dangerous Host header was added: %q", addHeaders.Get("Host"))
	}

	// Test non-matching URL conditional add
	addHeaders2 := http.Header{}
	policy.AddRequestHeaders(addHeaders2, "https://example.com/public")
	if addHeaders2.Get("X-Secure-Add") != "" {
		t.Fatalf("Conditional add matched non-matching URL: %q", addHeaders2.Get("X-Secure-Add"))
	}
	if addHeaders2.Get("X-Always-Add") != "always" {
		t.Fatalf("Unconditional add failed on second try")
	}

	// 3. Test Response Header Rewrites
	respHeaders := http.Header{}
	respHeaders.Set("Server", "Apache/2.4.41")
	respHeaders.Set("X-Unwanted", "tracking-id")
	respHeaders.Set("Transfer-Encoding", "chunked")

	policy.RewriteResponseHeaders(respHeaders)

	if respHeaders.Get("Server") != "LucidGate" {
		t.Fatalf("Server rewrite failed: %q", respHeaders.Get("Server"))
	}
	if respHeaders.Get("X-Unwanted") != "" {
		t.Fatalf("X-Unwanted was not deleted: %q", respHeaders.Get("X-Unwanted"))
	}
	if respHeaders.Get("Transfer-Encoding") != "chunked" {
		t.Fatalf("Dangerous Transfer-Encoding was mutated: %q", respHeaders.Get("Transfer-Encoding"))
	}
}

func TestPolicyURLRewritesAndRedirects(t *testing.T) {
	policy, err := NewPolicy(PolicyConfig{
		URLs: URLRulesConfig{
			Rewrites: []RegexRule{
				{Pattern: `^https://example\.com/old/(.*) => https://example.com/new/$1`},
				{Pattern: `^https://example\.com/search\?q=(.*) => https://evil.com/hijack?q=$1`}, // Cross-host hijack - should be rejected by guardrail
			},
			Redirects: []RegexRule{
				{Pattern: `^https://example\.com/redirect/google\?q=(.*) => https://www.google.com/search?q=$1`},
			},
		},
	})
	if err != nil {
		t.Fatalf("NewPolicy() error = %v", err)
	}

	// 1. Test URL Rewrites
	// Same-host rewrite should succeed
	r1, ok1 := policy.urls.RewriteURL("https://example.com/old/report?a=1")
	if !ok1 || r1 != "https://example.com/new/report?a=1" {
		t.Fatalf("same-host rewrite failed: r1=%q, ok1=%v", r1, ok1)
	}

	// Cross-host rewrite should be rejected by guardrail
	r2, ok2 := policy.urls.RewriteURL("https://example.com/search?q=something")
	if ok2 || r2 != "https://example.com/search?q=something" {
		t.Fatalf("cross-host rewrite succeeded (hijack guardrail failed): r2=%q, ok2=%v", r2, ok2)
	}

	// 2. Test URL Redirects
	dec, ok3 := policy.urls.RedirectDecision("https://example.com/redirect/google?q=antigravity")
	if !ok3 || !dec.Redirect || dec.RedirectURL != "https://www.google.com/search?q=antigravity" || dec.MatchType != "url_redirect" {
		t.Fatalf("URL redirect failed: dec=%#v, ok3=%v", dec, ok3)
	}
}
