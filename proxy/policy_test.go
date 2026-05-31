package proxy

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

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
			Banned:    []string{"x-tracker: blocked"},
			Exception: []string{"x-tracker: allowed"},
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
	resp.Header.Set("Set-Cookie", "trackid=response")
	if decision := policy.EvaluateResponse(resp, "http"); !decision.Blocked || decision.MatchType != "cookie" {
		t.Fatalf("response cookie decision = %#v, want cookie block", decision)
	}
}

func TestPolicyLogRules(t *testing.T) {
	policy, err := NewPolicy(PolicyConfig{
		Log: LogRulesConfig{
			LogURLs:                []string{"https://example.com/logme"},
			ExceptionLogURLs:       []string{"https://example.com/logme/except"},
			LogRegexURLs:           []RegexRule{{Pattern: `/logregex($|\?)`}},
			ExceptionLogRegexURLs:  []RegexRule{{Pattern: `/no-log`}},
			LogRegexSites:          []RegexRule{{Pattern: `^logsite\.com$`}},
			ExceptionLogRegexSites: []RegexRule{{Pattern: `^no-log\.com$`}},
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
}
