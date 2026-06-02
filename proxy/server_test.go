package proxy

import (
	"bufio"
	"bytes"
	"compress/flate"
	"compress/gzip"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/zstd"
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/quic-go/quic-go/http3"
	utls "github.com/refraction-networking/utls"
	"golang.org/x/net/http2"

	"lucidgate/pki"
	"lucidgate/stealth"
)

func TestServeHTTPRejectsUnsupportedPlainHTTPSRequest(t *testing.T) {
	server := NewServer("127.0.0.1:0", nil)
	req := httptest.NewRequest(http.MethodGet, "https://example.com/", nil)
	rec := httptest.NewRecorder()

	server.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
}

func TestServeHTTPPlainHTTPForwardsAbsoluteRequestThroughFilters(t *testing.T) {
	upstreamReq := make(chan *http.Request, 1)
	upstreamErr := make(chan error, 1)
	var logs safeBuffer
	server := NewServer("127.0.0.1:0", slog.New(slog.NewTextHandler(&logs, nil)))
	server.SetRelayOptions(RelayOptions{
		LogBodies:       true,
		MaxCaptureBytes: 1 << 20,
		IOTimeout:       time.Second,
		Filter: NewContentFilter(
			nil,
			nil,
			NewHTMLInjectionFilter(`<aside>LucidGate</aside>`),
			nil,
			NewSubstitutionFilter(map[string]string{"Madrid": "Barcelona"}),
		),
	})
	server.SetPlainHTTPDialer(plainDialerFunc(func(_ context.Context, network, address string) (net.Conn, error) {
		if network != "tcp" || address != "example.test:80" {
			return nil, fmt.Errorf("dial target = %s/%s, want tcp/example.test:80", network, address)
		}
		proxySide, upstreamSide := net.Pipe()
		go func() {
			defer upstreamSide.Close()
			req, err := http.ReadRequest(bufio.NewReader(upstreamSide))
			if err != nil {
				upstreamErr <- err
				return
			}
			upstreamReq <- req
			_, _ = io.Copy(io.Discard, req.Body)
			_ = req.Body.Close()
			_, err = io.WriteString(upstreamSide, "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Type: text/html\r\nContent-Length: 39\r\n\r\n<html><body>Madrid</body></html>")
			upstreamErr <- err
		}()
		return proxySide, nil
	}))

	req := httptest.NewRequest(http.MethodGet, "http://example.test/news?q=1", nil)
	req.RemoteAddr = "127.0.0.1:50000"
	req.Header.Set("Proxy-Connection", "keep-alive")
	req.Header.Set("X-Forwarded-For", "203.0.113.10")
	rec := httptest.NewRecorder()

	server.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body=%q", rec.Code, http.StatusOK, rec.Body.String())
	}
	body := rec.Body.String()
	if !strings.Contains(body, "Barcelona") || strings.Contains(body, "Madrid") {
		t.Fatalf("filtered body = %q, want substitution Madrid -> Barcelona", body)
	}
	if !strings.Contains(body, `<aside>LucidGate</aside>`) {
		t.Fatalf("filtered body = %q, want injected banner", body)
	}
	if got := rec.Header().Get("Content-Length"); got != "" {
		t.Fatalf("Content-Length = %q, want removed for mutable response", got)
	}

	select {
	case err := <-upstreamErr:
		if err != nil {
			t.Fatalf("upstream server error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("upstream server did not finish")
	}
	select {
	case req := <-upstreamReq:
		defer req.Body.Close()
		if req.URL.Scheme != "" || req.URL.Host != "" {
			t.Fatalf("upstream URL = %q, want origin-form", req.URL.String())
		}
		if req.URL.RequestURI() != "/news?q=1" {
			t.Fatalf("upstream RequestURI = %q, want /news?q=1", req.URL.RequestURI())
		}
		for _, header := range []string{"Proxy-Connection", "X-Forwarded-For"} {
			if got := req.Header.Get(header); got != "" {
				t.Fatalf("%s header = %q, want empty", header, got)
			}
		}
	case <-time.After(time.Second):
		t.Fatal("upstream request was not captured")
	}
	if got := waitForLog(t, &logs, "msg=exchange", "method=GET", "host=example.test", "status=200"); got == "" {
		t.Fatalf("log output = %q, want structured HTTP exchange log", got)
	}
}

func TestServeHTTPPlainHTTPReusesPooledUpstreamKeepAlive(t *testing.T) {
	var dials atomic.Int64
	upstreamPaths := make(chan string, 2)
	upstreamDone := make(chan error, 1)
	server := NewServer("127.0.0.1:0", nil)
	server.SetRelayOptions(RelayOptions{
		LogBodies:       true,
		MaxCaptureBytes: 1 << 20,
		IOTimeout:       time.Second,
	})
	server.SetPlainHTTPDialer(plainDialerFunc(func(_ context.Context, network, address string) (net.Conn, error) {
		if network != "tcp" || address != "example.test:80" {
			return nil, fmt.Errorf("dial target = %s/%s, want tcp/example.test:80", network, address)
		}
		if dials.Add(1) != 1 {
			return nil, errors.New("unexpected second upstream dial")
		}
		proxySide, upstreamSide := net.Pipe()
		go func() {
			defer upstreamSide.Close()
			reader := bufio.NewReader(upstreamSide)
			for i := 0; i < 2; i++ {
				req, err := http.ReadRequest(reader)
				if err != nil {
					upstreamDone <- err
					return
				}
				upstreamPaths <- req.URL.RequestURI()
				_, _ = io.Copy(io.Discard, req.Body)
				_ = req.Body.Close()
				if _, err := io.WriteString(upstreamSide, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"); err != nil {
					upstreamDone <- err
					return
				}
			}
			upstreamDone <- nil
		}()
		return proxySide, nil
	}))

	for _, path := range []string{"/first", "/second"} {
		req := httptest.NewRequest(http.MethodGet, "http://example.test"+path, nil)
		req.RemoteAddr = "127.0.0.1:50000"
		rec := httptest.NewRecorder()
		server.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s status = %d, want %d; body=%q", path, rec.Code, http.StatusOK, rec.Body.String())
		}
		if rec.Body.String() != "ok" {
			t.Fatalf("%s body = %q, want ok", path, rec.Body.String())
		}
	}

	select {
	case err := <-upstreamDone:
		if err != nil {
			t.Fatalf("upstream error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("upstream server did not finish")
	}
	if got := dials.Load(); got != 1 {
		t.Fatalf("upstream dials = %d, want 1", got)
	}
	for _, want := range []string{"/first", "/second"} {
		select {
		case got := <-upstreamPaths:
			if got != want {
				t.Fatalf("upstream path = %q, want %q", got, want)
			}
		default:
			t.Fatalf("missing upstream path %q", want)
		}
	}
}

func TestServeHTTPPlainHTTPBlocksDeniedDomainBeforeDial(t *testing.T) {
	server := NewServer("127.0.0.1:0", nil)
	server.SetDomainRules(NewDomainRules([]string{"blocked.test"}))
	var dialed atomic.Bool
	server.SetPlainHTTPDialer(plainDialerFunc(func(context.Context, string, string) (net.Conn, error) {
		dialed.Store(true)
		return nil, errors.New("dial should not happen")
	}))
	req := httptest.NewRequest(http.MethodGet, "http://sub.blocked.test/path", nil)
	req.RemoteAddr = "127.0.0.1:50000"
	rec := httptest.NewRecorder()

	server.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusForbidden)
	}
	assertBlockPage(t, rec, "Access denied")
	if dialed.Load() {
		t.Fatal("plain HTTP dialer was called before domain fast-fail")
	}
}

func TestServeHTTPPlainHTTPBlocksResolvedSiteIPBeforeDial(t *testing.T) {
	server := NewServer("127.0.0.1:0", nil)
	policy, err := NewPolicy(PolicyConfig{
		SiteIPs: SiteIPRulesConfig{Blocked: []string{"203.0.113.0/24"}},
	})
	if err != nil {
		t.Fatalf("NewPolicy() error = %v", err)
	}
	server.SetPolicy(policy)
	resolver := &mockLookupResolver{ips: []net.IP{net.ParseIP("203.0.113.7")}}
	server.dnsResolver = NewDNSResolver(false, 0)
	server.dnsResolver.resolver = resolver

	var dialed atomic.Bool
	server.SetPlainHTTPDialer(plainDialerFunc(func(context.Context, string, string) (net.Conn, error) {
		dialed.Store(true)
		return nil, errors.New("dial should not happen")
	}))
	req := httptest.NewRequest(http.MethodGet, "http://resolved-blocked.test/path", nil)
	req.RemoteAddr = "127.0.0.1:50000"
	rec := httptest.NewRecorder()

	server.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusForbidden)
	}
	assertBlockPage(t, rec, "Access denied")
	if dialed.Load() {
		t.Fatal("plain HTTP dialer was called after resolved site IP block")
	}
	if resolver.calls != 1 {
		t.Fatalf("DNS lookups = %d, want 1", resolver.calls)
	}
}

func TestServeHTTPPlainHTTPDialsResolvedAddressOnceForSiteIPPolicy(t *testing.T) {
	server := NewServer("127.0.0.1:0", nil)
	policy, err := NewPolicy(PolicyConfig{
		SiteIPs: SiteIPRulesConfig{Blocked: []string{"198.51.100.0/24"}},
	})
	if err != nil {
		t.Fatalf("NewPolicy() error = %v", err)
	}
	server.SetPolicy(policy)
	resolver := &mockLookupResolver{ips: []net.IP{net.ParseIP("203.0.113.8")}}
	server.dnsResolver = NewDNSResolver(false, 0)
	server.dnsResolver.resolver = resolver

	server.SetPlainHTTPDialer(plainDialerFunc(func(_ context.Context, network, address string) (net.Conn, error) {
		if network != "tcp" || address != "203.0.113.8:80" {
			return nil, fmt.Errorf("dial target = %s/%s, want tcp/203.0.113.8:80", network, address)
		}
		proxySide, upstreamSide := net.Pipe()
		go func() {
			defer upstreamSide.Close()
			if _, err := http.ReadRequest(bufio.NewReader(upstreamSide)); err != nil {
				return
			}
			_, _ = io.WriteString(upstreamSide, "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: 2\r\n\r\nok")
		}()
		return proxySide, nil
	}))
	req := httptest.NewRequest(http.MethodGet, "http://resolved-allowed.test/path", nil)
	req.RemoteAddr = "127.0.0.1:50000"
	rec := httptest.NewRecorder()

	server.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d body=%q", rec.Code, http.StatusOK, rec.Body.String())
	}
	if resolver.calls != 1 {
		t.Fatalf("DNS lookups = %d, want 1", resolver.calls)
	}
}

func TestAcquireHTTPSUpstreamBlocksResolvedSiteIPBeforeDial(t *testing.T) {
	server := NewServer("127.0.0.1:0", nil)
	policy, err := NewPolicy(PolicyConfig{
		SiteIPs: SiteIPRulesConfig{Blocked: []string{"203.0.113.0/24"}},
	})
	if err != nil {
		t.Fatalf("NewPolicy() error = %v", err)
	}
	server.SetPolicy(policy)
	resolver := &mockLookupResolver{ips: []net.IP{net.ParseIP("203.0.113.9")}}
	server.dnsResolver = NewDNSResolver(false, 0)
	server.dnsResolver.resolver = resolver

	var dialed atomic.Bool
	server.SetUpstreamDialer(upstreamDialerFunc(func(context.Context, string, string) (net.Conn, error) {
		dialed.Store(true)
		return nil, errors.New("dial should not happen")
	}))

	_, err = server.acquireHTTPSUpstream(context.Background(), "resolved-blocked.test:443", "resolved-blocked.test")
	if _, ok := policyDecisionFromError(err); !ok {
		t.Fatalf("acquireHTTPSUpstream() error = %v, want policy block", err)
	}
	if dialed.Load() {
		t.Fatal("HTTPS upstream dialer was called after resolved site IP block")
	}
	if resolver.calls != 1 {
		t.Fatalf("DNS lookups = %d, want 1", resolver.calls)
	}
}

func TestServeHTTPPlainHTTPBlocksDeniedURLBeforeDial(t *testing.T) {
	server := NewServer("127.0.0.1:0", nil)
	policy, err := NewPolicy(PolicyConfig{
		URLs: URLRulesConfig{Blocked: []string{"http://example.test/private"}},
	})
	if err != nil {
		t.Fatalf("NewPolicy() error = %v", err)
	}
	server.SetPolicy(policy)
	var dialed atomic.Bool
	server.SetPlainHTTPDialer(plainDialerFunc(func(context.Context, string, string) (net.Conn, error) {
		dialed.Store(true)
		return nil, errors.New("dial should not happen")
	}))
	req := httptest.NewRequest(http.MethodGet, "http://example.test/private/report?q=1", nil)
	req.RemoteAddr = "127.0.0.1:50000"
	rec := httptest.NewRecorder()

	server.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusForbidden)
	}
	assertBlockPage(t, rec, "Access denied")
	if dialed.Load() {
		t.Fatal("plain HTTP dialer was called before URL fast-fail")
	}
}

func TestServeHTTPPlainHTTPBlocksDeniedExtensionBeforeDial(t *testing.T) {
	server := NewServer("127.0.0.1:0", nil)
	policy, err := NewPolicy(PolicyConfig{
		Files: FileRulesConfig{BannedExtensions: []string{".exe"}},
	})
	if err != nil {
		t.Fatalf("NewPolicy() error = %v", err)
	}
	server.SetPolicy(policy)
	var dialed atomic.Bool
	server.SetPlainHTTPDialer(plainDialerFunc(func(context.Context, string, string) (net.Conn, error) {
		dialed.Store(true)
		return nil, errors.New("dial should not happen")
	}))
	req := httptest.NewRequest(http.MethodGet, "http://example.test/download/tool.exe", nil)
	req.RemoteAddr = "127.0.0.1:50000"
	rec := httptest.NewRecorder()

	server.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusForbidden)
	}
	assertBlockPage(t, rec, "Access denied")
	if dialed.Load() {
		t.Fatal("plain HTTP dialer was called before extension fast-fail")
	}
}

func TestServeHTTPPlainHTTPBlocksDeniedHeaderBeforeDial(t *testing.T) {
	server := NewServer("127.0.0.1:0", nil)
	policy, err := NewPolicy(PolicyConfig{
		Headers: HeaderRulesConfig{Banned: []string{"x-tracker: blocked"}},
	})
	if err != nil {
		t.Fatalf("NewPolicy() error = %v", err)
	}
	server.SetPolicy(policy)
	var dialed atomic.Bool
	server.SetPlainHTTPDialer(plainDialerFunc(func(context.Context, string, string) (net.Conn, error) {
		dialed.Store(true)
		return nil, errors.New("dial should not happen")
	}))
	req := httptest.NewRequest(http.MethodGet, "http://example.test/", nil)
	req.RemoteAddr = "127.0.0.1:50000"
	req.Header.Set("X-Tracker", "blocked")
	rec := httptest.NewRecorder()

	server.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusForbidden)
	}
	if dialed.Load() {
		t.Fatal("plain HTTP dialer was called before header fast-fail")
	}
}

func TestServeHTTPPlainHTTPBlocksDeniedMIMEBeforeBody(t *testing.T) {
	upstreamErr := make(chan error, 1)
	server := NewServer("127.0.0.1:0", nil)
	policy, err := NewPolicy(PolicyConfig{
		Files: FileRulesConfig{BannedMIMEs: []string{"application/x-msdownload"}},
	})
	if err != nil {
		t.Fatalf("NewPolicy() error = %v", err)
	}
	server.SetPolicy(policy)
	server.SetPlainHTTPDialer(plainDialerFunc(func(context.Context, string, string) (net.Conn, error) {
		proxySide, upstreamSide := net.Pipe()
		go func() {
			defer upstreamSide.Close()
			req, err := http.ReadRequest(bufio.NewReader(upstreamSide))
			if err != nil {
				upstreamErr <- err
				return
			}
			_, _ = io.Copy(io.Discard, req.Body)
			_ = req.Body.Close()
			_, err = io.WriteString(upstreamSide, "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Type: application/x-msdownload\r\nContent-Length: 11\r\n\r\n")
			upstreamErr <- err
		}()
		return proxySide, nil
	}))
	req := httptest.NewRequest(http.MethodGet, "http://example.test/download/tool", nil)
	req.RemoteAddr = "127.0.0.1:50000"
	rec := httptest.NewRecorder()

	server.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d; body=%q", rec.Code, http.StatusForbidden, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "binary-body") {
		t.Fatalf("blocked response leaked upstream body: %q", rec.Body.String())
	}
	select {
	case err := <-upstreamErr:
		if err != nil {
			t.Fatalf("upstream error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("upstream server did not finish")
	}
}

func TestServeHTTPPlainHTTPBlocksDeniedSetCookieBeforeBody(t *testing.T) {
	upstreamErr := make(chan error, 1)
	server := NewServer("127.0.0.1:0", nil)
	policy, err := NewPolicy(PolicyConfig{
		Cookies: CookieRulesConfig{Banned: []string{"trackid="}},
	})
	if err != nil {
		t.Fatalf("NewPolicy() error = %v", err)
	}
	server.SetPolicy(policy)
	server.SetPlainHTTPDialer(plainDialerFunc(func(context.Context, string, string) (net.Conn, error) {
		proxySide, upstreamSide := net.Pipe()
		go func() {
			defer upstreamSide.Close()
			req, err := http.ReadRequest(bufio.NewReader(upstreamSide))
			if err != nil {
				upstreamErr <- err
				return
			}
			_, _ = io.Copy(io.Discard, req.Body)
			_ = req.Body.Close()
			_, err = io.WriteString(upstreamSide, "HTTP/1.1 200 OK\r\nConnection: close\r\nSet-Cookie: trackid=response\r\nContent-Length: 11\r\n\r\n")
			upstreamErr <- err
		}()
		return proxySide, nil
	}))
	req := httptest.NewRequest(http.MethodGet, "http://example.test/", nil)
	req.RemoteAddr = "127.0.0.1:50000"
	rec := httptest.NewRecorder()

	server.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d; body=%q", rec.Code, http.StatusForbidden, rec.Body.String())
	}
	select {
	case err := <-upstreamErr:
		if err != nil {
			t.Fatalf("upstream error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("upstream server did not finish")
	}
}

func TestServeHTTPRejectsWhenConnectionLimitExceeded(t *testing.T) {
	server := NewServer("127.0.0.1:0", nil)
	server.SetMaxConnections(1)
	permit, ok := server.acquireConn(context.Background())
	if !ok {
		t.Fatal("failed to occupy connection slot")
	}
	defer server.releaseConn(permit)

	req := httptest.NewRequest(http.MethodConnect, "http://example.com:443/", nil)
	req.RemoteAddr = "127.0.0.1:50000"
	rec := httptest.NewRecorder()

	server.ServeHTTP(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusServiceUnavailable)
	}
	assertBlockPage(t, rec, "Connection limit exceeded")
}

func TestServeHTTPBlocksDeniedConnectBeforeHijack(t *testing.T) {
	server := NewServer("127.0.0.1:0", nil)
	server.SetDomainRules(NewDomainRules([]string{"blocked.test"}))
	req := &http.Request{
		Method:     http.MethodConnect,
		Host:       "sub.blocked.test:443",
		URL:        &url.URL{Host: "sub.blocked.test:443"},
		Header:     make(http.Header),
		RemoteAddr: "127.0.0.1:50000",
	}
	rec := httptest.NewRecorder()

	server.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusForbidden)
	}
	assertBlockPage(t, rec, "Access denied")
}

func TestServeHTTPBlocksDeniedClientBeforeHijack(t *testing.T) {
	server := NewServer("127.0.0.1:0", nil)
	access, err := NewAccessRules([]AccessProfile{
		{Name: "allowed", Clients: []string{"192.0.2.0/24"}},
	})
	if err != nil {
		t.Fatalf("NewAccessRules() error = %v", err)
	}
	server.SetAccessRules(access)
	req := &http.Request{
		Method:     http.MethodConnect,
		Host:       "example.test:443",
		URL:        &url.URL{Host: "example.test:443"},
		Header:     make(http.Header),
		RemoteAddr: "198.51.100.10:50000",
	}
	rec := httptest.NewRecorder()

	server.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusForbidden)
	}
	assertBlockPage(t, rec, "Client access denied")
}

func TestServeHTTPBlocksClientOutsideScheduleBeforeHijack(t *testing.T) {
	server := NewServer("127.0.0.1:0", nil)
	access, err := NewAccessRules([]AccessProfile{
		{Name: "students", Clients: []string{"192.0.2.0/24"}},
	})
	if err != nil {
		t.Fatalf("NewAccessRules() error = %v", err)
	}
	schedules, err := NewScheduleRules([]ScheduleWindow{
		{Profile: "students", Days: []string{"mon"}, Start: "08:00", End: "09:00"},
	})
	if err != nil {
		t.Fatalf("NewScheduleRules() error = %v", err)
	}
	server.SetAccessRules(access)
	server.SetScheduleRules(schedules)
	server.SetClock(func() time.Time {
		return time.Date(2026, 5, 4, 10, 0, 0, 0, time.Local)
	})
	req := &http.Request{
		Method:     http.MethodConnect,
		Host:       "example.test:443",
		URL:        &url.URL{Host: "example.test:443"},
		Header:     make(http.Header),
		RemoteAddr: "192.0.2.10:50000",
	}
	rec := httptest.NewRecorder()

	server.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusForbidden)
	}
	assertBlockPage(t, rec, "Access outside allowed schedule")
}

func assertBlockPage(t *testing.T, rec *httptest.ResponseRecorder, wantTitle string) {
	t.Helper()
	if got := rec.Header().Get("Content-Type"); got != "text/html; charset=utf-8" {
		t.Fatalf("Content-Type = %q, want text/html; charset=utf-8", got)
	}
	if got := rec.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("Cache-Control = %q, want no-store", got)
	}
	if got := rec.Header().Get("X-Content-Type-Options"); got != "nosniff" {
		t.Fatalf("X-Content-Type-Options = %q, want nosniff", got)
	}
	body := rec.Body.String()
	for _, want := range []string{"LucidGate", wantTitle, http.StatusText(rec.Code)} {
		if !strings.Contains(body, want) {
			t.Fatalf("block page body missing %q: %s", want, body)
		}
	}
}

func TestConnectHijackWritesEstablished(t *testing.T) {
	server := NewServer("127.0.0.1:0", nil)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen() error = %v", err)
	}
	defer ln.Close()

	errCh := make(chan error, 1)
	go func() {
		errCh <- server.httpServer.Serve(ln)
	}()
	defer func() {
		_ = server.httpServer.Shutdown(context.Background())
		err := <-errCh
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			t.Fatalf("Serve() error = %v", err)
		}
	}()

	conn, err := net.DialTimeout("tcp", ln.Addr().String(), time.Second)
	if err != nil {
		t.Fatalf("DialTimeout() error = %v", err)
	}
	defer conn.Close()

	if _, err := io.WriteString(conn, "CONNECT github.com:443 HTTP/1.1\r\nHost: github.com:443\r\n\r\n"); err != nil {
		t.Fatalf("write CONNECT error = %v", err)
	}

	reader := bufio.NewReader(conn)
	line, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("read status line error = %v", err)
	}
	if !strings.Contains(line, "200 Connection Established") {
		t.Fatalf("status line = %q, want 200 Connection Established", line)
	}
}

func TestServeStopsOnContextCancel(t *testing.T) {
	server := NewServer("127.0.0.1:0", nil)
	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() {
		errCh <- server.Serve(ctx)
	}()

	cancel()

	select {
	case err := <-errCh:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Serve() error = %v, want context.Canceled", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Serve() did not stop after context cancellation")
	}
}

func TestConnectStartsLocalTLSHandshake(t *testing.T) {
	ca, err := pki.GenerateRootCA(time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("GenerateRootCA() error = %v", err)
	}
	server := NewServer("127.0.0.1:0", nil, pki.NewLeafCache(ca.Certificate, ca.PrivateKey))
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen() error = %v", err)
	}
	defer ln.Close()

	errCh := make(chan error, 1)
	go func() {
		errCh <- server.httpServer.Serve(ln)
	}()
	defer func() {
		_ = server.httpServer.Shutdown(context.Background())
		err := <-errCh
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			t.Fatalf("Serve() error = %v", err)
		}
	}()

	conn, err := net.DialTimeout("tcp", ln.Addr().String(), time.Second)
	if err != nil {
		t.Fatalf("DialTimeout() error = %v", err)
	}
	defer conn.Close()

	if _, err := io.WriteString(conn, "CONNECT github.com:443 HTTP/1.1\r\nHost: github.com:443\r\n\r\n"); err != nil {
		t.Fatalf("write CONNECT error = %v", err)
	}

	reader := bufio.NewReader(conn)
	line, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("read status line error = %v", err)
	}
	if !strings.Contains(line, "200 Connection Established") {
		t.Fatalf("status line = %q, want 200 Connection Established", line)
	}
	blank, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("read blank line error = %v", err)
	}
	if blank != "\r\n" {
		t.Fatalf("blank line = %q, want CRLF", blank)
	}

	roots := x509.NewCertPool()
	roots.AddCert(ca.Certificate)
	tlsConn := tls.Client(conn, &tls.Config{
		ServerName: "github.com",
		RootCAs:    roots,
		MinVersion: tls.VersionTLS12,
	})
	if err := tlsConn.Handshake(); err != nil {
		t.Fatalf("TLS Handshake() error = %v", err)
	}
	state := tlsConn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		t.Fatal("server did not present a peer certificate")
	}
	if got := state.PeerCertificates[0].DNSNames; len(got) != 1 || got[0] != "github.com" {
		t.Fatalf("peer DNSNames = %v, want [github.com]", got)
	}
}

func TestConnectDialsUpstreamAfterLocalTLSHandshake(t *testing.T) {
	ca, err := pki.GenerateRootCA(time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("GenerateRootCA() error = %v", err)
	}
	dialed := make(chan upstreamCall, 1)
	server := NewServer("127.0.0.1:0", nil, pki.NewLeafCache(ca.Certificate, ca.PrivateKey))
	server.SetUpstreamDialer(fakeUpstreamDialer{calls: dialed})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen() error = %v", err)
	}
	defer ln.Close()

	errCh := make(chan error, 1)
	go func() {
		errCh <- server.httpServer.Serve(ln)
	}()
	defer func() {
		_ = server.httpServer.Shutdown(context.Background())
		err := <-errCh
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			t.Fatalf("Serve() error = %v", err)
		}
	}()

	tlsConn := connectAndHandshake(t, ln.Addr().String(), ca.Certificate, "github.com")
	defer tlsConn.Close()

	if _, err := io.WriteString(tlsConn, "GET / HTTP/1.1\r\nHost: github.com\r\nConnection: close\r\n\r\n"); err != nil {
		t.Fatalf("write local request error = %v", err)
	}
	select {
	case call := <-dialed:
		if call.address != "github.com:443" || call.serverName != "github.com" {
			t.Fatalf("upstream call = %#v, want github.com:443/github.com", call)
		}
	case <-time.After(time.Second):
		t.Fatal("upstream dial was not called")
	}
}

func TestPrewarmCertificatesEnqueuesUniqueHostsForWorkers(t *testing.T) {
	provider := &recordingCertificateProvider{hosts: make(chan string, 2)}
	server := NewServer("127.0.0.1:0", nil, provider)
	server.SetCertWorkers(1)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	server.startCertWorkers(ctx)

	if got := server.PrewarmCertificates([]string{"example.com", "example.com", " other.test "}); got != 2 {
		t.Fatalf("PrewarmCertificates() = %d, want 2", got)
	}

	seen := map[string]bool{}
	for i := 0; i < 2; i++ {
		select {
		case host := <-provider.hosts:
			seen[host] = true
		case <-time.After(time.Second):
			t.Fatal("timeout waiting for prewarmed certificate")
		}
	}
	if !seen["example.com"] || !seen["other.test"] {
		t.Fatalf("prewarmed hosts = %#v, want example.com and other.test", seen)
	}
}

func TestConnectReusesPooledUpstreamAcrossShortClientTunnels(t *testing.T) {
	ca, err := pki.GenerateRootCA(time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("GenerateRootCA() error = %v", err)
	}
	var dials atomic.Int64
	upstreamReqClose := make(chan bool, 2)
	upstreamDone := make(chan error, 1)
	server := NewServer("127.0.0.1:0", nil, pki.NewLeafCache(ca.Certificate, ca.PrivateKey))
	server.SetRelayOptions(RelayOptions{
		LogBodies:       true,
		MaxCaptureBytes: 1 << 20,
		IOTimeout:       time.Second,
	})
	server.SetUpstreamDialer(upstreamDialerFunc(func(context.Context, string, string) (net.Conn, error) {
		if dials.Add(1) != 1 {
			return nil, errors.New("unexpected second upstream dial")
		}
		proxySide, upstreamSide := net.Pipe()
		go func() {
			defer upstreamSide.Close()
			reader := bufio.NewReader(upstreamSide)
			for i := 0; i < 2; i++ {
				req, err := http.ReadRequest(reader)
				if err != nil {
					upstreamDone <- err
					return
				}
				upstreamReqClose <- req.Close
				_, _ = io.Copy(io.Discard, req.Body)
				_ = req.Body.Close()
				if _, err := io.WriteString(upstreamSide, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"); err != nil {
					upstreamDone <- err
					return
				}
			}
			upstreamDone <- nil
		}()
		return proxySide, nil
	}))
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen() error = %v", err)
	}
	defer ln.Close()

	errCh := make(chan error, 1)
	go func() {
		errCh <- server.httpServer.Serve(ln)
	}()
	defer func() {
		_ = server.httpServer.Shutdown(context.Background())
		err := <-errCh
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			t.Fatalf("Serve() error = %v", err)
		}
	}()

	for _, path := range []string{"/first", "/second"} {
		tlsConn := connectAndHandshake(t, ln.Addr().String(), ca.Certificate, "github.com")
		if _, err := fmt.Fprintf(tlsConn, "GET %s HTTP/1.1\r\nHost: github.com\r\nConnection: close\r\n\r\n", path); err != nil {
			t.Fatalf("write local request error = %v", err)
		}
		resp, err := http.ReadResponse(bufio.NewReader(tlsConn), nil)
		if err != nil {
			t.Fatalf("read local response error = %v", err)
		}
		body, err := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		_ = tlsConn.Close()
		if err != nil {
			t.Fatalf("read response body error = %v", err)
		}
		if resp.StatusCode != http.StatusOK || string(body) != "ok" {
			t.Fatalf("%s response = %d %q, want 200 ok", path, resp.StatusCode, string(body))
		}
	}

	select {
	case err := <-upstreamDone:
		if err != nil {
			t.Fatalf("upstream error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("upstream server did not finish")
	}
	if got := dials.Load(); got != 1 {
		t.Fatalf("upstream dials = %d, want 1", got)
	}
	for i := 0; i < 2; i++ {
		select {
		case got := <-upstreamReqClose:
			if got {
				t.Fatal("client Connection: close leaked to upstream request")
			}
		default:
			t.Fatal("missing upstream request close state")
		}
	}
}

func TestConnectWritesBadGatewayOnUpstreamFailure(t *testing.T) {
	ca, err := pki.GenerateRootCA(time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("GenerateRootCA() error = %v", err)
	}
	server := NewServer("127.0.0.1:0", nil, pki.NewLeafCache(ca.Certificate, ca.PrivateKey))
	server.SetUpstreamDialer(fakeUpstreamDialer{err: errors.New("upstream down")})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen() error = %v", err)
	}
	defer ln.Close()

	errCh := make(chan error, 1)
	go func() {
		errCh <- server.httpServer.Serve(ln)
	}()
	defer func() {
		_ = server.httpServer.Shutdown(context.Background())
		err := <-errCh
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			t.Fatalf("Serve() error = %v", err)
		}
	}()

	tlsConn := connectAndHandshake(t, ln.Addr().String(), ca.Certificate, "github.com")
	defer tlsConn.Close()

	if _, err := io.WriteString(tlsConn, "GET / HTTP/1.1\r\nHost: github.com\r\nConnection: close\r\n\r\n"); err != nil {
		t.Fatalf("write local request error = %v", err)
	}
	line, err := bufio.NewReader(tlsConn).ReadString('\n')
	if err != nil {
		t.Fatalf("read 502 status error = %v", err)
	}
	if !strings.Contains(line, "502 Bad Gateway") {
		t.Fatalf("status line = %q, want 502 Bad Gateway", line)
	}
}

func TestHTTPSURLPolicyBlocksBeforeUpstreamDial(t *testing.T) {
	ca, err := pki.GenerateRootCA(time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("GenerateRootCA() error = %v", err)
	}
	server := NewServer("127.0.0.1:0", nil, pki.NewLeafCache(ca.Certificate, ca.PrivateKey))
	policy, err := NewPolicy(PolicyConfig{
		URLs: URLRulesConfig{Blocked: []string{"https://github.com/private"}},
	})
	if err != nil {
		t.Fatalf("NewPolicy() error = %v", err)
	}
	server.SetPolicy(policy)
	server.SetRelayOptions(RelayOptions{IOTimeout: time.Second, Policy: policy})
	var dialed atomic.Bool
	server.SetUpstreamDialer(upstreamDialerFunc(func(context.Context, string, string) (net.Conn, error) {
		dialed.Store(true)
		return nil, errors.New("dial should not happen")
	}))
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen() error = %v", err)
	}
	defer ln.Close()

	errCh := make(chan error, 1)
	go func() {
		errCh <- server.httpServer.Serve(ln)
	}()
	defer func() {
		_ = server.httpServer.Shutdown(context.Background())
		err := <-errCh
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			t.Fatalf("Serve() error = %v", err)
		}
	}()

	tlsConn := connectAndHandshake(t, ln.Addr().String(), ca.Certificate, "github.com")
	defer tlsConn.Close()
	if _, err := io.WriteString(tlsConn, "GET /private/report?q=1 HTTP/1.1\r\nHost: github.com\r\nConnection: close\r\n\r\n"); err != nil {
		t.Fatalf("write local request error = %v", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(tlsConn), nil)
	if err != nil {
		t.Fatalf("read local response error = %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusForbidden)
	}
	if dialed.Load() {
		t.Fatal("upstream dialer was called before HTTPS URL fast-fail")
	}
}

func TestServeHTTPPlainWebSocketPolicyBlocksBeforeDial(t *testing.T) {
	server := NewServer("127.0.0.1:0", nil)
	policy, err := NewPolicy(PolicyConfig{
		Domains: DomainRulesConfig{Blocked: []string{"blocked.test"}},
	})
	if err != nil {
		t.Fatalf("NewPolicy() error = %v", err)
	}
	server.SetPolicy(policy)
	server.SetRelayOptions(RelayOptions{IOTimeout: time.Second, Policy: policy})
	var dialed atomic.Bool
	server.SetPlainHTTPDialer(plainDialerFunc(func(context.Context, string, string) (net.Conn, error) {
		dialed.Store(true)
		return nil, errors.New("dial should not happen")
	}))

	req := httptest.NewRequest(http.MethodGet, "http://blocked.test/ws", nil)
	req.RemoteAddr = "127.0.0.1:50000"
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
	req.Header.Set("Sec-WebSocket-Version", "13")
	rec := httptest.NewRecorder()
	deniedBefore := counterValue(t, WebSocketSessions.WithLabelValues("denied"))

	server.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusForbidden)
	}
	if dialed.Load() {
		t.Fatal("plain HTTP dialer was called before WebSocket policy fast-fail")
	}
	if got := counterValue(t, WebSocketSessions.WithLabelValues("denied")) - deniedBefore; got != 1 {
		t.Fatalf("WebSocketSessions[denied] delta = %v, want 1", got)
	}
}

func TestHTTPSDownstreamH2ServesConcurrentStreams(t *testing.T) {
	ca, err := pki.GenerateRootCA(time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("GenerateRootCA() error = %v", err)
	}
	server := NewServer("127.0.0.1:0", nil, pki.NewLeafCache(ca.Certificate, ca.PrivateKey))
	server.SetRelayOptions(RelayOptions{IOTimeout: time.Second, MaxCaptureBytes: 1 << 20})
	var dials atomic.Int64
	server.SetUpstreamDialer(upstreamDialerFunc(func(context.Context, string, string) (net.Conn, error) {
		dials.Add(1)
		proxySide, upstreamSide := net.Pipe()
		go func() {
			defer upstreamSide.Close()
			req, err := http.ReadRequest(bufio.NewReader(upstreamSide))
			if err != nil {
				return
			}
			_, _ = io.Copy(io.Discard, req.Body)
			_ = req.Body.Close()
			body := "h2 downstream " + req.URL.Path
			_, _ = fmt.Fprintf(upstreamSide,
				"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s",
				len(body), body)
		}()
		return proxySide, nil
	}))
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen() error = %v", err)
	}
	defer ln.Close()
	errCh := make(chan error, 1)
	go func() {
		errCh <- server.httpServer.Serve(ln)
	}()
	defer func() {
		_ = server.httpServer.Shutdown(context.Background())
		err := <-errCh
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			t.Fatalf("Serve() error = %v", err)
		}
	}()

	tlsConn := connectAndHandshakeWithNextProtos(t, ln.Addr().String(), ca.Certificate, "h2down.test", []string{"h2"})
	defer tlsConn.Close()
	if got := tlsConn.ConnectionState().NegotiatedProtocol; got != "h2" {
		t.Fatalf("downstream ALPN = %q, want h2", got)
	}
	tr := &http2.Transport{}
	cc, err := tr.NewClientConn(tlsConn)
	if err != nil {
		t.Fatalf("NewClientConn() error = %v", err)
	}

	paths := []string{"/one", "/two", "/three"}
	var wg sync.WaitGroup
	errs := make(chan error, len(paths))
	for _, path := range paths {
		path := path
		wg.Add(1)
		go func() {
			defer wg.Done()
			req, err := http.NewRequest(http.MethodGet, "https://h2down.test"+path, nil)
			if err != nil {
				errs <- err
				return
			}
			resp, err := cc.RoundTrip(req)
			if err != nil {
				errs <- fmt.Errorf("RoundTrip(%s): %w", path, err)
				return
			}
			defer resp.Body.Close()
			body, err := io.ReadAll(resp.Body)
			if err != nil {
				errs <- fmt.Errorf("ReadAll(%s): %w", path, err)
				return
			}
			if resp.StatusCode != http.StatusOK || string(body) != "h2 downstream "+path {
				errs <- fmt.Errorf("response(%s) = %d %q", path, resp.StatusCode, string(body))
				return
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	if got := dials.Load(); got != int64(len(paths)) {
		t.Fatalf("upstream dials = %d, want %d", got, len(paths))
	}
}

func TestHTTPSDownstreamH2PolicyBlocksBeforeUpstreamDial(t *testing.T) {
	ca, err := pki.GenerateRootCA(time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("GenerateRootCA() error = %v", err)
	}
	policy, err := NewPolicy(PolicyConfig{
		URLs: URLRulesConfig{Blocked: []string{"https://blocked-h2.test/private"}},
	})
	if err != nil {
		t.Fatalf("NewPolicy() error = %v", err)
	}
	server := NewServer("127.0.0.1:0", nil, pki.NewLeafCache(ca.Certificate, ca.PrivateKey))
	server.SetPolicy(policy)
	server.SetRelayOptions(RelayOptions{IOTimeout: time.Second, Policy: policy})
	var dialed atomic.Bool
	server.SetUpstreamDialer(upstreamDialerFunc(func(context.Context, string, string) (net.Conn, error) {
		dialed.Store(true)
		return nil, errors.New("dial should not happen")
	}))
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen() error = %v", err)
	}
	defer ln.Close()
	errCh := make(chan error, 1)
	go func() {
		errCh <- server.httpServer.Serve(ln)
	}()
	defer func() {
		_ = server.httpServer.Shutdown(context.Background())
		err := <-errCh
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			t.Fatalf("Serve() error = %v", err)
		}
	}()

	tlsConn := connectAndHandshakeWithNextProtos(t, ln.Addr().String(), ca.Certificate, "blocked-h2.test", []string{"h2"})
	defer tlsConn.Close()
	if got := tlsConn.ConnectionState().NegotiatedProtocol; got != "h2" {
		t.Fatalf("downstream ALPN = %q, want h2", got)
	}
	tr := &http2.Transport{}
	cc, err := tr.NewClientConn(tlsConn)
	if err != nil {
		t.Fatalf("NewClientConn() error = %v", err)
	}
	req, err := http.NewRequest(http.MethodGet, "https://blocked-h2.test/private/report", nil)
	if err != nil {
		t.Fatalf("NewRequest() error = %v", err)
	}
	resp, err := cc.RoundTrip(req)
	if err != nil {
		t.Fatalf("RoundTrip() error = %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusForbidden)
	}
	if dialed.Load() {
		t.Fatal("upstream dialer was called before downstream h2 policy fast-fail")
	}
}

func TestHTTPSDownstreamH2StripsAltSvc(t *testing.T) {
	ca, err := pki.GenerateRootCA(time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("GenerateRootCA() error = %v", err)
	}
	server := NewServer("127.0.0.1:0", nil, pki.NewLeafCache(ca.Certificate, ca.PrivateKey))
	server.SetRelayOptions(RelayOptions{IOTimeout: time.Second, MaxCaptureBytes: 1 << 20})
	server.SetUpstreamDialer(upstreamDialerFunc(func(context.Context, string, string) (net.Conn, error) {
		proxySide, upstreamSide := net.Pipe()
		go func() {
			defer upstreamSide.Close()
			req, err := http.ReadRequest(bufio.NewReader(upstreamSide))
			if err != nil {
				return
			}
			_, _ = io.Copy(io.Discard, req.Body)
			_ = req.Body.Close()
			_, _ = io.WriteString(upstreamSide,
				"HTTP/1.1 200 OK\r\n"+
					"Alt-Svc: h3=\":443\"; ma=86400\r\n"+
					"Alternate-Protocol: 443:quic\r\n"+
					"Content-Type: text/plain\r\n"+
					"Content-Length: 5\r\n"+
					"Connection: close\r\n"+
					"\r\n"+
					"hello")
		}()
		return proxySide, nil
	}))
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen() error = %v", err)
	}
	defer ln.Close()
	errCh := make(chan error, 1)
	go func() {
		errCh <- server.httpServer.Serve(ln)
	}()
	defer func() {
		_ = server.httpServer.Shutdown(context.Background())
		err := <-errCh
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			t.Fatalf("Serve() error = %v", err)
		}
	}()

	tlsConn := connectAndHandshakeWithNextProtos(t, ln.Addr().String(), ca.Certificate, "altsvc-h2.test", []string{"h2"})
	defer tlsConn.Close()
	tr := &http2.Transport{}
	cc, err := tr.NewClientConn(tlsConn)
	if err != nil {
		t.Fatalf("NewClientConn() error = %v", err)
	}
	req, err := http.NewRequest(http.MethodGet, "https://altsvc-h2.test/", nil)
	if err != nil {
		t.Fatalf("NewRequest() error = %v", err)
	}
	before := counterValue(t, AltSvcStripped)
	resp, err := cc.RoundTrip(req)
	if err != nil {
		t.Fatalf("RoundTrip() error = %v", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("ReadAll() error = %v", err)
	}
	if string(body) != "hello" {
		t.Fatalf("body = %q, want hello", string(body))
	}
	if got := resp.Header.Get("Alt-Svc"); got != "" {
		t.Fatalf("Alt-Svc leaked to downstream h2 client: %q", got)
	}
	if got := resp.Header.Get("Alternate-Protocol"); got != "" {
		t.Fatalf("Alternate-Protocol leaked to downstream h2 client: %q", got)
	}
	if got := counterValue(t, AltSvcStripped) - before; got != 1 {
		t.Fatalf("AltSvcStripped delta = %v, want 1", got)
	}
}

func TestHTTPSFilePolicyBlocksResponseBeforeClientBody(t *testing.T) {
	ca, err := pki.GenerateRootCA(time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("GenerateRootCA() error = %v", err)
	}
	upstreamErr := make(chan error, 1)
	server := NewServer("127.0.0.1:0", nil, pki.NewLeafCache(ca.Certificate, ca.PrivateKey))
	policy, err := NewPolicy(PolicyConfig{
		Files: FileRulesConfig{BannedFilenames: []string{"secret.zip"}},
	})
	if err != nil {
		t.Fatalf("NewPolicy() error = %v", err)
	}
	server.SetPolicy(policy)
	server.SetRelayOptions(RelayOptions{IOTimeout: time.Second, Policy: policy})
	server.SetUpstreamDialer(upstreamDialerFunc(func(context.Context, string, string) (net.Conn, error) {
		proxySide, upstreamSide := net.Pipe()
		go func() {
			defer upstreamSide.Close()
			req, err := http.ReadRequest(bufio.NewReader(upstreamSide))
			if err != nil {
				upstreamErr <- err
				return
			}
			_, _ = io.Copy(io.Discard, req.Body)
			_ = req.Body.Close()
			_, err = io.WriteString(upstreamSide, "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Disposition: attachment; filename=\"secret.zip\"\r\nContent-Type: application/zip\r\nContent-Length: 8\r\n\r\n")
			upstreamErr <- err
		}()
		return proxySide, nil
	}))
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen() error = %v", err)
	}
	defer ln.Close()

	errCh := make(chan error, 1)
	go func() {
		errCh <- server.httpServer.Serve(ln)
	}()
	defer func() {
		_ = server.httpServer.Shutdown(context.Background())
		err := <-errCh
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			t.Fatalf("Serve() error = %v", err)
		}
	}()

	tlsConn := connectAndHandshake(t, ln.Addr().String(), ca.Certificate, "github.com")
	defer tlsConn.Close()
	if _, err := io.WriteString(tlsConn, "GET /download HTTP/1.1\r\nHost: github.com\r\nConnection: close\r\n\r\n"); err != nil {
		t.Fatalf("write local request error = %v", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(tlsConn), nil)
	if err != nil {
		t.Fatalf("read local response error = %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusForbidden)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read response body error = %v", err)
	}
	if strings.Contains(string(body), "ZIP-BODY") {
		t.Fatalf("blocked response leaked upstream body: %q", string(body))
	}
	select {
	case err := <-upstreamErr:
		if err != nil {
			t.Fatalf("upstream error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("upstream server did not finish")
	}
}

func TestRelaySanitizesAndForwardsHTTPRequest(t *testing.T) {
	ca, err := pki.GenerateRootCA(time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("GenerateRootCA() error = %v", err)
	}
	upstreamReq := make(chan *http.Request, 1)
	upstreamErr := make(chan error, 1)
	var logs safeBuffer
	server := NewServer("127.0.0.1:0", slog.New(slog.NewTextHandler(&logs, nil)), pki.NewLeafCache(ca.Certificate, ca.PrivateKey))
	server.SetUpstreamDialer(upstreamDialerFunc(func(_ context.Context, _, _ string) (net.Conn, error) {
		proxySide, upstreamSide := net.Pipe()
		go func() {
			defer upstreamSide.Close()
			req, err := http.ReadRequest(bufio.NewReader(upstreamSide))
			if err != nil {
				upstreamErr <- err
				return
			}
			upstreamReq <- req
			_, err = io.Copy(io.Discard, req.Body)
			_ = req.Body.Close()
			if err != nil {
				upstreamErr <- err
				return
			}
			_, err = io.WriteString(upstreamSide, "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: 5\r\n\r\nworld")
			upstreamErr <- err
		}()
		return proxySide, nil
	}))
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen() error = %v", err)
	}
	defer ln.Close()

	errCh := make(chan error, 1)
	go func() {
		errCh <- server.httpServer.Serve(ln)
	}()
	defer func() {
		_ = server.httpServer.Shutdown(context.Background())
		err := <-errCh
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			t.Fatalf("Serve() error = %v", err)
		}
	}()

	tlsConn := connectAndHandshake(t, ln.Addr().String(), ca.Certificate, "github.com")
	defer tlsConn.Close()

	_, err = io.WriteString(tlsConn, "POST https://github.com/some/path?q=1 HTTP/1.1\r\nHost: github.com\r\nProxy-Connection: keep-alive\r\nX-Forwarded-For: 127.0.0.1\r\nVia: test\r\nX-Real-IP: 127.0.0.1\r\nConnection: close\r\nContent-Length: 5\r\n\r\nhello")
	if err != nil {
		t.Fatalf("write local request error = %v", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(tlsConn), nil)
	if err != nil {
		t.Fatalf("read local response error = %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read response body error = %v", err)
	}
	if string(body) != "world" {
		t.Fatalf("response body = %q, want world", string(body))
	}

	select {
	case err := <-upstreamErr:
		if err != nil {
			t.Fatalf("upstream server error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("upstream server did not finish")
	}

	select {
	case req := <-upstreamReq:
		defer req.Body.Close()
		if req.URL.Scheme != "" || req.URL.Host != "" {
			t.Fatalf("upstream URL = %q, want origin-form", req.URL.String())
		}
		if req.URL.RequestURI() != "/some/path?q=1" {
			t.Fatalf("upstream RequestURI = %q, want /some/path?q=1", req.URL.RequestURI())
		}
		for _, header := range []string{"Proxy-Connection", "X-Forwarded-For", "Via", "X-Real-IP"} {
			if got := req.Header.Get(header); got != "" {
				t.Fatalf("%s header = %q, want empty", header, got)
			}
		}
	case <-time.After(time.Second):
		t.Fatal("upstream request was not captured")
	}
	if got := waitForLog(t, &logs, "msg=exchange", "method=POST", "host=github.com", "status=200", "req_bytes=5", "resp_bytes=5"); got == "" {
		t.Fatalf("log output = %q, want structured exchange log", got)
	}
}

func waitForLog(t *testing.T, logs *safeBuffer, parts ...string) string {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		got := logs.String()
		matched := true
		for _, part := range parts {
			if !strings.Contains(got, part) {
				matched = false
				break
			}
		}
		if matched {
			return got
		}
		time.Sleep(10 * time.Millisecond)
	}
	return ""
}

func TestWriteRequestStreamingDoesNotBufferAboveLimit(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "https://example.com/", strings.NewReader("hello"))
	req.ContentLength = 5
	var out bytes.Buffer
	cap := newBodyCapture(req.Body != nil, RelayOptions{LogBodies: true, MaxCaptureBytes: 4, DumpDir: t.TempDir()})
	got, _, err := writeRequestStreaming(&out, req, cap, RelayOptions{}, nil)
	if err != nil {
		t.Fatalf("writeRequestStreaming() error = %v", err)
	}
	if got != 5 {
		t.Fatalf("logged bytes = %d, want 5", got)
	}
	if got := out.String(); !strings.Contains(got, "\r\n\r\nhello") {
		t.Fatalf("serialized request = %q, want streamed body", got)
	}
	data, truncated, skipped := cap.dumpPayload()
	if string(data) != "hell" || !truncated || skipped != "" {
		t.Fatalf("dump = %q truncated=%t skipped=%q, want bounded prefix", string(data), truncated, skipped)
	}
}

func TestWriteRequestStreamingStopsTextUploadOnSemanticMatch(t *testing.T) {
	filter, err := NewPhraseFilter([]string{"secret upload"})
	if err != nil {
		t.Fatalf("NewPhraseFilter() error = %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "https://example.com/", strings.NewReader("before secret upload after"))
	req.Header.Set("Content-Type", "text/plain")
	req.ContentLength = int64(len("before secret upload after"))
	var out bytes.Buffer
	cap := newBodyCapture(req.Body != nil, RelayOptions{LogBodies: true, MaxCaptureBytes: 4})

	got, _, err := writeRequestStreaming(&out, req, cap, RelayOptions{RequestFilter: filter}, nil)
	if err != nil {
		t.Fatalf("writeRequestStreaming() error = %v", err)
	}
	if got != int64(len("before secret upload")) {
		t.Fatalf("logged bytes = %d, want truncated upload size", got)
	}
	raw := out.String()
	if strings.Contains(raw, "after") {
		t.Fatalf("serialized request leaked bytes after blocked upload: %q", raw)
	}
	if !strings.Contains(raw, "\r\n\r\nbefore secret upload") {
		t.Fatalf("serialized request missing body through match: %q", raw)
	}
}

func TestWriteRequestStreamingBypassesMultipartUpload(t *testing.T) {
	filter := &countingFilter{}
	req := httptest.NewRequest(http.MethodPost, "https://example.com/", strings.NewReader("blocked phrase"))
	req.Header.Set("Content-Type", "multipart/form-data; boundary=x")
	req.ContentLength = int64(len("blocked phrase"))
	var out bytes.Buffer
	cap := newBodyCapture(req.Body != nil, RelayOptions{LogBodies: true, MaxCaptureBytes: 4})

	got, _, err := writeRequestStreaming(&out, req, cap, RelayOptions{RequestFilter: filter}, nil)
	if err != nil {
		t.Fatalf("writeRequestStreaming() error = %v", err)
	}
	if got != int64(len("blocked phrase")) {
		t.Fatalf("logged bytes = %d, want full multipart size", got)
	}
	if !strings.Contains(out.String(), "blocked phrase") {
		t.Fatalf("serialized request missing multipart body: %q", out.String())
	}
	if filter.calls.Load() != 0 {
		t.Fatalf("filter calls = %d, want multipart bypass", filter.calls.Load())
	}
}

func TestWriteResponseStreamingForcesChunkedForMutableContent(t *testing.T) {
	resp := &http.Response{
		Status:        "200 OK",
		StatusCode:    http.StatusOK,
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        make(http.Header),
		Body:          io.NopCloser(strings.NewReader("hello")),
		ContentLength: 5,
	}
	resp.Header.Set("Content-Type", "text/html; charset=utf-8")

	var out bytes.Buffer
	cap := newBodyCapture(resp.Body != nil, RelayOptions{LogBodies: true, MaxCaptureBytes: 1})
	got, _, err := writeResponseStreaming(&out, resp, cap, uppercaseFilter{})
	if err != nil {
		t.Fatalf("writeResponseStreaming() error = %v", err)
	}
	if got != 5 {
		t.Fatalf("logged bytes = %d, want 5", got)
	}
	raw := out.String()
	if strings.Contains(raw, "Content-Length:") {
		t.Fatalf("serialized response contains Content-Length: %q", raw)
	}
	if !strings.Contains(raw, "Transfer-Encoding: chunked\r\n") {
		t.Fatalf("serialized response missing chunked encoding: %q", raw)
	}
	parsed, err := http.ReadResponse(bufio.NewReader(strings.NewReader(raw)), nil)
	if err != nil {
		t.Fatalf("ReadResponse() error = %v", err)
	}
	body, err := io.ReadAll(parsed.Body)
	_ = parsed.Body.Close()
	if err != nil {
		t.Fatalf("read parsed body error = %v", err)
	}
	if string(body) != "HELLO" {
		t.Fatalf("body = %q, want HELLO", string(body))
	}
}

func TestWriteResponseStreamingBypassesBinaryContent(t *testing.T) {
	filter := &countingFilter{}
	resp := &http.Response{
		Status:        "200 OK",
		StatusCode:    http.StatusOK,
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        make(http.Header),
		Body:          io.NopCloser(strings.NewReader("bin")),
		ContentLength: 3,
	}
	resp.Header.Set("Content-Type", "application/octet-stream")

	var out bytes.Buffer
	cap := newBodyCapture(resp.Body != nil, RelayOptions{LogBodies: true, MaxCaptureBytes: 1})
	got, _, err := writeResponseStreaming(&out, resp, cap, filter)
	if err != nil {
		t.Fatalf("writeResponseStreaming() error = %v", err)
	}
	if got != 3 {
		t.Fatalf("logged bytes = %d, want 3", got)
	}
	raw := out.String()
	if !strings.Contains(raw, "Content-Length: 3\r\n") {
		t.Fatalf("serialized response missing Content-Length: %q", raw)
	}
	if strings.Contains(raw, "Transfer-Encoding: chunked\r\n") {
		t.Fatalf("serialized response unexpectedly chunked: %q", raw)
	}
	if filter.calls.Load() != 0 {
		t.Fatalf("filter calls = %d, want 0", filter.calls.Load())
	}
}

func TestWriteResponseStreamingBypassesRangeMediaWhenMagicEnabled(t *testing.T) {
	filter := NewContentFilter(nil, nil, nil, NewMagicFilter([]string{"executable/elf"}), nil)
	body := strings.Repeat("v", 128)
	req := httptest.NewRequest(http.MethodGet, "https://video.example/segment.mp4", nil)
	req.Header.Set("Range", "bytes=1000-1127")
	resp := &http.Response{
		Status:        "206 Partial Content",
		StatusCode:    http.StatusPartialContent,
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        make(http.Header),
		Body:          io.NopCloser(strings.NewReader(body)),
		ContentLength: int64(len(body)),
		Request:       req,
	}
	resp.Header.Set("Content-Type", "video/mp4")
	resp.Header.Set("Content-Range", "bytes 1000-1127/5000")

	var out bytes.Buffer
	cap := newBodyCapture(resp.Body != nil, RelayOptions{LogBodies: true, MaxCaptureBytes: 1})
	got, _, err := writeResponseStreaming(&out, resp, cap, filter)
	if err != nil {
		t.Fatalf("writeResponseStreaming() error = %v", err)
	}
	if got != int64(len(body)) {
		t.Fatalf("logged bytes = %d, want %d", got, len(body))
	}
	raw := out.String()
	if !strings.Contains(raw, "HTTP/1.1 206 Partial Content\r\n") {
		t.Fatalf("serialized response missing 206 status: %q", raw)
	}
	if !strings.Contains(raw, fmt.Sprintf("Content-Length: %d\r\n", len(body))) {
		t.Fatalf("serialized response missing Content-Length: %q", raw)
	}
	if !strings.Contains(raw, "Content-Range: bytes 1000-1127/5000\r\n") {
		t.Fatalf("serialized response missing Content-Range: %q", raw)
	}
	if strings.Contains(raw, "Transfer-Encoding: chunked\r\n") {
		t.Fatalf("range media response unexpectedly chunked: %q", raw)
	}
	if !strings.HasSuffix(raw, "\r\n\r\n"+body) {
		t.Fatalf("range media body mismatch: %q", raw)
	}
}

func TestWriteResponseStreamingBypassesRangeRequestEvenWithOctetStream(t *testing.T) {
	filter := NewContentFilter(nil, nil, nil, NewMagicFilter([]string{"application/octet-stream"}), nil)
	body := strings.Repeat("x", 64)
	req := httptest.NewRequest(http.MethodGet, "https://cdn.example/file.bin", nil)
	req.Header.Set("Range", "bytes=0-63")
	resp := &http.Response{
		Status:        "200 OK",
		StatusCode:    http.StatusOK,
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        make(http.Header),
		Body:          io.NopCloser(strings.NewReader(body)),
		ContentLength: int64(len(body)),
		Request:       req,
	}
	resp.Header.Set("Content-Type", "application/octet-stream")

	var out bytes.Buffer
	cap := newBodyCapture(resp.Body != nil, RelayOptions{LogBodies: true, MaxCaptureBytes: 1})
	if _, _, err := writeResponseStreaming(&out, resp, cap, filter); err != nil {
		t.Fatalf("writeResponseStreaming() error = %v", err)
	}
	raw := out.String()
	if !strings.Contains(raw, fmt.Sprintf("Content-Length: %d\r\n", len(body))) {
		t.Fatalf("serialized response missing Content-Length: %q", raw)
	}
	if strings.Contains(raw, "Transfer-Encoding: chunked\r\n") {
		t.Fatalf("range request response unexpectedly chunked: %q", raw)
	}
	if !strings.HasSuffix(raw, "\r\n\r\n"+body) {
		t.Fatalf("range request body mismatch: %q", raw)
	}
}

func TestWriteResponseStreamingBypassesJavaScriptMutations(t *testing.T) {
	filter := NewContentFilter(
		nil,
		nil,
		nil,
		nil,
		NewSubstitutionFilter(map[string]string{
			"Real Madrid": "Super Real Madrid",
			"Madrid":      "Barcelona",
		}),
	)
	body := `var yt = {"club":"Real Madrid","city":"Madrid"};`
	resp := &http.Response{
		Status:        "200 OK",
		StatusCode:    http.StatusOK,
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        make(http.Header),
		Body:          io.NopCloser(strings.NewReader(body)),
		ContentLength: int64(len(body)),
	}
	resp.Header.Set("Content-Type", "application/javascript")

	var out bytes.Buffer
	cap := newBodyCapture(resp.Body != nil, RelayOptions{LogBodies: true, MaxCaptureBytes: 1})
	got, _, err := writeResponseStreaming(&out, resp, cap, filter)
	if err != nil {
		t.Fatalf("writeResponseStreaming() error = %v", err)
	}
	if got != int64(len(body)) {
		t.Fatalf("logged bytes = %d, want %d", got, len(body))
	}
	raw := out.String()
	if !strings.Contains(raw, fmt.Sprintf("Content-Length: %d\r\n", len(body))) {
		t.Fatalf("serialized response missing original Content-Length: %q", raw)
	}
	if strings.Contains(raw, "Transfer-Encoding: chunked\r\n") {
		t.Fatalf("serialized response unexpectedly chunked: %q", raw)
	}
	if !strings.HasSuffix(raw, "\r\n\r\n"+body) {
		t.Fatalf("serialized JS mutated/truncated: %q", raw)
	}
}

func TestWriteResponseStreamingBypassesEventStreamMutations(t *testing.T) {
	filter := NewContentFilter(
		nil,
		nil,
		nil,
		nil,
		NewSubstitutionFilter(map[string]string{"Real Madrid": "Super Real Madrid"}),
	)
	body := "event: delta\ndata: {\"text\":\"Real Madrid based in Madrid\",\"annotations\":[[0,11]]}\n\n"
	resp := &http.Response{
		Status:        "200 OK",
		StatusCode:    http.StatusOK,
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        make(http.Header),
		Body:          io.NopCloser(strings.NewReader(body)),
		ContentLength: int64(len(body)),
	}
	resp.Header.Set("Content-Type", "text/event-stream")

	var out bytes.Buffer
	cap := newBodyCapture(resp.Body != nil, RelayOptions{LogBodies: true, MaxCaptureBytes: 1})
	got, _, err := writeResponseStreaming(&out, resp, cap, filter)
	if err != nil {
		t.Fatalf("writeResponseStreaming() error = %v", err)
	}
	if got != int64(len(body)) {
		t.Fatalf("logged bytes = %d, want %d", got, len(body))
	}
	raw := out.String()
	if !strings.Contains(raw, fmt.Sprintf("Content-Length: %d\r\n", len(body))) {
		t.Fatalf("serialized response missing original Content-Length: %q", raw)
	}
	if strings.Contains(raw, "Transfer-Encoding: chunked\r\n") {
		t.Fatalf("event-stream response unexpectedly chunked: %q", raw)
	}
	if !strings.HasSuffix(raw, "\r\n\r\n"+body) {
		t.Fatalf("serialized event-stream mutated/truncated: %q", raw)
	}
}

func TestWriteResponseStreamingStillSubstitutesHTML(t *testing.T) {
	filter := NewContentFilter(
		nil,
		nil,
		nil,
		nil,
		NewSubstitutionFilter(map[string]string{"Madrid": "Barcelona"}),
	)
	body := `<html><body>Madrid</body></html>`
	resp := &http.Response{
		Status:        "200 OK",
		StatusCode:    http.StatusOK,
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        make(http.Header),
		Body:          io.NopCloser(strings.NewReader(body)),
		ContentLength: int64(len(body)),
	}
	resp.Header.Set("Content-Type", "text/html")

	var out bytes.Buffer
	cap := newBodyCapture(resp.Body != nil, RelayOptions{LogBodies: true, MaxCaptureBytes: 1})
	if _, _, err := writeResponseStreaming(&out, resp, cap, filter); err != nil {
		t.Fatalf("writeResponseStreaming() error = %v", err)
	}
	raw := out.String()
	if !strings.Contains(raw, "Barcelona") || strings.Contains(raw, ">Madrid<") {
		t.Fatalf("serialized HTML did not substitute as expected: %q", raw)
	}
}

func TestWriteResponseStreamingAppliesRegexSubstitution(t *testing.T) {
	substitution, err := NewSubstitutionFilterWithRegex(nil, []RegexSubstitutionRule{
		{Pattern: `ca.*sa\.png`, Replace: "carcasa.png", MaxWindowBytes: 64},
	})
	if err != nil {
		t.Fatalf("NewSubstitutionFilterWithRegex() error = %v", err)
	}
	filter := NewContentFilter(nil, nil, nil, nil, substitution)
	body := `<html><body><img src="/assets/carpeta/sa.png"></body></html>`
	resp := &http.Response{
		Status:        "200 OK",
		StatusCode:    http.StatusOK,
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        make(http.Header),
		Body:          io.NopCloser(strings.NewReader(body)),
		ContentLength: int64(len(body)),
	}
	resp.Header.Set("Content-Type", "text/html")

	var out bytes.Buffer
	cap := newBodyCapture(resp.Body != nil, RelayOptions{LogBodies: true, MaxCaptureBytes: 1})
	if _, _, err := writeResponseStreaming(&out, resp, cap, filter); err != nil {
		t.Fatalf("writeResponseStreaming() error = %v", err)
	}
	raw := out.String()
	if !strings.Contains(raw, "carcasa.png") || strings.Contains(raw, "carpeta/sa.png") {
		t.Fatalf("serialized HTML did not regex-substitute as expected: %q", raw)
	}
}

func TestWriteResponseStreamingInspectsCompressedMutableContent(t *testing.T) {
	filter, err := NewPhraseFilter([]string{"blocked phrase"})
	if err != nil {
		t.Fatalf("NewPhraseFilter() error = %v", err)
	}
	for _, encoding := range []string{"gzip", "deflate", "br", "zstd"} {
		t.Run(encoding, func(t *testing.T) {
			encoded := encodeTestContent(t, encoding, "before blocked phrase after")
			resp := &http.Response{
				Status:        "200 OK",
				StatusCode:    http.StatusOK,
				ProtoMajor:    1,
				ProtoMinor:    1,
				Header:        make(http.Header),
				Body:          io.NopCloser(bytes.NewReader(encoded)),
				ContentLength: int64(len(encoded)),
			}
			resp.Header.Set("Content-Type", "text/html")
			resp.Header.Set("Content-Encoding", encoding)

			var out bytes.Buffer
			cap := newBodyCapture(resp.Body != nil, RelayOptions{LogBodies: true, MaxCaptureBytes: 1})
			got, _, err := writeResponseStreaming(&out, resp, cap, filter)
			if err != nil {
				t.Fatalf("writeResponseStreaming() error = %v", err)
			}
			if got <= 0 {
				t.Fatalf("logged bytes = %d, want encoded response bytes", got)
			}
			raw := out.String()
			if strings.Contains(raw, "Content-Length:") {
				t.Fatalf("serialized response contains Content-Length: %q", raw)
			}
			if !strings.Contains(raw, "Transfer-Encoding: chunked\r\n") {
				t.Fatalf("serialized response missing chunked encoding: %q", raw)
			}
			parsed, err := http.ReadResponse(bufio.NewReader(strings.NewReader(raw)), nil)
			if err != nil {
				t.Fatalf("ReadResponse() error = %v", err)
			}
			if got := parsed.Header.Get("Content-Encoding"); got != encoding {
				t.Fatalf("Content-Encoding = %q, want %q", got, encoding)
			}
			body, err := io.ReadAll(parsed.Body)
			_ = parsed.Body.Close()
			if err != nil {
				t.Fatalf("read parsed body error = %v", err)
			}
			decoded := decodeTestContent(t, encoding, body)
			if string(decoded) != "before blocked phrase" {
				t.Fatalf("decoded body = %q, want truncated semantic response", string(decoded))
			}
		})
	}
}

func TestWriteResponseStreamingBypassesUnsupportedCompressedMutableContent(t *testing.T) {
	filter := &countingFilter{}
	resp := &http.Response{
		Status:        "200 OK",
		StatusCode:    http.StatusOK,
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        make(http.Header),
		Body:          io.NopCloser(strings.NewReader("lzmadata")),
		ContentLength: 8,
	}
	resp.Header.Set("Content-Type", "text/html")
	resp.Header.Set("Content-Encoding", "lzma")

	var out bytes.Buffer
	cap := newBodyCapture(resp.Body != nil, RelayOptions{LogBodies: true, MaxCaptureBytes: 1})
	_, _, err := writeResponseStreaming(&out, resp, cap, filter)
	if err != nil {
		t.Fatalf("writeResponseStreaming() error = %v", err)
	}
	raw := out.String()
	if !strings.Contains(raw, "Content-Length: 8\r\n") {
		t.Fatalf("serialized response missing Content-Length: %q", raw)
	}
	if strings.Contains(raw, "Transfer-Encoding: chunked\r\n") {
		t.Fatalf("serialized response unexpectedly chunked: %q", raw)
	}
	if filter.calls.Load() != 0 {
		t.Fatalf("filter calls = %d, want 0", filter.calls.Load())
	}
}

func TestSetRelayOptionsPublishesLatestSemanticFilter(t *testing.T) {
	server := NewServer("127.0.0.1:0", nil)
	oldFilter, err := NewPhraseFilter([]string{"old phrase"})
	if err != nil {
		t.Fatalf("NewPhraseFilter(old) error = %v", err)
	}
	newFilter, err := NewPhraseFilter([]string{"new phrase"})
	if err != nil {
		t.Fatalf("NewPhraseFilter(new) error = %v", err)
	}

	server.SetRelayOptions(RelayOptions{LogBodies: true, MaxCaptureBytes: 1, IOTimeout: time.Second, Filter: oldFilter})
	server.SetRelayOptions(RelayOptions{LogBodies: true, MaxCaptureBytes: 1, IOTimeout: time.Second, Filter: newFilter})
	opts := server.relay.Load().(RelayOptions)

	var cleanOut bytes.Buffer
	cleanResp := &http.Response{
		Status:        "200 OK",
		StatusCode:    http.StatusOK,
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        make(http.Header),
		Body:          io.NopCloser(strings.NewReader("old phrase remains allowed")),
		ContentLength: int64(len("old phrase remains allowed")),
	}
	cleanResp.Header.Set("Content-Type", "text/plain")
	if _, _, err := writeResponseStreaming(&cleanOut, cleanResp, newBodyCapture(cleanResp.Body != nil, opts), opts.Filter); err != nil {
		t.Fatalf("writeResponseStreaming(clean) error = %v", err)
	}
	if !strings.Contains(cleanOut.String(), "old phrase remains allowed") {
		t.Fatalf("latest filter unexpectedly used stale phrase: %q", cleanOut.String())
	}

	var blockedOut bytes.Buffer
	blockedResp := &http.Response{
		Status:        "200 OK",
		StatusCode:    http.StatusOK,
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        make(http.Header),
		Body:          io.NopCloser(strings.NewReader("before new phrase after")),
		ContentLength: int64(len("before new phrase after")),
	}
	blockedResp.Header.Set("Content-Type", "text/plain")
	if _, _, err := writeResponseStreaming(&blockedOut, blockedResp, newBodyCapture(blockedResp.Body != nil, opts), opts.Filter); err != nil {
		t.Fatalf("writeResponseStreaming(blocked) error = %v", err)
	}
	if strings.Contains(blockedOut.String(), "after") {
		t.Fatalf("latest filter did not block new phrase: %q", blockedOut.String())
	}
}

func TestPlainHTTPRefererExceptionBypassesResponseFilters(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(w, "before blocked phrase after")
	}))
	defer upstream.Close()

	freeLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen proxy: %v", err)
	}
	proxyAddr := freeLn.Addr().String()
	freeLn.Close()

	policy, err := NewPolicy(PolicyConfig{
		Referer: RefererRulesConfig{
			ExceptionSites: []string{"trusted-ref.test"},
		},
	})
	if err != nil {
		t.Fatalf("NewPolicy() error = %v", err)
	}
	filter, err := NewPhraseFilter([]string{"blocked phrase"})
	if err != nil {
		t.Fatalf("NewPhraseFilter() error = %v", err)
	}
	server := NewServer(proxyAddr, nil)
	server.SetPolicy(policy)
	server.SetRelayOptions(RelayOptions{
		Policy:          policy,
		Filter:          filter,
		IOTimeout:       time.Second,
		LogBodies:       true,
		MaxCaptureBytes: 1024,
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errCh := make(chan error, 1)
	go func() {
		errCh <- server.Serve(ctx)
	}()
	time.Sleep(100 * time.Millisecond)
	defer func() {
		cancel()
		if err := <-errCh; err != nil && err != context.Canceled {
			t.Fatalf("Serve() finished with error: %v", err)
		}
	}()

	proxyURL, err := url.Parse("http://" + proxyAddr)
	if err != nil {
		t.Fatalf("parse proxy URL: %v", err)
	}
	client := &http.Client{
		Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)},
		Timeout:   5 * time.Second,
	}

	resp, err := client.Get(upstream.URL)
	if err != nil {
		t.Fatalf("GET without referer: %v", err)
	}
	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		t.Fatalf("read response without referer: %v", err)
	}
	if strings.Contains(string(body), " after") {
		t.Fatalf("response without referer was not filtered: %q", string(body))
	}

	req, err := http.NewRequest(http.MethodGet, upstream.URL, nil)
	if err != nil {
		t.Fatalf("NewRequest() error = %v", err)
	}
	req.Header.Set("Referer", "https://trusted-ref.test/source")
	resp, err = client.Do(req)
	if err != nil {
		t.Fatalf("GET with referer: %v", err)
	}
	body, err = io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		t.Fatalf("read response with referer: %v", err)
	}
	if string(body) != "before blocked phrase after" {
		t.Fatalf("response with referer = %q, want unfiltered body", string(body))
	}
}

func TestRelaySetsReadAndWriteDeadlines(t *testing.T) {
	localClient, localProxy := net.Pipe()
	upstreamProxy, upstreamServer := net.Pipe()
	defer localClient.Close()
	defer upstreamServer.Close()

	localConn := &deadlineRecordingConn{Conn: localProxy}
	upstreamConn := &deadlineRecordingConn{Conn: upstreamProxy}
	errCh := make(chan error, 1)
	go func() {
		errCh <- relayHTTP(localConn, upstreamConn, nil, RelayOptions{
			LogBodies:       true,
			MaxCaptureBytes: 1 << 20,
			IOTimeout:       time.Second,
		})
	}()

	upstreamErr := make(chan error, 1)
	go func() {
		req, err := http.ReadRequest(bufio.NewReader(upstreamServer))
		if err != nil {
			upstreamErr <- err
			return
		}
		_, _ = io.Copy(io.Discard, req.Body)
		_ = req.Body.Close()
		_, err = io.WriteString(upstreamServer, "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: 2\r\n\r\nok")
		upstreamErr <- err
	}()

	if _, err := io.WriteString(localClient, "GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\nContent-Length: 0\r\n\r\n"); err != nil {
		t.Fatalf("write request error = %v", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(localClient), nil)
	if err != nil {
		t.Fatalf("read response error = %v", err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()

	if err := <-upstreamErr; err != nil {
		t.Fatalf("upstream error = %v", err)
	}
	if err := <-errCh; err != nil {
		t.Fatalf("relayHTTP() error = %v", err)
	}
	if localConn.readDeadlines.Load() == 0 || localConn.writeDeadlines.Load() == 0 {
		t.Fatalf("local deadlines read=%d write=%d, want both set", localConn.readDeadlines.Load(), localConn.writeDeadlines.Load())
	}
	if upstreamConn.readDeadlines.Load() == 0 || upstreamConn.writeDeadlines.Load() == 0 {
		t.Fatalf("upstream deadlines read=%d write=%d, want both set", upstreamConn.readDeadlines.Load(), upstreamConn.writeDeadlines.Load())
	}
}

func TestRelayRenewsBodyDeadlinesWhileStreaming(t *testing.T) {
	localClient, localProxy := net.Pipe()
	upstreamProxy, upstreamServer := net.Pipe()
	defer localClient.Close()
	defer upstreamServer.Close()

	localConn := &deadlineRecordingConn{Conn: localProxy}
	upstreamConn := &deadlineRecordingConn{Conn: upstreamProxy}
	errCh := make(chan error, 1)
	go func() {
		errCh <- relayHTTP(localConn, upstreamConn, nil, RelayOptions{
			LogBodies:       true,
			MaxCaptureBytes: 1 << 20,
			IOTimeout:       time.Second,
		})
	}()

	body := bytes.Repeat([]byte("a"), 96*1024)
	upstreamErr := make(chan error, 1)
	go func() {
		req, err := http.ReadRequest(bufio.NewReader(upstreamServer))
		if err != nil {
			upstreamErr <- err
			return
		}
		_, _ = io.Copy(io.Discard, req.Body)
		_ = req.Body.Close()
		if _, err := fmt.Fprintf(upstreamServer, "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: %d\r\n\r\n", len(body)); err != nil {
			upstreamErr <- err
			return
		}
		for off := 0; off < len(body); off += 8192 {
			end := off + 8192
			if end > len(body) {
				end = len(body)
			}
			if _, err := upstreamServer.Write(body[off:end]); err != nil {
				upstreamErr <- err
				return
			}
		}
		upstreamErr <- nil
	}()

	if _, err := io.WriteString(localClient, "GET /large HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\nContent-Length: 0\r\n\r\n"); err != nil {
		t.Fatalf("write request error = %v", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(localClient), nil)
	if err != nil {
		t.Fatalf("read response error = %v", err)
	}
	got, err := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if err != nil {
		t.Fatalf("read response body error = %v", err)
	}
	if !bytes.Equal(got, body) {
		t.Fatalf("response body length=%d, want %d", len(got), len(body))
	}
	if err := <-upstreamErr; err != nil {
		t.Fatalf("upstream error = %v", err)
	}
	if err := <-errCh; err != nil {
		t.Fatalf("relayHTTP() error = %v", err)
	}
	if got := upstreamConn.readDeadlines.Load(); got < 2 {
		t.Fatalf("upstream read deadlines=%d, want renewal during response body", got)
	}
	if got := localConn.writeDeadlines.Load(); got < 2 {
		t.Fatalf("local write deadlines=%d, want renewal during response body", got)
	}
}

func TestRelayTreatsKeepAliveReadTimeoutAfterExchangeAsCleanClose(t *testing.T) {
	localClient, localProxy := net.Pipe()
	upstreamProxy, upstreamServer := net.Pipe()
	defer localClient.Close()
	defer upstreamServer.Close()

	localConn := &deadlineRecordingConn{Conn: localProxy}
	upstreamConn := &deadlineRecordingConn{Conn: upstreamProxy}
	errCh := make(chan error, 1)
	go func() {
		errCh <- relayHTTP(localConn, upstreamConn, nil, RelayOptions{
			LogBodies:       true,
			MaxCaptureBytes: 1 << 20,
			IOTimeout:       25 * time.Millisecond,
		})
	}()

	upstreamErr := make(chan error, 1)
	go func() {
		req, err := http.ReadRequest(bufio.NewReader(upstreamServer))
		if err != nil {
			upstreamErr <- err
			return
		}
		_, _ = io.Copy(io.Discard, req.Body)
		_ = req.Body.Close()
		_, err = io.WriteString(upstreamServer, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
		upstreamErr <- err
	}()

	if _, err := io.WriteString(localClient, "GET / HTTP/1.1\r\nHost: example.com\r\nContent-Length: 0\r\n\r\n"); err != nil {
		t.Fatalf("write request error = %v", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(localClient), nil)
	if err != nil {
		t.Fatalf("read response error = %v", err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()

	if err := <-upstreamErr; err != nil {
		t.Fatalf("upstream error = %v", err)
	}
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("relayHTTP() error = %v, want clean close", err)
		}
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for relay keep-alive idle close")
	}
}

func connectAndHandshake(t *testing.T, address string, root *x509.Certificate, serverName string) *tls.Conn {
	return connectAndHandshakeWithNextProtos(t, address, root, serverName, nil)
}

func connectAndHandshakeWithNextProtos(t *testing.T, address string, root *x509.Certificate, serverName string, nextProtos []string) *tls.Conn {
	t.Helper()

	conn, err := net.DialTimeout("tcp", address, time.Second)
	if err != nil {
		t.Fatalf("DialTimeout() error = %v", err)
	}

	if _, err := io.WriteString(conn, fmt.Sprintf("CONNECT %s:443 HTTP/1.1\r\nHost: %s:443\r\n\r\n", serverName, serverName)); err != nil {
		conn.Close()
		t.Fatalf("write CONNECT error = %v", err)
	}
	reader := bufio.NewReader(conn)
	line, err := reader.ReadString('\n')
	if err != nil {
		conn.Close()
		t.Fatalf("read status line error = %v", err)
	}
	if !strings.Contains(line, "200 Connection Established") {
		conn.Close()
		t.Fatalf("status line = %q, want 200 Connection Established", line)
	}
	blank, err := reader.ReadString('\n')
	if err != nil {
		conn.Close()
		t.Fatalf("read blank line error = %v", err)
	}
	if blank != "\r\n" {
		conn.Close()
		t.Fatalf("blank line = %q, want CRLF", blank)
	}

	roots := x509.NewCertPool()
	roots.AddCert(root)
	tlsConn := tls.Client(conn, &tls.Config{
		ServerName:         serverName,
		RootCAs:            roots,
		MinVersion:         tls.VersionTLS12,
		NextProtos:         nextProtos,
		InsecureSkipVerify: false,
	})
	if err := tlsConn.Handshake(); err != nil {
		conn.Close()
		t.Fatalf("TLS Handshake() error = %v", err)
	}
	return tlsConn
}

func doH1MITMRequest(t *testing.T, address string, root *x509.Certificate, serverName string, path string) string {
	t.Helper()

	tlsConn := connectAndHandshake(t, address, root, serverName)
	defer tlsConn.Close()
	if _, err := fmt.Fprintf(tlsConn, "GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", path, serverName); err != nil {
		t.Fatalf("write request %s error = %v", path, err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(tlsConn), nil)
	if err != nil {
		t.Fatalf("read response %s error = %v", path, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body %s error = %v", path, err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %s = %d, want 200", path, resp.StatusCode)
	}
	return string(body)
}

func doH2ClientConnRequest(t *testing.T, cc *http2.ClientConn, host string, path string) string {
	t.Helper()

	req, err := http.NewRequest(http.MethodGet, "https://"+host+path, nil)
	if err != nil {
		t.Fatalf("NewRequest(%s) error = %v", path, err)
	}
	resp, err := cc.RoundTrip(req)
	if err != nil {
		t.Fatalf("RoundTrip(%s) error = %v", path, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body %s error = %v", path, err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %s = %d, want 200", path, resp.StatusCode)
	}
	return string(body)
}

func encodeTestContent(t *testing.T, encoding string, body string) []byte {
	t.Helper()
	var out bytes.Buffer
	var w io.WriteCloser
	var err error
	switch encoding {
	case "gzip":
		w = gzip.NewWriter(&out)
	case "deflate":
		w, err = flate.NewWriter(&out, flate.DefaultCompression)
	case "br":
		w = brotli.NewWriter(&out)
	case "zstd":
		enc, encErr := zstd.NewWriter(&out)
		if encErr != nil {
			t.Fatalf("failed to create zstd writer: %v", encErr)
		}
		w = enc
	default:
		t.Fatalf("unsupported test encoding %q", encoding)
	}
	if err != nil {
		t.Fatalf("new encoder %s error = %v", encoding, err)
	}
	if _, err := io.WriteString(w, body); err != nil {
		t.Fatalf("write encoder %s error = %v", encoding, err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("close encoder %s error = %v", encoding, err)
	}
	return out.Bytes()
}

func decodeTestContent(t *testing.T, encoding string, body []byte) []byte {
	t.Helper()
	var r io.ReadCloser
	var err error
	switch encoding {
	case "gzip":
		r, err = gzip.NewReader(bytes.NewReader(body))
	case "deflate":
		r = flate.NewReader(bytes.NewReader(body))
	case "br":
		r = readCloser{Reader: brotli.NewReader(bytes.NewReader(body))}
	case "zstd":
		dec, decErr := zstd.NewReader(bytes.NewReader(body))
		if decErr != nil {
			t.Fatalf("failed to create zstd reader: %v", decErr)
		}
		r = readCloser{Reader: dec, close: func() error { dec.Close(); return nil }}
	default:
		t.Fatalf("unsupported test encoding %q", encoding)
	}
	if err != nil {
		t.Fatalf("new decoder %s error = %v", encoding, err)
	}
	decoded, err := io.ReadAll(r)
	closeErr := r.Close()
	if err != nil {
		t.Fatalf("read decoder %s error = %v", encoding, err)
	}
	if closeErr != nil {
		t.Fatalf("close decoder %s error = %v", encoding, closeErr)
	}
	return decoded
}

type upstreamCall struct {
	address    string
	serverName string
}

type recordingCertificateProvider struct {
	hosts chan string
}

func (p *recordingCertificateProvider) Get(hostname string) (*tls.Certificate, error) {
	p.hosts <- hostname
	return &tls.Certificate{}, nil
}

type fakeUpstreamDialer struct {
	calls chan<- upstreamCall
	err   error
}

func (d fakeUpstreamDialer) Dial(_ context.Context, address, serverName string) (net.Conn, error) {
	if d.calls != nil {
		d.calls <- upstreamCall{address: address, serverName: serverName}
	}
	if d.err != nil {
		return nil, d.err
	}
	client, server := net.Pipe()
	_ = client.Close()
	return server, nil
}

type upstreamDialerFunc func(context.Context, string, string) (net.Conn, error)

func (f upstreamDialerFunc) Dial(ctx context.Context, address, serverName string) (net.Conn, error) {
	return f(ctx, address, serverName)
}

type plainDialerFunc func(context.Context, string, string) (net.Conn, error)

func (f plainDialerFunc) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return f(ctx, network, address)
}

type deadlineRecordingConn struct {
	net.Conn
	readDeadlines  atomic.Int64
	writeDeadlines atomic.Int64
}

type uppercaseFilter struct{}

func (uppercaseFilter) ProcessChunk(in []byte) ([]byte, bool, error) {
	return bytes.ToUpper(in), false, nil
}

type countingFilter struct {
	calls atomic.Int64
}

func (f *countingFilter) ProcessChunk(in []byte) ([]byte, bool, error) {
	f.calls.Add(1)
	return in, false, nil
}

func (c *deadlineRecordingConn) SetReadDeadline(t time.Time) error {
	c.readDeadlines.Add(1)
	return c.Conn.SetReadDeadline(t)
}

func (c *deadlineRecordingConn) SetWriteDeadline(t time.Time) error {
	c.writeDeadlines.Add(1)
	return c.Conn.SetWriteDeadline(t)
}

func TestServeHTTPAcquiresAfterWait(t *testing.T) {
	server := NewServer("127.0.0.1:0", nil)
	server.SetMaxConnections(1)
	server.SetWaitTimeout(200 * time.Millisecond)

	// Acquire the single slot
	permit, ok := server.acquireConn(context.Background())
	if !ok {
		t.Fatal("failed to occupy first connection slot")
	}

	acquiredCh := make(chan bool)
	go func() {
		// Attempt to acquire second slot - should block until first is released
		p2, ok2 := server.acquireConn(context.Background())
		if ok2 {
			server.releaseConn(p2)
		}
		acquiredCh <- ok2
	}()

	// Wait 50ms (less than 200ms timeout) and release first slot
	time.Sleep(50 * time.Millisecond)
	server.releaseConn(permit)

	select {
	case success := <-acquiredCh:
		if !success {
			t.Fatal("second slot acquisition failed despite releasing the first slot in time")
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("timeout waiting for second slot acquisition goroutine to complete")
	}
}

func TestServeHTTPTimeoutExceeded(t *testing.T) {
	server := NewServer("127.0.0.1:0", nil)
	server.SetMaxConnections(1)
	server.SetWaitTimeout(50 * time.Millisecond)

	// Acquire the single slot
	permit, ok := server.acquireConn(context.Background())
	if !ok {
		t.Fatal("failed to occupy first connection slot")
	}
	defer server.releaseConn(permit)

	// Attempt to acquire second slot with 50ms waitTimeout - should fail/timeout
	start := time.Now()
	p2, ok2 := server.acquireConn(context.Background())
	duration := time.Since(start)

	if ok2 {
		server.releaseConn(p2)
		t.Fatal("managed to acquire second slot but it should have been blocked")
	}

	if duration < 40*time.Millisecond {
		t.Fatalf("wait timeout was too short: %s, expected ~50ms", duration)
	}
}

type safeBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (s *safeBuffer) Write(p []byte) (n int, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.Write(p)
}

func (s *safeBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.String()
}

func TestCertPreGenerationWorkers(t *testing.T) {
	ca, err := pki.GenerateRootCA(time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("GenerateRootCA() error = %v", err)
	}
	cache := pki.NewLeafCache(ca.Certificate, ca.PrivateKey)
	server := NewServer("127.0.0.1:0", nil, cache)
	server.SetCertWorkers(2)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Launch background workers
	server.startCertWorkers(ctx)

	// Proactively queue a hostname for pre-generation
	server.preGenerateCert("prefetch.test")

	// Wait up to 500ms for workers to process and cache the certificate
	deadline := time.Now().Add(500 * time.Millisecond)
	var found bool
	for time.Now().Before(deadline) {
		if cache.Len() > 0 {
			found = true
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	if !found {
		t.Fatal("background workers failed to pre-generate and cache the certificate in time")
	}

	// Double check we have a cache hit now when doing Get()
	cert, err := cache.Get("prefetch.test")
	if err != nil {
		t.Fatalf("failed to retrieve pre-generated cert: %v", err)
	}
	if cert == nil {
		t.Fatal("returned certificate was nil")
	}
}

func getCounterValue(counter prometheus.Counter) float64 {
	var m dto.Metric
	_ = counter.Write(&m)
	return m.GetCounter().GetValue()
}

func TestServeHTTPRejectedMetric(t *testing.T) {
	server := NewServer("127.0.0.1:0", nil)
	server.SetMaxConnections(1)
	permit, ok := server.acquireConn(context.Background())
	if !ok {
		t.Fatal("failed to occupy connection slot")
	}
	defer server.releaseConn(permit)

	before := getCounterValue(ConnectionsRejected.WithLabelValues("max_connections"))

	req := httptest.NewRequest(http.MethodConnect, "http://example.com:443/", nil)
	req.RemoteAddr = "127.0.0.1:50000"
	rec := httptest.NewRecorder()

	server.ServeHTTP(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusServiceUnavailable)
	}

	after := getCounterValue(ConnectionsRejected.WithLabelValues("max_connections"))
	if after != before+1 {
		t.Fatalf("ConnectionsRejected metric after = %f, want %f", after, before+1)
	}
}

func TestMITMBypassTrivial(t *testing.T) {
	server := NewServer("127.0.0.1:0", nil)
	server.SetMITMBypass([]string{"bypass.test", "*.wildcard.test"})

	if !server.shouldBypassMITM("bypass.test") {
		t.Error("bypass.test should be bypassed")
	}
	if !server.shouldBypassMITM("sub.wildcard.test") {
		t.Error("sub.wildcard.test should be bypassed")
	}
	if server.shouldBypassMITM("nobypass.test") {
		t.Error("nobypass.test should not be bypassed")
	}
}

func TestLogBodiesSampleRateOpt(t *testing.T) {
	opts := RelayOptions{
		LogBodies:           true,
		LogBodiesSampleRate: 0.5,
		MaxCaptureBytes:     1024,
	}
	if opts.LogBodiesSampleRate != 0.5 {
		t.Fatalf("LogBodiesSampleRate = %f, want 0.5", opts.LogBodiesSampleRate)
	}
}

func TestQoSProfileMaxConnections(t *testing.T) {
	server := NewServer("127.0.0.1:0", nil)
	server.SetWaitTimeout(0) // non-blocking for quick test

	// Configure profiles:
	// "limited" has MaxConns = 1
	// "unlimited" has no specific MaxConns limit
	limitVal := 1
	profiles := []AccessProfile{
		{
			Name:     "limited",
			Clients:  []string{"192.168.1.0/24"},
			MaxConns: &limitVal,
		},
		{
			Name:    "unlimited",
			Clients: []string{"10.0.0.0/24"},
		},
	}
	access, err := NewAccessRules(profiles)
	if err != nil {
		t.Fatal(err)
	}
	server.SetAccessRules(access)
	server.SetProfileMaxConnections(profiles)

	// 1. Occupy the only slot for "limited" profile
	permit, ok, _ := server.acquireConnForProfile(context.Background(), "limited")
	if !ok {
		t.Fatal("failed to occupy slot for limited profile")
	}
	defer server.releaseConn(permit)

	// 2. Request from the limited profile IP should be rejected with 503
	beforeLimited := getCounterValue(ConnectionsRejected.WithLabelValues("profile_max_connections"))

	req1 := httptest.NewRequest(http.MethodConnect, "http://example.com:443/", nil)
	req1.RemoteAddr = "192.168.1.5:50000"
	rec1 := httptest.NewRecorder()
	server.ServeHTTP(rec1, req1)

	if rec1.Code != http.StatusServiceUnavailable {
		t.Fatalf("limited req status = %d, want %d", rec1.Code, http.StatusServiceUnavailable)
	}

	afterLimited := getCounterValue(ConnectionsRejected.WithLabelValues("profile_max_connections"))
	if afterLimited != beforeLimited+1 {
		t.Fatalf("metric profile_max_connections after = %f, want %f", afterLimited, beforeLimited+1)
	}

	// 3. Request from the unlimited profile IP should NOT be rejected with 503
	req2 := httptest.NewRequest(http.MethodConnect, "http://example.com:443/", nil)
	req2.RemoteAddr = "10.0.0.5:50000"
	rec2 := httptest.NewRecorder()
	server.ServeHTTP(rec2, req2)

	// Should not get 503 limit exceeded. It might get 400 bad connect host or other error, but not 503.
	if rec2.Code == http.StatusServiceUnavailable {
		t.Fatalf("unlimited req should not get 503, got %d", rec2.Code)
	}
}

func TestQoSClientRateLimiting(t *testing.T) {
	server := NewServer("127.0.0.1:0", nil)

	// Configure profile with RateLimit = 100 req/s, Burst = 2
	rateVal := 100.0
	burstVal := 2
	profiles := []AccessProfile{
		{
			Name:      "ratelimited",
			Clients:   []string{"192.168.2.0/24"},
			RateLimit: &rateVal,
			RateBurst: &burstVal,
		},
	}
	access, err := NewAccessRules(profiles)
	if err != nil {
		t.Fatal(err)
	}
	server.SetAccessRules(access)
	server.SetProfileMaxConnections(profiles)

	// 1. IP 192.168.2.5 - first two requests should pass the rate limit check
	for i := 0; i < 2; i++ {
		req := httptest.NewRequest(http.MethodConnect, "http://example.com:443/", nil)
		req.RemoteAddr = "192.168.2.5:50000"
		rec := httptest.NewRecorder()
		server.ServeHTTP(rec, req)

		// Might fail with bad host or block page (not rate limit), but must NOT get 429.
		if rec.Code == http.StatusTooManyRequests {
			t.Fatalf("request %d was rate limited prematurely", i)
		}
	}

	// 2. Third request from 192.168.2.5 should be rejected with 429
	beforeRate := getCounterValue(ConnectionsRejected.WithLabelValues("rate_limit"))

	req3 := httptest.NewRequest(http.MethodConnect, "http://example.com:443/", nil)
	req3.RemoteAddr = "192.168.2.5:50000"
	rec3 := httptest.NewRecorder()
	server.ServeHTTP(rec3, req3)

	if rec3.Code != http.StatusTooManyRequests {
		t.Fatalf("third request status = %d, want %d", rec3.Code, http.StatusTooManyRequests)
	}

	afterRate := getCounterValue(ConnectionsRejected.WithLabelValues("rate_limit"))
	if afterRate != beforeRate+1 {
		t.Fatalf("metric rate_limit after = %f, want %f", afterRate, beforeRate+1)
	}

	// 3. Request from IP 192.168.2.6 (different client) should NOT be rate limited
	req4 := httptest.NewRequest(http.MethodConnect, "http://example.com:443/", nil)
	req4.RemoteAddr = "192.168.2.6:50000"
	rec4 := httptest.NewRecorder()
	server.ServeHTTP(rec4, req4)

	if rec4.Code == http.StatusTooManyRequests {
		t.Fatalf("request from different IP was rate limited incorrectly")
	}
}

type fakeDialerWithVerify struct {
	dial func(context.Context, string, string) (net.Conn, error)
}

func (f fakeDialerWithVerify) Dial(ctx context.Context, address, serverName string) (net.Conn, error) {
	return f.dial(ctx, address, serverName)
}

func TestQoSUpstreamH2NegotiationAndFallback(t *testing.T) {
	ca, err := pki.GenerateRootCA(time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("GenerateRootCA() error = %v", err)
	}

	var dials atomic.Int64
	var h2Requests atomic.Int64

	// 1. Create a local TLS test server with H2 enabled
	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h2Requests.Add(1)
		w.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(w, "hello from h2 upstream")
	}))
	ts.EnableHTTP2 = true
	ts.StartTLS()
	defer ts.Close()

	server := NewServer("127.0.0.1:0", nil, pki.NewLeafCache(ca.Certificate, ca.PrivateKey))
	server.SetRelayOptions(RelayOptions{
		LogBodies:       true,
		MaxCaptureBytes: 1024,
		IOTimeout:       2 * time.Second,
	})

	// Configure real uTLS-compatible TLS dialer over net.Dial pointing to ts
	h2Dialer := fakeDialerWithVerify{
		dial: func(ctx context.Context, addr, serverName string) (net.Conn, error) {
			dials.Add(1)
			conf := ts.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
			conf.InsecureSkipVerify = true
			conf.ServerName = serverName
			conf.NextProtos = []string{"h2", "http/1.1"}
			conn, err := net.Dial("tcp", ts.Listener.Addr().String())
			if err != nil {
				return nil, err
			}
			tlsConn := tls.Client(conn, conf)
			if err := tlsConn.Handshake(); err != nil {
				_ = conn.Close()
				return nil, err
			}
			return tlsConn, nil
		},
	}
	server.SetH2UpstreamDialer(h2Dialer)
	server.SetUpstreamDialer(h2Dialer)

	// Set up local server listener to handle intercepted connections
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen() error = %v", err)
	}
	defer ln.Close()

	errCh := make(chan error, 1)
	go func() {
		errCh <- server.httpServer.Serve(ln)
	}()
	defer func() {
		_ = server.httpServer.Shutdown(context.Background())
		_ = <-errCh
	}()

	// 2. Perform first request. This should dial the backend, negotiate H2,
	// register the host in h2Hosts, inject the connection into h2Transport,
	// and serve the request multiplexed.
	tlsConn1 := connectAndHandshake(t, ln.Addr().String(), ca.Certificate, "h2host.test")
	defer tlsConn1.Close()

	if _, err := io.WriteString(tlsConn1, "GET / HTTP/1.1\r\nHost: h2host.test\r\nConnection: keep-alive\r\n\r\n"); err != nil {
		t.Fatalf("write req1 error = %v", err)
	}

	reader1 := bufio.NewReader(tlsConn1)
	resp1, err := http.ReadResponse(reader1, nil)
	if err != nil {
		t.Fatalf("read resp1 error = %v", err)
	}
	defer resp1.Body.Close()

	body1, _ := io.ReadAll(resp1.Body)
	if string(body1) != "hello from h2 upstream" {
		t.Fatalf("resp1 body = %q, want %q", body1, "hello from h2 upstream")
	}

	// 3. Verify H2 negotiation took place and host was cached
	if dials.Load() != 1 {
		t.Fatalf("expected 1 dial, got %d", dials.Load())
	}
	if h2Requests.Load() != 1 {
		t.Fatalf("expected 1 h2 request, got %d", h2Requests.Load())
	}

	// 4. Perform second request sequentially or concurrently. It MUST reuse
	// the physical connection, meaning dials count should remain 1.
	tlsConn2 := connectAndHandshake(t, ln.Addr().String(), ca.Certificate, "h2host.test")
	defer tlsConn2.Close()

	if _, err := io.WriteString(tlsConn2, "GET / HTTP/1.1\r\nHost: h2host.test\r\nConnection: close\r\n\r\n"); err != nil {
		t.Fatalf("write req2 error = %v", err)
	}

	reader2 := bufio.NewReader(tlsConn2)
	resp2, err := http.ReadResponse(reader2, nil)
	if err != nil {
		t.Fatalf("read resp2 error = %v", err)
	}
	defer resp2.Body.Close()

	body2, _ := io.ReadAll(resp2.Body)
	if string(body2) != "hello from h2 upstream" {
		t.Fatalf("resp2 body = %q, want %q", body2, "hello from h2 upstream")
	}

	// Re-verify that NO new dial was opened! That's the power of H2 multiplexed upstream!
	if dials.Load() != 1 {
		t.Fatalf("expected exactly 1 dial due to H2 multiplexing, but got %d dials", dials.Load())
	}
	if h2Requests.Load() != 2 {
		t.Fatalf("expected 2 h2 requests served, got %d", h2Requests.Load())
	}
}

func TestQoSUpstreamH2MultiplexesConcurrentH1Clients(t *testing.T) {
	ca, err := pki.GenerateRootCA(time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("GenerateRootCA() error = %v", err)
	}

	var dials atomic.Int64
	var h2Requests atomic.Int64
	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h2Requests.Add(1)
		time.Sleep(20 * time.Millisecond)
		w.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(w, "hello "+r.URL.Path)
	}))
	ts.EnableHTTP2 = true
	ts.StartTLS()
	defer ts.Close()

	server := NewServer("127.0.0.1:0", nil, pki.NewLeafCache(ca.Certificate, ca.PrivateKey))
	server.SetRelayOptions(RelayOptions{
		LogBodies:       true,
		MaxCaptureBytes: 1024,
		IOTimeout:       2 * time.Second,
	})
	h2Dialer := fakeDialerWithVerify{
		dial: func(ctx context.Context, addr, serverName string) (net.Conn, error) {
			dials.Add(1)
			conf := ts.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
			conf.InsecureSkipVerify = true
			conf.ServerName = serverName
			conf.NextProtos = []string{"h2", "http/1.1"}
			conn, err := net.Dial("tcp", ts.Listener.Addr().String())
			if err != nil {
				return nil, err
			}
			tlsConn := tls.Client(conn, conf)
			if err := tlsConn.Handshake(); err != nil {
				_ = conn.Close()
				return nil, err
			}
			return tlsConn, nil
		},
	}
	server.SetH2UpstreamDialer(h2Dialer)
	server.SetUpstreamDialer(h2Dialer)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen() error = %v", err)
	}
	defer ln.Close()
	errCh := make(chan error, 1)
	go func() {
		errCh <- server.httpServer.Serve(ln)
	}()
	defer func() {
		_ = server.httpServer.Shutdown(context.Background())
		_ = <-errCh
	}()

	// Warm the host once so the proxy detects and caches the upstream h2 conn.
	if body := doH1MITMRequest(t, ln.Addr().String(), ca.Certificate, "h2multi.test", "/warm"); body != "hello /warm" {
		t.Fatalf("warm body = %q", body)
	}
	if dials.Load() != 1 {
		t.Fatalf("warm dials = %d, want 1", dials.Load())
	}

	paths := []string{"/a", "/b", "/c", "/d", "/e"}
	var wg sync.WaitGroup
	errs := make(chan error, len(paths))
	for _, path := range paths {
		path := path
		wg.Add(1)
		go func() {
			defer wg.Done()
			body := doH1MITMRequest(t, ln.Addr().String(), ca.Certificate, "h2multi.test", path)
			if body != "hello "+path {
				errs <- fmt.Errorf("body for %s = %q", path, body)
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	if got := dials.Load(); got != 1 {
		t.Fatalf("upstream dials = %d, want 1 for warmed concurrent h2 multiplexing", got)
	}
	if got, want := h2Requests.Load(), int64(len(paths)+1); got != want {
		t.Fatalf("h2 requests = %d, want %d", got, want)
	}
}

func TestQoSUpstreamH2MultiplexesConcurrentDownstreamH2Streams(t *testing.T) {
	ca, err := pki.GenerateRootCA(time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("GenerateRootCA() error = %v", err)
	}

	var dials atomic.Int64
	var h2Requests atomic.Int64
	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h2Requests.Add(1)
		time.Sleep(20 * time.Millisecond)
		w.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(w, "hello "+r.URL.Path)
	}))
	ts.EnableHTTP2 = true
	ts.StartTLS()
	defer ts.Close()

	server := NewServer("127.0.0.1:0", nil, pki.NewLeafCache(ca.Certificate, ca.PrivateKey))
	server.SetRelayOptions(RelayOptions{
		LogBodies:       true,
		MaxCaptureBytes: 1024,
		IOTimeout:       2 * time.Second,
	})
	h2Dialer := fakeDialerWithVerify{
		dial: func(ctx context.Context, addr, serverName string) (net.Conn, error) {
			dials.Add(1)
			conf := ts.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
			conf.InsecureSkipVerify = true
			conf.ServerName = serverName
			conf.NextProtos = []string{"h2", "http/1.1"}
			conn, err := net.Dial("tcp", ts.Listener.Addr().String())
			if err != nil {
				return nil, err
			}
			tlsConn := tls.Client(conn, conf)
			if err := tlsConn.Handshake(); err != nil {
				_ = conn.Close()
				return nil, err
			}
			return tlsConn, nil
		},
	}
	server.SetH2UpstreamDialer(h2Dialer)
	server.SetUpstreamDialer(h2Dialer)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen() error = %v", err)
	}
	defer ln.Close()
	errCh := make(chan error, 1)
	go func() {
		errCh <- server.httpServer.Serve(ln)
	}()
	defer func() {
		_ = server.httpServer.Shutdown(context.Background())
		_ = <-errCh
	}()

	tlsConn := connectAndHandshakeWithNextProtos(t, ln.Addr().String(), ca.Certificate, "h2both.test", []string{"h2"})
	defer tlsConn.Close()
	if got := tlsConn.ConnectionState().NegotiatedProtocol; got != "h2" {
		t.Fatalf("downstream ALPN = %q, want h2", got)
	}
	tr := &http2.Transport{}
	cc, err := tr.NewClientConn(tlsConn)
	if err != nil {
		t.Fatalf("NewClientConn() error = %v", err)
	}
	if body := doH2ClientConnRequest(t, cc, "h2both.test", "/warm"); body != "hello /warm" {
		t.Fatalf("warm body = %q", body)
	}
	if dials.Load() != 1 {
		t.Fatalf("warm dials = %d, want 1", dials.Load())
	}

	paths := []string{"/a", "/b", "/c", "/d", "/e"}
	var wg sync.WaitGroup
	errs := make(chan error, len(paths))
	for _, path := range paths {
		path := path
		wg.Add(1)
		go func() {
			defer wg.Done()
			body := doH2ClientConnRequest(t, cc, "h2both.test", path)
			if body != "hello "+path {
				errs <- fmt.Errorf("body for %s = %q", path, body)
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	if got := dials.Load(); got != 1 {
		t.Fatalf("upstream dials = %d, want 1 for warmed downstream h2 streams", got)
	}
	if got, want := h2Requests.Load(), int64(len(paths)+1); got != want {
		t.Fatalf("h2 requests = %d, want %d", got, want)
	}
}

func TestQoSUpstreamFallbackToHTTP1(t *testing.T) {
	ca, err := pki.GenerateRootCA(time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("GenerateRootCA() error = %v", err)
	}

	var dials atomic.Int64
	var h1Requests atomic.Int64

	// 1. Create a local TLS test server with H2 DISABLED (only HTTP/1.1)
	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h1Requests.Add(1)
		w.Header().Set("Connection", "close")
		w.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(w, "hello from h1 upstream")
	}))
	ts.EnableHTTP2 = false
	ts.StartTLS()
	defer ts.Close()

	server := NewServer("127.0.0.1:0", nil, pki.NewLeafCache(ca.Certificate, ca.PrivateKey))
	server.SetRelayOptions(RelayOptions{
		LogBodies:       true,
		MaxCaptureBytes: 1024,
		IOTimeout:       2 * time.Second,
	})

	h1Dialer := fakeDialerWithVerify{
		dial: func(ctx context.Context, addr, serverName string) (net.Conn, error) {
			dials.Add(1)
			conf := ts.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
			conf.InsecureSkipVerify = true
			conf.ServerName = serverName
			conf.NextProtos = []string{"http/1.1"}
			conn, err := net.Dial("tcp", ts.Listener.Addr().String())
			if err != nil {
				return nil, err
			}
			tlsConn := tls.Client(conn, conf)
			if err := tlsConn.Handshake(); err != nil {
				_ = conn.Close()
				return nil, err
			}
			return tlsConn, nil
		},
	}
	server.SetH2UpstreamDialer(h1Dialer)
	server.SetUpstreamDialer(h1Dialer)

	// Set up local server listener to handle intercepted connections
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen() error = %v", err)
	}
	defer ln.Close()

	errCh := make(chan error, 1)
	go func() {
		errCh <- server.httpServer.Serve(ln)
	}()
	defer func() {
		_ = server.httpServer.Shutdown(context.Background())
		_ = <-errCh
	}()

	// 2. Perform first request. This should dial the backend, negotiate HTTP/1.1,
	// and register the host in h2Hosts as false.
	tlsConn1 := connectAndHandshake(t, ln.Addr().String(), ca.Certificate, "h1host.test")
	defer tlsConn1.Close()

	if _, err := io.WriteString(tlsConn1, "GET / HTTP/1.1\r\nHost: h1host.test\r\nConnection: close\r\n\r\n"); err != nil {
		t.Fatalf("write req1 error = %v", err)
	}

	reader1 := bufio.NewReader(tlsConn1)
	resp1, err := http.ReadResponse(reader1, nil)
	if err != nil {
		t.Fatalf("read resp1 error = %v", err)
	}
	defer resp1.Body.Close()

	body1, _ := io.ReadAll(resp1.Body)
	if string(body1) != "hello from h1 upstream" {
		t.Fatalf("resp1 body = %q, want %q", body1, "hello from h1 upstream")
	}

	// 3. Verify HTTP/1.1 was negotiated and host is stored as false
	if val, ok := server.h2Hosts.Load("h1host.test"); !ok || val.(bool) {
		t.Fatalf("expected host h1host.test to be cached as false, got ok=%v, val=%v", ok, val)
	}

	// 4. Perform second request. Since H2 is false, it MUST dial a new physical connection!
	tlsConn2 := connectAndHandshake(t, ln.Addr().String(), ca.Certificate, "h1host.test")
	defer tlsConn2.Close()

	if _, err := io.WriteString(tlsConn2, "GET / HTTP/1.1\r\nHost: h1host.test\r\nConnection: close\r\n\r\n"); err != nil {
		t.Fatalf("write req2 error = %v", err)
	}

	reader2 := bufio.NewReader(tlsConn2)
	resp2, err := http.ReadResponse(reader2, nil)
	if err != nil {
		t.Fatalf("read resp2 error = %v", err)
	}
	defer resp2.Body.Close()

	body2, _ := io.ReadAll(resp2.Body)
	if string(body2) != "hello from h1 upstream" {
		t.Fatalf("resp2 body = %q, want %q", body2, "hello from h1 upstream")
	}

	// Should have dialed twice!
	if dials.Load() != 2 {
		t.Fatalf("expected exactly 2 dials due to HTTP/1.1 fallback, but got %d dials", dials.Load())
	}
}

func TestServerSO_REUSEPORT(t *testing.T) {
	// Find a free port
	freeLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("find free port: %v", err)
	}
	addr := freeLn.Addr().String()
	freeLn.Close()

	// Initialize server
	logger := slog.New(slog.NewJSONHandler(&bytes.Buffer{}, nil))
	server := NewServer(addr, logger)
	server.SetReusePort(true)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- server.Serve(ctx)
	}()

	// Wait for server to start
	time.Sleep(100 * time.Millisecond)

	// Verify we can connect to the reuseport server
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("failed to connect to reuseport server: %v", err)
	}
	conn.Close()

	// Shutdown
	cancel()
	err = <-errCh
	if err != nil && err != context.Canceled {
		t.Fatalf("Serve() finished with error: %v", err)
	}
}

func TestMITMBypassIntegration(t *testing.T) {
	// 1. Start a mock upstream TCP server
	upstreamLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen upstream: %v", err)
	}
	defer upstreamLn.Close()

	upstreamAddr := upstreamLn.Addr().String()
	_, upstreamPort, _ := net.SplitHostPort(upstreamAddr)

	go func() {
		conn, err := upstreamLn.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		// Echo test bytes back
		buf := make([]byte, 1024)
		n, err := conn.Read(buf)
		if err != nil {
			return
		}
		_, _ = conn.Write(buf[:n])
	}()

	// 2. Start LucidGate server with bypass enabled for "127.0.0.1"
	freeLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen proxy: %v", err)
	}
	proxyAddr := freeLn.Addr().String()
	freeLn.Close()

	logger := slog.New(slog.NewJSONHandler(&bytes.Buffer{}, nil))
	server := NewServer(proxyAddr, logger)
	server.SetMITMBypass([]string{"127.0.0.1"})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- server.Serve(ctx)
	}()

	// Wait for server to start
	time.Sleep(100 * time.Millisecond)

	// 3. Connect to the proxy and send a CONNECT request
	clientConn, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer clientConn.Close()

	reqStr := fmt.Sprintf("CONNECT 127.0.0.1:%s HTTP/1.1\r\nHost: 127.0.0.1:%s\r\n\r\n", upstreamPort, upstreamPort)
	if _, err := clientConn.Write([]byte(reqStr)); err != nil {
		t.Fatalf("write CONNECT: %v", err)
	}

	// Read CONNECT response
	reader := bufio.NewReader(clientConn)
	line, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("read CONNECT response line: %v", err)
	}
	if !strings.Contains(line, "200") {
		t.Fatalf("expected 200 Connection Established, got: %q", line)
	}

	// Drain headers (read until empty line)
	for {
		l, err := reader.ReadString('\n')
		if err != nil {
			t.Fatalf("read header: %v", err)
		}
		if l == "\r\n" || l == "\n" {
			break
		}
	}

	// 4. Send payload to the proxy (it will go through the zero-copy splice path!)
	payload := []byte("hello zero-copy splice")
	if _, err := clientConn.Write(payload); err != nil {
		t.Fatalf("write payload: %v", err)
	}

	// Read echoed response
	buf := make([]byte, len(payload))
	n, err := io.ReadFull(clientConn, buf)
	if err != nil {
		t.Fatalf("read echo: %v", err)
	}

	if string(buf[:n]) != string(payload) {
		t.Fatalf("got echo = %q, want %q", buf[:n], payload)
	}
}

func TestHijackedConnectionTrackingAndDraining(t *testing.T) {
	// Find a free port
	freeLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen proxy: %v", err)
	}
	proxyAddr := freeLn.Addr().String()
	freeLn.Close()

	// Start a mock upstream TCP server
	upstreamLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen upstream: %v", err)
	}
	defer upstreamLn.Close()

	upstreamAddr := upstreamLn.Addr().String()
	_, upstreamPort, _ := net.SplitHostPort(upstreamAddr)

	go func() {
		conn, err := upstreamLn.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		buf := make([]byte, 1024)
		_, _ = conn.Read(buf)
	}()

	logger := slog.New(slog.NewJSONHandler(&bytes.Buffer{}, nil))
	server := NewServer(proxyAddr, logger)
	server.SetMITMBypass([]string{"127.0.0.1"})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- server.Serve(ctx)
	}()

	// Wait for server to start
	time.Sleep(100 * time.Millisecond)

	// Connect to the proxy and send a CONNECT request to hijack it
	clientConn, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer clientConn.Close()

	reqStr := fmt.Sprintf("CONNECT 127.0.0.1:%s HTTP/1.1\r\nHost: 127.0.0.1:%s\r\n\r\n", upstreamPort, upstreamPort)
	if _, err := clientConn.Write([]byte(reqStr)); err != nil {
		t.Fatalf("write CONNECT: %v", err)
	}

	// Read CONNECT response
	reader := bufio.NewReader(clientConn)
	line, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("read CONNECT response line: %v", err)
	}
	if !strings.Contains(line, "200") {
		t.Fatalf("expected 200 Connection Established, got: %q", line)
	}

	// Drain headers
	for {
		l, err := reader.ReadString('\n')
		if err != nil {
			t.Fatalf("read header: %v", err)
		}
		if l == "\r\n" || l == "\n" {
			break
		}
	}

	// Wait a moment for connection to register in activeConns
	time.Sleep(50 * time.Millisecond)

	// Check if activeConns has exactly 1 tracked connection
	count := 0
	server.activeConns.Range(func(key, value any) bool {
		count++
		return true
	})
	if count != 1 {
		t.Errorf("expected 1 tracked connection, got %d", count)
	}

	// Close the client connection to allow instant graceful shutdown
	clientConn.Close()
	time.Sleep(50 * time.Millisecond)

	// Now shutdown
	cancel()

	// Wait for Serve to finish
	select {
	case err := <-errCh:
		if err != nil && err != context.Canceled {
			t.Errorf("Serve() finished with unexpected error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Serve() took too long to shutdown or got blocked")
	}
}

func TestHijackedConnectionForceClose(t *testing.T) {
	// Find a free port
	freeLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen proxy: %v", err)
	}
	proxyAddr := freeLn.Addr().String()
	freeLn.Close()

	server := NewServer(proxyAddr, nil)

	// Create a dummy net.Conn to track
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	server.trackConn(c1)

	// Verify tracked count
	count := 0
	server.activeConns.Range(func(key, value any) bool {
		count++
		return true
	})
	if count != 1 {
		t.Fatalf("expected 1 tracked connection, got %d", count)
	}

	// Start a timer to verify drainHijacked force closes it
	start := time.Now()
	server.drainHijacked(100 * time.Millisecond)
	duration := time.Since(start)

	if duration < 100*time.Millisecond {
		t.Errorf("drainHijacked returned too early: %v", duration)
	}

	// Verify c1 was closed (which means c2.Read should return io.EOF or error)
	c2.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
	buf := make([]byte, 1)
	_, err = c2.Read(buf)
	if err == nil {
		t.Error("expected connection to be closed by drainHijacked, but Read succeeded")
	}
}

func TestWriteResponseStreamingDumpsOnlyOnPolicyHit(t *testing.T) {
	phraseFilter, err := NewPhraseFilter([]string{"malicious blockphrase"})
	if err != nil {
		t.Fatalf("NewPhraseFilter() error = %v", err)
	}
	contentFilter := NewContentFilter(phraseFilter, nil, nil, nil, nil)

	policyLog, err := NewPolicy(PolicyConfig{
		Log: LogRulesConfig{
			LogURLs: []string{"http://example.test/logpath"},
		},
	})
	if err != nil {
		t.Fatalf("NewPolicy() error = %v", err)
	}

	tests := []struct {
		name            string
		dumpOnPolicyHit bool
		policy          *Policy
		filter          FilterEngine
		requestPath     string
		requestBody     string
		responseBody    string
		expectDumps     bool
		expectCode      int
	}{
		{
			name:            "dump_always_on_benign_traffic",
			dumpOnPolicyHit: false,
			policy:          nil,
			filter:          contentFilter,
			requestPath:     "/benign",
			requestBody:     "benign request content",
			responseBody:    "benign response content madrid",
			expectDumps:     true,
			expectCode:      200,
		},
		{
			name:            "no_dump_on_policy_hit_enabled_benign_traffic",
			dumpOnPolicyHit: true,
			policy:          nil,
			filter:          contentFilter,
			requestPath:     "/benign",
			requestBody:     "benign request content",
			responseBody:    "benign response content madrid",
			expectDumps:     false,
			expectCode:      200,
		},
		{
			name:            "dump_on_policy_hit_enabled_request_blocked",
			dumpOnPolicyHit: true,
			policy:          nil,
			filter:          contentFilter,
			requestPath:     "/blocked-req",
			requestBody:     "malicious blockphrase request content",
			responseBody:    "benign response content",
			expectDumps:     true,
			expectCode:      403,
		},
		{
			name:            "dump_on_policy_hit_enabled_response_blocked",
			dumpOnPolicyHit: true,
			policy:          nil,
			filter:          contentFilter,
			requestPath:     "/blocked-resp",
			requestBody:     "benign request content",
			responseBody:    "malicious blockphrase response content",
			expectDumps:     true,
			expectCode:      200, // ServeHTTP plain HTTP writes a block page or logs block but response bytes are still read
		},
		{
			name:            "dump_on_policy_hit_enabled_audit_log_hit",
			dumpOnPolicyHit: true,
			policy:          policyLog,
			filter:          contentFilter,
			requestPath:     "/logpath",
			requestBody:     "benign request content",
			responseBody:    "benign response content",
			expectDumps:     true,
			expectCode:      200,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			resetDumper()
			t.Cleanup(resetDumper)

			dumpDir := t.TempDir()
			server := NewServer("127.0.0.1:0", nil)
			server.SetRelayOptions(RelayOptions{
				LogBodies:       true,
				MaxCaptureBytes: 1 << 20,
				IOTimeout:       time.Second,
				DumpDir:         dumpDir,
				DumpOnPolicyHit: tc.dumpOnPolicyHit,
				Filter:          tc.filter,
				RequestFilter:   tc.filter,
				Policy:          tc.policy,
			})
			if tc.policy != nil {
				server.SetPolicy(tc.policy)
			}

			server.SetPlainHTTPDialer(plainDialerFunc(func(_ context.Context, network, address string) (net.Conn, error) {
				proxySide, upstreamSide := net.Pipe()
				go func() {
					defer upstreamSide.Close()
					req, err := http.ReadRequest(bufio.NewReader(upstreamSide))
					if err != nil {
						return
					}
					_, _ = io.Copy(io.Discard, req.Body)
					_ = req.Body.Close()
					_, _ = io.WriteString(upstreamSide, fmt.Sprintf("HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Type: text/html\r\nContent-Length: %d\r\n\r\n%s", len(tc.responseBody), tc.responseBody))
				}()
				return proxySide, nil
			}))

			req := httptest.NewRequest(http.MethodPost, "http://example.test"+tc.requestPath, strings.NewReader(tc.requestBody))
			req.Header.Set("Content-Type", "text/html")
			req.RemoteAddr = "127.0.0.1:50000"
			rec := httptest.NewRecorder()

			server.ServeHTTP(rec, req)

			// Wait a bit for the asynchronous dumper to write to disk
			time.Sleep(150 * time.Millisecond)

			// Count dump files in the directory
			files, err := os.ReadDir(dumpDir)
			if err != nil {
				t.Fatalf("ReadDir() error = %v", err)
			}

			var fileNames []string
			for _, f := range files {
				fileNames = append(fileNames, f.Name())
			}
			t.Logf("tc: %s, code: %d, files: %v", tc.name, rec.Code, fileNames)

			if rec.Code != tc.expectCode {
				t.Errorf("expected status code %d, got %d", tc.expectCode, rec.Code)
			}

			hasDumps := len(files) > 0
			if tc.expectDumps && !hasDumps {
				t.Fatalf("expected dump files in %s, found none", dumpDir)
			}
			if !tc.expectDumps && hasDumps {
				t.Fatalf("expected NO dump files in %s, but found %d files", dumpDir, len(files))
			}
		})
	}
}

func resetDumper() {
	globalDumperMu.Lock()
	defer globalDumperMu.Unlock()

	d := globalDumper.Load()
	if d != nil {
		d.Close()
		globalDumper.Store(nil)
	}
}

func TestServeHTTPPlainHTTPRequestBlockDoesNotContactUpstream(t *testing.T) {
	phraseFilter, err := NewPhraseFilter([]string{"malicious blockphrase"})
	if err != nil {
		t.Fatalf("NewPhraseFilter() error = %v", err)
	}
	contentFilter := NewContentFilter(phraseFilter, nil, nil, nil, nil)

	server := NewServer("127.0.0.1:0", nil)
	server.SetRelayOptions(RelayOptions{
		LogBodies:       true,
		MaxCaptureBytes: 1 << 20,
		IOTimeout:       time.Second,
		Filter:          contentFilter,
		RequestFilter:   contentFilter,
	})

	var dialCount atomic.Int64
	server.SetPlainHTTPDialer(plainDialerFunc(func(_ context.Context, network, address string) (net.Conn, error) {
		dialCount.Add(1)
		proxySide, upstreamSide := net.Pipe()
		go func() {
			defer upstreamSide.Close()
			req, err := http.ReadRequest(bufio.NewReader(upstreamSide))
			if err != nil {
				return
			}
			_, _ = io.Copy(io.Discard, req.Body)
			_ = req.Body.Close()
			_, _ = io.WriteString(upstreamSide, "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: 0\r\n\r\n")
		}()
		return proxySide, nil
	}))

	req := httptest.NewRequest(http.MethodPost, "http://example.test/path", strings.NewReader("malicious blockphrase body"))
	req.Header.Set("Content-Type", "text/html")
	req.RemoteAddr = "127.0.0.1:50000"
	rec := httptest.NewRecorder()

	server.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden, got %d", rec.Code)
	}

	if dialCount.Load() != 1 {
		t.Fatalf("expected 1 dial to upstream, got %d", dialCount.Load())
	}
}

func TestServeHTTPChunkedAndExpectHeader(t *testing.T) {
	server := NewServer("127.0.0.1:0", nil)
	dumpDir := t.TempDir()
	resetDumper()
	t.Cleanup(resetDumper)

	server.SetRelayOptions(RelayOptions{
		LogBodies:       true,
		MaxCaptureBytes: 1024,
		DumpDir:         dumpDir,
		DumpOnPolicyHit: false, // always dump
	})

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen failed: %v", err)
	}
	t.Cleanup(func() { ln.Close() })

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(upstreamSide net.Conn) {
				defer upstreamSide.Close()
				br := bufio.NewReader(upstreamSide)
				req, err := http.ReadRequest(br)
				if err != nil {
					return
				}
				_, _ = io.Copy(io.Discard, req.Body)
				_ = req.Body.Close()
				_, _ = io.WriteString(upstreamSide, "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: 5\r\n\r\nworld")
			}(conn)
		}
	}()

	server.SetPlainHTTPDialer(plainDialerFunc(func(_ context.Context, network, address string) (net.Conn, error) {
		return net.Dial("tcp", ln.Addr().String())
	}))

	// 1. Expect 100-continue request
	req := httptest.NewRequest(http.MethodPost, "http://example.test/", strings.NewReader("hello"))
	req.Header.Set("Expect", "100-continue")
	req.Header.Set("Content-Type", "text/plain")
	req.RemoteAddr = "127.0.0.1:50000"
	rec := httptest.NewRecorder()

	server.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("Expect 100 status = %d", rec.Code)
	}

	// 2. Chunked encoding request
	reqChunked := httptest.NewRequest(http.MethodPost, "http://example.test/", strings.NewReader("chunked data"))
	reqChunked.TransferEncoding = []string{"chunked"}
	reqChunked.Header.Set("Content-Type", "text/plain")
	reqChunked.RemoteAddr = "127.0.0.1:50000"
	rec2 := httptest.NewRecorder()

	server.ServeHTTP(rec2, reqChunked)

	if rec2.Code != http.StatusOK {
		t.Fatalf("Chunked status = %d", rec2.Code)
	}
}

func TestServeHTTPBodyLimitAndEarlyDisconnect(t *testing.T) {
	server := NewServer("127.0.0.1:0", nil)
	dumpDir := t.TempDir()
	resetDumper()
	t.Cleanup(resetDumper)

	server.SetRelayOptions(RelayOptions{
		LogBodies:       true,
		MaxCaptureBytes: 5, // very small limit to trigger truncation
		DumpDir:         dumpDir,
		DumpOnPolicyHit: false, // always dump
	})

	server.SetPlainHTTPDialer(plainDialerFunc(func(_ context.Context, network, address string) (net.Conn, error) {
		proxySide, upstreamSide := net.Pipe()
		go func() {
			defer upstreamSide.Close()
			req, err := http.ReadRequest(bufio.NewReader(upstreamSide))
			if err != nil {
				return
			}
			_, _ = io.Copy(io.Discard, req.Body)
			_ = req.Body.Close()
			_, _ = io.WriteString(upstreamSide, "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: 10\r\n\r\n0123456789")
		}()
		return proxySide, nil
	}))

	// 1. Request without body (GET)
	reqNoBody := httptest.NewRequest(http.MethodGet, "http://example.test/", nil)
	reqNoBody.RemoteAddr = "127.0.0.1:50000"
	rec := httptest.NewRecorder()
	server.ServeHTTP(rec, reqNoBody)

	if rec.Code != http.StatusOK {
		t.Fatalf("GET no-body status = %d", rec.Code)
	}

	// 2. Request body > MaxCaptureBytes
	reqLarge := httptest.NewRequest(http.MethodPost, "http://example.test/", strings.NewReader("abcdefghijkl"))
	reqLarge.Header.Set("Content-Type", "text/plain")
	reqLarge.RemoteAddr = "127.0.0.1:50000"
	rec2 := httptest.NewRecorder()
	server.ServeHTTP(rec2, reqLarge)

	if rec2.Code != http.StatusOK {
		t.Fatalf("POST large status = %d", rec2.Code)
	}

	time.Sleep(150 * time.Millisecond)

	// Verify that dumps exist, and let's check their content
	files, err := os.ReadDir(dumpDir)
	if err != nil || len(files) == 0 {
		t.Fatalf("expected dump files, found none or err=%v", err)
	}
}

func TestServeHTTPConcurrency(t *testing.T) {
	server := NewServer("127.0.0.1:0", nil)
	dumpDir := t.TempDir()
	resetDumper()
	t.Cleanup(resetDumper)

	server.SetRelayOptions(RelayOptions{
		LogBodies:       true,
		MaxCaptureBytes: 1024,
		DumpDir:         dumpDir,
		DumpOnPolicyHit: false, // always dump
	})

	server.SetPlainHTTPDialer(plainDialerFunc(func(_ context.Context, network, address string) (net.Conn, error) {
		proxySide, upstreamSide := net.Pipe()
		go func() {
			defer upstreamSide.Close()
			req, err := http.ReadRequest(bufio.NewReader(upstreamSide))
			if err != nil {
				return
			}
			_, _ = io.Copy(io.Discard, req.Body)
			_ = req.Body.Close()
			time.Sleep(10 * time.Millisecond)
			_, _ = io.WriteString(upstreamSide, "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: 2\r\n\r\nOK")
		}()
		return proxySide, nil
	}))

	var wg sync.WaitGroup
	numRequests := 10
	for i := 0; i < numRequests; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			req := httptest.NewRequest(http.MethodPost, fmt.Sprintf("http://example.test/path-%d", id), strings.NewReader("concurrent request body"))
			req.Header.Set("Content-Type", "text/plain")
			req.RemoteAddr = fmt.Sprintf("127.0.0.1:%d", 50000+id)
			rec := httptest.NewRecorder()
			server.ServeHTTP(rec, req)
			if rec.Code != http.StatusOK {
				t.Errorf("concurrent request %d failed status = %d", id, rec.Code)
			}
		}(i)
	}
	wg.Wait()

	time.Sleep(200 * time.Millisecond)

	files, err := os.ReadDir(dumpDir)
	if err != nil || len(files) == 0 {
		t.Fatalf("expected concurrent dump files, found none or err=%v", err)
	}
}

func TestForensicDumpAttributionAndRedaction(t *testing.T) {
	phraseFilter, err := NewPhraseFilter([]string{"trigger-block"})
	if err != nil {
		t.Fatalf("NewPhraseFilter error = %v", err)
	}
	contentFilter := NewContentFilter(phraseFilter, nil, nil, nil, nil)

	policyLog, err := NewPolicy(PolicyConfig{
		Log: LogRulesConfig{
			LogURLs: []string{"http://example.test/audit-path"},
		},
	})
	if err != nil {
		t.Fatalf("NewPolicy error = %v", err)
	}

	runCase := func(t *testing.T, cleartext bool, auditKey string, triggerBlock bool, triggerAudit bool) *dumpEntry {
		resetDumper()
		t.Cleanup(resetDumper)

		parentDir := t.TempDir()
		dumpDir := filepath.Join(parentDir, "forensic-dumps")
		server := NewServer("127.0.0.1:0", nil)
		server.SetRelayOptions(RelayOptions{
			LogBodies:                true,
			MaxCaptureBytes:          1 << 20,
			IOTimeout:                time.Second,
			Filter:                   contentFilter,
			RequestFilter:            contentFilter,
			DumpDir:                  dumpDir,
			DumpOnPolicyHit:          true,
			DumpCredentialsCleartext: cleartext,
			AuditKey:                 auditKey,
			Policy:                   policyLog,
		})

		server.SetPlainHTTPDialer(plainDialerFunc(func(_ context.Context, network, address string) (net.Conn, error) {
			proxySide, upstreamSide := net.Pipe()
			go func() {
				defer upstreamSide.Close()
				req, err := http.ReadRequest(bufio.NewReader(upstreamSide))
				if err != nil {
					return
				}
				_, _ = io.Copy(io.Discard, req.Body)
				_ = req.Body.Close()
				_, _ = io.WriteString(upstreamSide, "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Type: text/plain\r\nContent-Length: 6\r\n\r\nbenign")
			}()
			return proxySide, nil
		}))

		path := "/benign-path"
		if triggerAudit {
			path = "/audit-path"
		}
		bodyStr := `{"password":"secretPassword123","user":"forensicClient"}`
		if triggerBlock {
			bodyStr = `{"password":"secretPassword123","trigger-block":"yes"}`
		}

		req := httptest.NewRequest(http.MethodPost, "http://example.test"+path, strings.NewReader(bodyStr))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer tokenXYZ123")
		req.Header.Set("User-Agent", "ForensicAgent/1.0")
		req.Header.Set("X-User", "forensic-sso-user")
		req.RemoteAddr = "192.168.1.50:62345"
		rec := httptest.NewRecorder()

		server.ServeHTTP(rec, req)

		// Wait slightly for async dump
		time.Sleep(150 * time.Millisecond)

		files, err := os.ReadDir(dumpDir)
		if err != nil {
			if os.IsNotExist(err) {
				return nil
			}
			t.Fatalf("ReadDir error: %v", err)
		}
		if len(files) == 0 {
			return nil
		}

		// Verify directory permissions
		dirInfo, err := os.Stat(dumpDir)
		if err != nil {
			t.Fatalf("Stat directory error: %v", err)
		}
		// Expect directory permission is 0700
		if dirInfo.Mode().Perm() != 0700 {
			t.Errorf("expected directory mode 0700, got %v", dirInfo.Mode().Perm())
		}

		filePath := filepath.Join(dumpDir, files[0].Name())
		fileInfo, err := os.Stat(filePath)
		if err != nil {
			t.Fatalf("Stat file error: %v", err)
		}
		// Expect file permission is 0600
		if fileInfo.Mode().Perm() != 0600 {
			t.Errorf("expected file mode 0600, got %v", fileInfo.Mode().Perm())
		}

		data, err := os.ReadFile(filePath)
		if err != nil {
			t.Fatalf("ReadFile error: %v", err)
		}

		// JSONL might have multiple lines (req and resp)
		lines := strings.Split(strings.TrimSpace(string(data)), "\n")
		for _, line := range lines {
			if line == "" {
				continue
			}
			var entry dumpEntry
			if err := json.Unmarshal([]byte(line), &entry); err != nil {
				t.Fatalf("JSON Unmarshal error: %v", err)
			}
			if entry.Direction == "req" {
				return &entry
			}
		}
		return nil
	}

	t.Run("default_mode_redacts_credentials", func(t *testing.T) {
		entry := runCase(t, false, "", true, false)
		if entry == nil {
			t.Fatal("expected request dump, got none")
		}
		if entry.ContainsCleartextCredentials {
			t.Error("expected ContainsCleartextCredentials to be false")
		}
		if entry.User != "forensic-sso-user" {
			t.Errorf("expected User forensic-sso-user, got %q", entry.User)
		}
		if entry.ClientIP != "192.168.1.50" {
			t.Errorf("expected ClientIP 192.168.1.50, got %q", entry.ClientIP)
		}
		if entry.ClientDevice != "ForensicAgent/1.0" {
			t.Errorf("expected ClientDevice ForensicAgent/1.0, got %q", entry.ClientDevice)
		}
		if entry.PolicyAction != "blocked" {
			t.Errorf("expected PolicyAction blocked, got %q", entry.PolicyAction)
		}
		if entry.BodyHash == "" {
			t.Error("expected BodyHash to be populated")
		}

		// Auth header must be redacted as [REDACTED]
		authHeader := entry.Headers["Authorization"]
		if authHeader != "[REDACTED]" {
			t.Errorf("expected Authorization header redacted as '[REDACTED]', got %q", authHeader)
		}

		// Password inside body must be redacted
		if strings.Contains(entry.Body, "secretPassword123") {
			t.Errorf("found secretPassword123 in cleartext in normal mode: %q", entry.Body)
		}
		if !strings.Contains(entry.Body, `[REDACTED]`) {
			t.Errorf("expected redacted password marker in body, got: %q", entry.Body)
		}
	})

	t.Run("hmac_mode_hashes_credentials", func(t *testing.T) {
		entry := runCase(t, false, "forensic-secret-key", true, false)
		if entry == nil {
			t.Fatal("expected request dump, got none")
		}

		authHeader := entry.Headers["Authorization"]
		if !strings.HasPrefix(authHeader, "[REDACTED:HMAC-") {
			t.Errorf("expected Authorization header redacted with HMAC, got %q", authHeader)
		}

		// Password inside body must be hashed
		if strings.Contains(entry.Body, "secretPassword123") {
			t.Errorf("found secretPassword123 in cleartext in hmac mode: %q", entry.Body)
		}
		if !strings.Contains(entry.Body, `[REDACTED:HMAC-`) {
			t.Errorf("expected redacted HMAC password marker in body, got: %q", entry.Body)
		}
	})

	t.Run("cleartext_mode_keeps_cleartext", func(t *testing.T) {
		entry := runCase(t, true, "", true, false)
		if entry == nil {
			t.Fatal("expected request dump, got none")
		}
		if !entry.ContainsCleartextCredentials {
			t.Error("expected ContainsCleartextCredentials to be true")
		}

		authHeader := entry.Headers["Authorization"]
		if authHeader != "Bearer tokenXYZ123" {
			t.Errorf("expected cleartext Authorization header, got %q", authHeader)
		}

		if !strings.Contains(entry.Body, "secretPassword123") {
			t.Errorf("expected cleartext secretPassword123 in body, got: %q", entry.Body)
		}
	})

	t.Run("no_policy_hit_means_no_dump", func(t *testing.T) {
		// Under DumpOnPolicyHit = true, benign traffic shouldn't produce a dump
		entry := runCase(t, false, "", false, false)
		if entry != nil {
			t.Errorf("expected no dump for benign traffic, but got one: %+v", entry)
		}
	})

	t.Run("policy_audit_hit_produces_dump", func(t *testing.T) {
		entry := runCase(t, false, "", false, true)
		if entry == nil {
			t.Fatal("expected dump for audited/logged path, got none")
		}
		if entry.PolicyAction != "audited" {
			t.Errorf("expected PolicyAction audited, got %q", entry.PolicyAction)
		}
	})
}

func TestDumpRotationAndDiskQuotas(t *testing.T) {
	// 1. Rotation and Compression test
	t.Run("dump_file_rotation_and_compression", func(t *testing.T) {
		resetDumper()
		t.Cleanup(resetDumper)

		dumpDir := filepath.Join(t.TempDir(), "rotation-dumps")

		opts := RelayOptions{
			DumpDir:         dumpDir,
			DumpOnPolicyHit: false, // always dump
			DumpMaxSizeMB:   1,     // 1 MB rotation threshold
			DumpMaxBackups:  3,
			DumpCompress:    true,
		}

		if err := initDumper(opts); err != nil {
			t.Fatalf("initDumper error = %v", err)
		}

		largeString := strings.Repeat("A", 10*1024)
		for i := 0; i < 110; i++ {
			entry := dumpEntry{
				Timestamp:  time.Now().Format(time.RFC3339),
				ExchangeID: fmt.Sprintf("id-%d", i),
				Body:       largeString,
			}
			writeDumpLine(opts, &entry, nil)
		}

		time.Sleep(300 * time.Millisecond)

		files, err := os.ReadDir(dumpDir)
		if err != nil {
			t.Fatalf("ReadDir failed: %v", err)
		}

		var hasGz bool
		var jsonlCount int
		for _, f := range files {
			if strings.HasSuffix(f.Name(), ".jsonl.gz") {
				hasGz = true
			}
			if strings.HasSuffix(f.Name(), ".jsonl") {
				jsonlCount++
			}
		}

		if !hasGz {
			t.Error("expected at least one compressed backup file (.jsonl.gz)")
		}
		if jsonlCount == 0 {
			t.Error("expected an active uncompressed dump file (.jsonl)")
		}
	})

	// 2. Backup Limit (DumpMaxBackups) test
	t.Run("enforce_max_backups_limit", func(t *testing.T) {
		resetDumper()
		t.Cleanup(resetDumper)

		dumpDir := filepath.Join(t.TempDir(), "backups-dumps")
		_ = os.MkdirAll(dumpDir, 0o700)

		for i := 1; i <= 10; i++ {
			path := filepath.Join(dumpDir, fmt.Sprintf("dump_%d.jsonl.gz", i))
			_ = os.WriteFile(path, []byte("mock-data"), 0o600)
		}

		opts := RelayOptions{
			DumpDir:        dumpDir,
			DumpMaxBackups: 3,
		}

		d := &ForensicDumper{
			opts: opts,
		}

		currentPath := filepath.Join(dumpDir, "dump_active.jsonl")
		_ = os.WriteFile(currentPath, []byte("active-content"), 0o600)

		d.rotateDumpFiles(currentPath, nil)

		files, err := os.ReadDir(dumpDir)
		if err != nil {
			t.Fatalf("ReadDir error: %v", err)
		}

		var count int
		for _, f := range files {
			if strings.HasPrefix(f.Name(), "dump_") {
				count++
			}
		}

		if count != 3 {
			t.Errorf("expected exactly 3 backup files left, got %d", count)
		}
	})

	// 3. Disk space threshold check
	t.Run("skips_when_disk_space_low", func(t *testing.T) {
		resetDumper()
		t.Cleanup(resetDumper)

		dumpDir := filepath.Join(t.TempDir(), "quota-dumps")

		opts := RelayOptions{
			DumpDir:            dumpDir,
			DumpOnPolicyHit:    false,
			DumpMinFreeSpaceMB: 99999999, // Unbelievably high threshold to force skip
		}

		entry := dumpEntry{
			ExchangeID: "test-space",
			Body:       "this should not be written to disk because disk space is simulated low",
		}

		writeDumpLine(opts, &entry, nil)
		time.Sleep(150 * time.Millisecond)

		files, err := os.ReadDir(dumpDir)
		if err != nil && !os.IsNotExist(err) {
			t.Fatalf("unexpected error: %v", err)
		}

		if len(files) > 0 {
			t.Errorf("expected no files to be created under low disk space simulation, found %d", len(files))
		}
	})
}

func TestHTTP3ServerLifecycleAndMITMGeneration(t *testing.T) {
	ca, err := pki.GenerateRootCA(time.Now())
	if err != nil {
		t.Fatalf("GenerateRootCA failed: %v", err)
	}
	leafCache := pki.NewLeafCache(ca.Certificate, ca.PrivateKey)

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen failed: %v", err)
	}
	addr := l.Addr().String()
	l.Close()

	server := NewServer(addr, nil, leafCache)
	server.SetHTTP3Enabled(true)

	opts := server.RelayOptions()
	if !opts.HTTP3Enabled {
		t.Error("expected opts.HTTP3Enabled to be true")
	}
	_, expectedPort, _ := net.SplitHostPort(addr)
	if opts.HTTP3Port != expectedPort {
		t.Errorf("expected opts.HTTP3Port to be %s, got %s", expectedPort, opts.HTTP3Port)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- server.Serve(ctx)
	}()

	time.Sleep(150 * time.Millisecond)

	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		t.Fatalf("ResolveUDPAddr failed: %v", err)
	}

	testUDPConn, err := net.ListenUDP("udp", udpAddr)
	if err == nil {
		testUDPConn.Close()
		t.Error("expected UDP address to be already in use by HTTP/3 listener")
	}

	cancel()
	err = <-errCh
	if err != nil && err != context.Canceled {
		t.Fatalf("Serve failed: %v", err)
	}

	testUDPConn, err = net.ListenUDP("udp", udpAddr)
	if err != nil {
		t.Errorf("expected UDP address to be free after server close, got error: %v", err)
	} else {
		testUDPConn.Close()
	}
}

func TestHTTP3ServerEndToEnd(t *testing.T) {
	// 1. Levantar servidor HTTPS upstream local de prueba
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Write([]byte("Hello from HTTP/3 through LucidGate!"))
	}))
	defer upstream.Close()

	// 2. Generar CA y leaf cache
	ca, err := pki.GenerateRootCA(time.Now())
	if err != nil {
		t.Fatalf("GenerateRootCA failed: %v", err)
	}
	leafCache := pki.NewLeafCache(ca.Certificate, ca.PrivateKey)

	// 3. Levantar LucidGate
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen failed: %v", err)
	}
	addr := l.Addr().String()
	l.Close()

	server := NewServer(addr, nil, leafCache)
	server.SetHTTP3Enabled(true)

	// Configurar el dialer upstream para redirigir todo el tráfico a nuestro httptest.NewTLSServer usando uTLS real
	_, upstreamPort, _ := net.SplitHostPort(upstream.Listener.Addr().String())
	upstreamCAs := x509.NewCertPool()
	upstreamCAs.AddCert(upstream.Certificate())

	server.SetUpstreamDialer(&mockUpstreamDialer{
		dialer: stealth.Dialer{
			Config: &utls.Config{
				RootCAs: upstreamCAs,
			},
		},
		targetAddr: "127.0.0.1:" + upstreamPort,
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- server.Serve(ctx)
	}()

	time.Sleep(150 * time.Millisecond)

	// 4. Crear cliente HTTP/3 que confía en la CA de LucidGate
	caCertPool := x509.NewCertPool()
	caCertPool.AddCert(ca.Certificate)

	// QUIC/HTTP3 requiere TLS 1.3
	tlsClientConfig := &tls.Config{
		RootCAs:            caCertPool,
		ServerName:         "www.google.com", // Queremos que el SNI sea www.google.com
		InsecureSkipVerify: false,            // Validamos que el certificado generado por LucidGate sea de confianza
	}

	rt := &http3.RoundTripper{
		TLSClientConfig: tlsClientConfig,
	}
	defer rt.Close()

	client := &http.Client{
		Transport: rt,
		Timeout:   5 * time.Second,
	}

	// 5. Enviar la petición HTTP/3 al puerto UDP de LucidGate
	_, localPort, _ := net.SplitHostPort(addr)
	resp, err := client.Get(fmt.Sprintf("https://127.0.0.1:%s/", localPort))
	if err != nil {
		t.Fatalf("HTTP/3 request failed: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read response body failed: %v", err)
	}

	expected := "Hello from HTTP/3 through LucidGate!"
	if string(body) != expected {
		t.Errorf("expected body %q, got %q", expected, string(body))
	}

	if !strings.HasPrefix(resp.Proto, "HTTP/3") {
		t.Errorf("expected protocol to start with HTTP/3, got %q", resp.Proto)
	}

	// 6. Detener el servidor LucidGate
	cancel()
	err = <-errCh
	if err != nil && err != context.Canceled {
		t.Fatalf("Serve failed: %v", err)
	}
}

type mockUpstreamDialer struct {
	dialer     stealth.Dialer
	targetAddr string
}

func (m *mockUpstreamDialer) Dial(ctx context.Context, address, serverName string) (net.Conn, error) {
	return m.dialer.DialFirefox(ctx, m.targetAddr, serverName)
}
