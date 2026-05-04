package proxy

import (
	"bufio"
	"bytes"
	"compress/flate"
	"compress/gzip"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/andybalholm/brotli"

	"lucidgate/pki"
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
	var logs bytes.Buffer
	server := NewServer("127.0.0.1:0", log.New(&logs, "", 0))
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
	if got := logs.String(); !strings.Contains(got, "[GET] [example.test] [/news?q=1] - Status: 200") {
		t.Fatalf("log output = %q, want structured HTTP exchange log", got)
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

func TestServeHTTPRejectsWhenConnectionLimitExceeded(t *testing.T) {
	server := NewServer("127.0.0.1:0", nil)
	server.SetMaxConnections(1)
	permit, ok := server.acquireConn()
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

	select {
	case call := <-dialed:
		if call.address != "github.com:443" || call.serverName != "github.com" {
			t.Fatalf("upstream call = %#v, want github.com:443/github.com", call)
		}
	case <-time.After(time.Second):
		t.Fatal("upstream dial was not called")
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

	line, err := bufio.NewReader(tlsConn).ReadString('\n')
	if err != nil {
		t.Fatalf("read 502 status error = %v", err)
	}
	if !strings.Contains(line, "502 Bad Gateway") {
		t.Fatalf("status line = %q, want 502 Bad Gateway", line)
	}
}

func TestRelaySanitizesAndForwardsHTTPRequest(t *testing.T) {
	ca, err := pki.GenerateRootCA(time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("GenerateRootCA() error = %v", err)
	}
	upstreamReq := make(chan *http.Request, 1)
	upstreamErr := make(chan error, 1)
	var logs bytes.Buffer
	server := NewServer("127.0.0.1:0", log.New(&logs, "", 0), pki.NewLeafCache(ca.Certificate, ca.PrivateKey))
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
	if got := logs.String(); !strings.Contains(got, "[POST] [github.com] [/some/path?q=1] - Status: 200 - ReqBytes: 5 - RespBytes: 5") {
		t.Fatalf("log output = %q, want structured exchange log", got)
	}
}

func TestWriteRequestStreamingDoesNotBufferAboveLimit(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "https://example.com/", strings.NewReader("hello"))
	req.ContentLength = 5
	var out bytes.Buffer
	cap := newBodyCapture(req.Body != nil, RelayOptions{LogBodies: true, MaxCaptureBytes: 4, DumpDir: t.TempDir()})
	got, err := writeRequestStreaming(&out, req, cap, nil)
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

	got, err := writeRequestStreaming(&out, req, cap, filter)
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

	got, err := writeRequestStreaming(&out, req, cap, filter)
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
	got, err := writeResponseStreaming(&out, resp, cap, uppercaseFilter{})
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
	got, err := writeResponseStreaming(&out, resp, cap, filter)
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
	got, err := writeResponseStreaming(&out, resp, cap, filter)
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
	if _, err := writeResponseStreaming(&out, resp, cap, filter); err != nil {
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
	got, err := writeResponseStreaming(&out, resp, cap, filter)
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
	if _, err := writeResponseStreaming(&out, resp, cap, filter); err != nil {
		t.Fatalf("writeResponseStreaming() error = %v", err)
	}
	raw := out.String()
	if !strings.Contains(raw, "Barcelona") || strings.Contains(raw, ">Madrid<") {
		t.Fatalf("serialized HTML did not substitute as expected: %q", raw)
	}
}

func TestWriteResponseStreamingInspectsCompressedMutableContent(t *testing.T) {
	filter, err := NewPhraseFilter([]string{"blocked phrase"})
	if err != nil {
		t.Fatalf("NewPhraseFilter() error = %v", err)
	}
	for _, encoding := range []string{"gzip", "deflate", "br"} {
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
			got, err := writeResponseStreaming(&out, resp, cap, filter)
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
		Body:          io.NopCloser(strings.NewReader("zstddata")),
		ContentLength: 8,
	}
	resp.Header.Set("Content-Type", "text/html")
	resp.Header.Set("Content-Encoding", "zstd")

	var out bytes.Buffer
	cap := newBodyCapture(resp.Body != nil, RelayOptions{LogBodies: true, MaxCaptureBytes: 1})
	_, err := writeResponseStreaming(&out, resp, cap, filter)
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
	if _, err := writeResponseStreaming(&cleanOut, cleanResp, newBodyCapture(cleanResp.Body != nil, opts), opts.Filter); err != nil {
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
	if _, err := writeResponseStreaming(&blockedOut, blockedResp, newBodyCapture(blockedResp.Body != nil, opts), opts.Filter); err != nil {
		t.Fatalf("writeResponseStreaming(blocked) error = %v", err)
	}
	if strings.Contains(blockedOut.String(), "after") {
		t.Fatalf("latest filter did not block new phrase: %q", blockedOut.String())
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

func connectAndHandshake(t *testing.T, address string, root *x509.Certificate, serverName string) *tls.Conn {
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
		ServerName: serverName,
		RootCAs:    roots,
		MinVersion: tls.VersionTLS12,
	})
	if err := tlsConn.Handshake(); err != nil {
		conn.Close()
		t.Fatalf("TLS Handshake() error = %v", err)
	}
	return tlsConn
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
