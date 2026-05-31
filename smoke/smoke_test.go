package smoke_test

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestBinaryEndToEndHTTPSIntercept(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for _, header := range []string{"Proxy-Connection", "X-Forwarded-For", "Via", "X-Real-IP"} {
			if value := r.Header.Get(header); value != "" {
				t.Errorf("%s header leaked upstream: %q", header, value)
			}
		}
		if r.URL.RequestURI() != "/smoke?q=1" {
			t.Errorf("upstream uri = %q, want /smoke?q=1", r.URL.RequestURI())
		}
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("smoke-ok"))
	}))
	defer upstream.Close()

	upstreamURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse upstream URL: %v", err)
	}

	addr, certDir := startBinaryProxy(t,
		"--log-bodies=true",
		"--max-capture-bytes=65536",
		"--upstream-insecure-skip-verify",
	)
	root := loadRootCA(t, filepath.Join(certDir, "ca.crt"))

	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatalf("dial proxy %s: %v", addr, err)
	}
	defer conn.Close()

	if _, err := fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", upstreamURL.Host, upstreamURL.Host); err != nil {
		t.Fatalf("write CONNECT: %v", err)
	}
	reader := bufio.NewReader(conn)
	line, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("read CONNECT status: %v", err)
	}
	if !strings.Contains(line, "200 Connection Established") {
		t.Fatalf("CONNECT status = %q", line)
	}
	if blank, err := reader.ReadString('\n'); err != nil || blank != "\r\n" {
		t.Fatalf("CONNECT blank line = %q err=%v", blank, err)
	}

	roots := x509.NewCertPool()
	roots.AddCert(root)
	tlsConn := tls.Client(conn, &tls.Config{
		ServerName: upstreamURL.Hostname(),
		RootCAs:    roots,
		MinVersion: tls.VersionTLS12,
	})
	if err := tlsConn.Handshake(); err != nil {
		t.Fatalf("local TLS handshake: %v", err)
	}

	if _, err := fmt.Fprintf(tlsConn, "GET https://%s/smoke?q=1 HTTP/1.1\r\nHost: %s\r\nProxy-Connection: keep-alive\r\nVia: smoke\r\nConnection: close\r\n\r\n", upstreamURL.Host, upstreamURL.Host); err != nil {
		t.Fatalf("write proxied request: %v", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(tlsConn), nil)
	if err != nil {
		t.Fatalf("read proxied response: %v", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read response body: %v", err)
	}
	if resp.StatusCode != http.StatusOK || string(body) != "smoke-ok" {
		t.Fatalf("response = %d %q, want 200 smoke-ok", resp.StatusCode, string(body))
	}
}

func TestBinaryWebSocketSmokePlainHTTP(t *testing.T) {
	upstreamErr := make(chan error, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.RequestURI() != "/ws" {
			upstreamErr <- fmt.Errorf("upstream uri = %q, want /ws", r.URL.RequestURI())
			http.Error(w, "bad uri", http.StatusBadRequest)
			return
		}
		if !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") || !headerHasToken(r.Header.Values("Connection"), "upgrade") {
			upstreamErr <- fmt.Errorf("upstream did not receive websocket upgrade headers: %v", r.Header)
			http.Error(w, "missing upgrade", http.StatusBadRequest)
			return
		}
		for _, header := range []string{"Proxy-Connection", "X-Forwarded-For", "Via", "X-Real-IP"} {
			if value := r.Header.Get(header); value != "" {
				upstreamErr <- fmt.Errorf("%s header leaked upstream: %q", header, value)
				http.Error(w, "leaked proxy header", http.StatusBadRequest)
				return
			}
		}
		hj, ok := w.(http.Hijacker)
		if !ok {
			upstreamErr <- fmt.Errorf("response writer does not support hijack")
			return
		}
		conn, rw, err := hj.Hijack()
		if err != nil {
			upstreamErr <- fmt.Errorf("hijack: %w", err)
			return
		}
		defer conn.Close()
		if _, err := io.WriteString(conn,
			"HTTP/1.1 101 Switching Protocols\r\n"+
				"Upgrade: websocket\r\n"+
				"Connection: Upgrade\r\n"+
				"Sec-WebSocket-Accept: smoke-accept\r\n"+
				"\r\n"); err != nil {
			upstreamErr <- fmt.Errorf("write 101: %w", err)
			return
		}
		if err := echoRaw(rw.Reader, conn, 2); err != nil {
			upstreamErr <- err
			return
		}
		upstreamErr <- nil
	}))
	defer upstream.Close()

	upstreamURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse upstream URL: %v", err)
	}
	proxyAddr, _ := startBinaryProxy(t)

	conn, err := net.DialTimeout("tcp", proxyAddr, 2*time.Second)
	if err != nil {
		t.Fatalf("dial proxy %s: %v", proxyAddr, err)
	}
	defer conn.Close()

	if _, err := fmt.Fprintf(conn,
		"GET http://%s/ws HTTP/1.1\r\n"+
			"Host: %s\r\n"+
			"Connection: keep-alive, Upgrade\r\n"+
			"Upgrade: websocket\r\n"+
			"Sec-WebSocket-Key: smoke-key\r\n"+
			"Sec-WebSocket-Version: 13\r\n"+
			"Proxy-Connection: keep-alive\r\n"+
			"X-Forwarded-For: 203.0.113.10\r\n"+
			"Via: smoke\r\n"+
			"\r\n",
		upstreamURL.Host, upstreamURL.Host); err != nil {
		t.Fatalf("write websocket request: %v", err)
	}
	reader := bufio.NewReader(conn)
	resp, err := http.ReadResponse(reader, nil)
	if err != nil {
		t.Fatalf("read websocket response: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("websocket status = %d, want 101", resp.StatusCode)
	}
	if got := resp.Header.Get("Sec-WebSocket-Accept"); got != "smoke-accept" {
		t.Fatalf("Sec-WebSocket-Accept = %q, want smoke-accept", got)
	}
	for _, payload := range [][]byte{[]byte("first-ws-payload"), []byte("\x01\x02second")} {
		if _, err := conn.Write(payload); err != nil {
			t.Fatalf("write websocket payload: %v", err)
		}
		got := make([]byte, len(payload))
		if _, err := io.ReadFull(reader, got); err != nil {
			t.Fatalf("read websocket echo: %v", err)
		}
		if string(got) != string(payload) {
			t.Fatalf("websocket echo = %q, want %q", string(got), string(payload))
		}
	}
	if err := waitSmokeErr(t, upstreamErr, "websocket upstream"); err != nil {
		t.Fatal(err)
	}
}

func TestBinaryWebSocketSmokeHTTPSMITM(t *testing.T) {
	upstreamErr := make(chan error, 1)
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.RequestURI() != "/ws" {
			upstreamErr <- fmt.Errorf("upstream uri = %q, want /ws", r.URL.RequestURI())
			http.Error(w, "bad uri", http.StatusBadRequest)
			return
		}
		if !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") || !headerHasToken(r.Header.Values("Connection"), "upgrade") {
			upstreamErr <- fmt.Errorf("upstream did not receive websocket upgrade headers: %v", r.Header)
			http.Error(w, "missing upgrade", http.StatusBadRequest)
			return
		}
		for _, header := range []string{"Proxy-Connection", "X-Forwarded-For", "Via", "X-Real-IP"} {
			if value := r.Header.Get(header); value != "" {
				upstreamErr <- fmt.Errorf("%s header leaked upstream: %q", header, value)
				http.Error(w, "leaked proxy header", http.StatusBadRequest)
				return
			}
		}
		hj, ok := w.(http.Hijacker)
		if !ok {
			upstreamErr <- fmt.Errorf("response writer does not support hijack")
			return
		}
		conn, rw, err := hj.Hijack()
		if err != nil {
			upstreamErr <- fmt.Errorf("hijack: %w", err)
			return
		}
		defer conn.Close()
		if _, err := io.WriteString(conn,
			"HTTP/1.1 101 Switching Protocols\r\n"+
				"Upgrade: websocket\r\n"+
				"Connection: Upgrade\r\n"+
				"Sec-WebSocket-Accept: smoke-mitm-accept\r\n"+
				"\r\n"); err != nil {
			upstreamErr <- fmt.Errorf("write 101: %w", err)
			return
		}
		if err := echoRaw(rw.Reader, conn, 2); err != nil {
			upstreamErr <- err
			return
		}
		upstreamErr <- nil
	}))
	defer upstream.Close()

	upstreamURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse upstream URL: %v", err)
	}
	proxyAddr, certDir := startBinaryProxy(t, "--upstream-insecure-skip-verify")
	root := loadRootCA(t, filepath.Join(certDir, "ca.crt"))

	conn, err := net.DialTimeout("tcp", proxyAddr, 2*time.Second)
	if err != nil {
		t.Fatalf("dial proxy %s: %v", proxyAddr, err)
	}
	defer conn.Close()
	if _, err := fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", upstreamURL.Host, upstreamURL.Host); err != nil {
		t.Fatalf("write CONNECT: %v", err)
	}
	reader := bufio.NewReader(conn)
	line, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("read CONNECT status: %v", err)
	}
	if !strings.Contains(line, "200 Connection Established") {
		t.Fatalf("CONNECT status = %q", line)
	}
	if blank, err := reader.ReadString('\n'); err != nil || blank != "\r\n" {
		t.Fatalf("CONNECT blank line = %q err=%v", blank, err)
	}

	roots := x509.NewCertPool()
	roots.AddCert(root)
	tlsConn := tls.Client(conn, &tls.Config{
		ServerName: upstreamURL.Hostname(),
		RootCAs:    roots,
		MinVersion: tls.VersionTLS12,
	})
	if err := tlsConn.Handshake(); err != nil {
		t.Fatalf("local TLS handshake: %v", err)
	}
	if _, err := fmt.Fprintf(tlsConn,
		"GET https://%s/ws HTTP/1.1\r\n"+
			"Host: %s\r\n"+
			"Connection: Upgrade\r\n"+
			"Upgrade: websocket\r\n"+
			"Sec-WebSocket-Key: smoke-key\r\n"+
			"Sec-WebSocket-Version: 13\r\n"+
			"Proxy-Connection: keep-alive\r\n"+
			"Via: smoke\r\n"+
			"\r\n",
		upstreamURL.Host, upstreamURL.Host); err != nil {
		t.Fatalf("write websocket request: %v", err)
	}
	tlsReader := bufio.NewReader(tlsConn)
	resp, err := http.ReadResponse(tlsReader, nil)
	if err != nil {
		t.Fatalf("read websocket response: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("websocket status = %d, want 101", resp.StatusCode)
	}
	if got := resp.Header.Get("Sec-WebSocket-Accept"); got != "smoke-mitm-accept" {
		t.Fatalf("Sec-WebSocket-Accept = %q, want smoke-mitm-accept", got)
	}
	for _, payload := range [][]byte{[]byte("first-wss-payload"), []byte("\x03\x04second")} {
		if _, err := tlsConn.Write(payload); err != nil {
			t.Fatalf("write websocket payload: %v", err)
		}
		got := make([]byte, len(payload))
		if _, err := io.ReadFull(tlsReader, got); err != nil {
			t.Fatalf("read websocket echo: %v", err)
		}
		if string(got) != string(payload) {
			t.Fatalf("websocket echo = %q, want %q", string(got), string(payload))
		}
	}
	if err := waitSmokeErr(t, upstreamErr, "websocket upstream"); err != nil {
		t.Fatal(err)
	}
}

func TestBinaryAltSvcSmokeStripsHTTP3Advertising(t *testing.T) {
	plainUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Alt-Svc", `h3=":443"; ma=86400`)
		w.Header().Add("Alt-Svc", `h3-29=":443"; ma=86400`)
		w.Header().Set("Alternate-Protocol", `443:quic`)
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("plain-alt-svc"))
	}))
	defer plainUpstream.Close()

	tlsUpstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Alt-Svc", `h3=":443"; ma=86400`)
		w.Header().Set("Alternate-Protocol", `443:quic`)
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("mitm-alt-svc"))
	}))
	defer tlsUpstream.Close()

	proxyAddr, certDir := startBinaryProxy(t, "--upstream-insecure-skip-verify")

	plainResp, plainBody := getPlainViaProxy(t, proxyAddr, plainUpstream.URL)
	assertAltSvcStripped(t, plainResp, plainBody, "plain-alt-svc")

	root := loadRootCA(t, filepath.Join(certDir, "ca.crt"))
	tlsResp, tlsBody := getHTTPSViaProxy(t, proxyAddr, root, tlsUpstream.URL, "/alt-svc")
	assertAltSvcStripped(t, tlsResp, tlsBody, "mitm-alt-svc")
}

func startBinaryProxy(t *testing.T, args ...string) (addr string, certDir string) {
	t.Helper()

	bin := os.Getenv("LUCIDGATE_BIN")
	if bin == "" {
		bin = os.Getenv("CLEARGATE_BIN")
	}
	if bin == "" {
		t.Skip("LUCIDGATE_BIN is not set")
	}

	ctx, cancel := context.WithCancel(context.Background())
	workDir := t.TempDir()
	certDir = filepath.Join(workDir, "certs")
	baseArgs := []string{
		"--listen=127.0.0.1:0",
		"--cert-dir=" + certDir,
		"--dial-timeout=2s",
		"--handshake-timeout=2s",
		"--io-timeout=2s",
		"--ws-idle-timeout=2s",
	}
	cmd := exec.CommandContext(ctx, bin, append(baseArgs, args...)...)
	cmd.Dir = workDir
	stderr, err := cmd.StderrPipe()
	if err != nil {
		cancel()
		t.Fatalf("stderr pipe: %v", err)
	}
	cmd.Stdout = io.Discard
	if err := cmd.Start(); err != nil {
		cancel()
		t.Fatalf("start proxy: %v", err)
	}
	t.Cleanup(func() {
		cancel()
		_ = cmd.Wait()
	})

	return waitForProxyAddress(t, stderr), certDir
}

func waitForProxyAddress(t *testing.T, stderr io.Reader) string {
	t.Helper()

	lines := make(chan string, 32)
	go func() {
		scanner := bufio.NewScanner(stderr)
		for scanner.Scan() {
			lines <- scanner.Text()
		}
		close(lines)
	}()

	timeout := time.After(5 * time.Second)
	for {
		select {
		case line, ok := <-lines:
			if !ok {
				t.Fatal("proxy exited before reporting listen address")
			}
			const marker = "proxy listening on "
			if idx := strings.Index(line, marker); idx >= 0 {
				return strings.TrimSpace(line[idx+len(marker):])
			}
			if addr := proxyAddressFromSlog(line); addr != "" {
				return addr
			}
		case <-timeout:
			t.Fatal("timeout waiting for proxy listen address")
		}
	}
}

func proxyAddressFromSlog(line string) string {
	var fields struct {
		Msg  string `json:"msg"`
		Addr string `json:"addr"`
	}
	if err := json.Unmarshal([]byte(line), &fields); err != nil {
		return ""
	}
	if fields.Msg != "proxy listening" {
		return ""
	}
	return fields.Addr
}

func getPlainViaProxy(t *testing.T, proxyAddr, target string) (*http.Response, []byte) {
	t.Helper()

	targetURL, err := url.Parse(target)
	if err != nil {
		t.Fatalf("parse target URL: %v", err)
	}
	conn, err := net.DialTimeout("tcp", proxyAddr, 2*time.Second)
	if err != nil {
		t.Fatalf("dial proxy %s: %v", proxyAddr, err)
	}
	defer conn.Close()
	if _, err := fmt.Fprintf(conn, "GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", target, targetURL.Host); err != nil {
		t.Fatalf("write plain request: %v", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("read plain response: %v", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read plain response body: %v", err)
	}
	return resp, body
}

func getHTTPSViaProxy(t *testing.T, proxyAddr string, root *x509.Certificate, target string, path string) (*http.Response, []byte) {
	t.Helper()

	targetURL, err := url.Parse(target)
	if err != nil {
		t.Fatalf("parse target URL: %v", err)
	}
	conn, err := net.DialTimeout("tcp", proxyAddr, 2*time.Second)
	if err != nil {
		t.Fatalf("dial proxy %s: %v", proxyAddr, err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if _, err := fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", targetURL.Host, targetURL.Host); err != nil {
		t.Fatalf("write CONNECT: %v", err)
	}
	reader := bufio.NewReader(conn)
	line, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("read CONNECT status: %v", err)
	}
	if !strings.Contains(line, "200 Connection Established") {
		t.Fatalf("CONNECT status = %q", line)
	}
	if blank, err := reader.ReadString('\n'); err != nil || blank != "\r\n" {
		t.Fatalf("CONNECT blank line = %q err=%v", blank, err)
	}

	roots := x509.NewCertPool()
	roots.AddCert(root)
	tlsConn := tls.Client(conn, &tls.Config{
		ServerName: targetURL.Hostname(),
		RootCAs:    roots,
		MinVersion: tls.VersionTLS12,
	})
	if err := tlsConn.Handshake(); err != nil {
		t.Fatalf("local TLS handshake: %v", err)
	}
	if _, err := fmt.Fprintf(tlsConn, "GET https://%s%s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", targetURL.Host, path, targetURL.Host); err != nil {
		t.Fatalf("write HTTPS request: %v", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(tlsConn), nil)
	if err != nil {
		t.Fatalf("read HTTPS response: %v", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read HTTPS response body: %v", err)
	}
	return resp, body
}

func assertAltSvcStripped(t *testing.T, resp *http.Response, body []byte, wantBody string) {
	t.Helper()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if string(body) != wantBody {
		t.Fatalf("body = %q, want %q", string(body), wantBody)
	}
	if got := resp.Header.Get("Alt-Svc"); got != "" {
		t.Fatalf("Alt-Svc leaked to client: %q", got)
	}
	if values := resp.Header.Values("Alt-Svc"); len(values) != 0 {
		t.Fatalf("Alt-Svc values leaked to client: %v", values)
	}
	if got := resp.Header.Get("Alternate-Protocol"); got != "" {
		t.Fatalf("Alternate-Protocol leaked to client: %q", got)
	}
}

func headerHasToken(values []string, token string) bool {
	for _, value := range values {
		for _, part := range strings.Split(value, ",") {
			if strings.EqualFold(strings.TrimSpace(part), token) {
				return true
			}
		}
	}
	return false
}

func echoRaw(r *bufio.Reader, w io.Writer, exchanges int) error {
	buf := make([]byte, 32*1024)
	for i := 0; i < exchanges; i++ {
		n, err := r.Read(buf)
		if err != nil {
			return fmt.Errorf("upstream read websocket payload: %w", err)
		}
		if _, err := w.Write(buf[:n]); err != nil {
			return fmt.Errorf("upstream write websocket echo: %w", err)
		}
	}
	return nil
}

func waitSmokeErr(t *testing.T, ch <-chan error, name string) error {
	t.Helper()

	select {
	case err := <-ch:
		if err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
		return nil
	case <-time.After(2 * time.Second):
		return fmt.Errorf("%s timed out", name)
	}
}

func loadRootCA(t *testing.T, path string) *x509.Certificate {
	t.Helper()

	deadline := time.Now().Add(5 * time.Second)
	var data []byte
	var err error
	for time.Now().Before(deadline) {
		data, err = os.ReadFile(path)
		if err == nil {
			break
		}
		time.Sleep(25 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("read root ca %s: %v", path, err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		t.Fatal("decode root ca pem: no block")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse root ca: %v", err)
	}
	return cert
}
