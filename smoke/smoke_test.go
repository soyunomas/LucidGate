package smoke_test

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
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
	bin := os.Getenv("LUCIDGATE_BIN")
	if bin == "" {
		bin = os.Getenv("CLEARGATE_BIN")
	}
	if bin == "" {
		t.Skip("LUCIDGATE_BIN is not set")
	}

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

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	certDir := filepath.Join(t.TempDir(), "certs")
	cmd := exec.CommandContext(ctx, bin,
		"--listen=127.0.0.1:0",
		"--cert-dir="+certDir,
		"--dial-timeout=2s",
		"--handshake-timeout=2s",
		"--log-bodies=true",
		"--max-capture-bytes=65536",
		"--upstream-insecure-skip-verify",
	)
	stderr, err := cmd.StderrPipe()
	if err != nil {
		t.Fatalf("stderr pipe: %v", err)
	}
	cmd.Stdout = io.Discard
	if err := cmd.Start(); err != nil {
		t.Fatalf("start proxy: %v", err)
	}
	defer func() {
		cancel()
		_ = cmd.Wait()
	}()

	addr := waitForProxyAddress(t, stderr)
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
		case <-timeout:
			t.Fatal("timeout waiting for proxy listen address")
		}
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
