package proxy

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestIsWebSocketUpgradeRecognizesValidHandshake(t *testing.T) {
	req := newWSRequest("GET")
	if !isWebSocketUpgrade(req) {
		t.Fatalf("expected valid WS handshake to be recognized")
	}
}

func TestIsWebSocketUpgradeRejectsNonGET(t *testing.T) {
	req := newWSRequest("POST")
	if isWebSocketUpgrade(req) {
		t.Fatalf("POST + Upgrade should not be treated as WS handshake")
	}
}

func TestIsWebSocketUpgradeRejectsMissingUpgradeToken(t *testing.T) {
	req := newWSRequest("GET")
	req.Header.Set("Connection", "keep-alive")
	if isWebSocketUpgrade(req) {
		t.Fatalf("missing Connection: upgrade should not be treated as WS")
	}
}

func TestIsWebSocketUpgradeAcceptsMultiTokenConnection(t *testing.T) {
	req := newWSRequest("GET")
	req.Header.Set("Connection", "keep-alive, Upgrade")
	if !isWebSocketUpgrade(req) {
		t.Fatalf("Connection: keep-alive, Upgrade should be treated as WS")
	}
}

func TestIsWebSocketUpgradeRejectsWrongProtocol(t *testing.T) {
	req := newWSRequest("GET")
	req.Header.Set("Upgrade", "h2c")
	if isWebSocketUpgrade(req) {
		t.Fatalf("Upgrade: h2c should not be treated as WS")
	}
}

func TestSanitizeWebSocketRequestPreservesHandshakeHeaders(t *testing.T) {
	req := newWSRequest("GET")
	req.Header.Set("Proxy-Connection", "keep-alive")
	req.Header.Set("X-Forwarded-For", "203.0.113.10")
	sanitizeWebSocketRequest(req)
	if got := req.Header.Get("Proxy-Connection"); got != "" {
		t.Fatalf("Proxy-Connection not stripped: %q", got)
	}
	if got := req.Header.Get("X-Forwarded-For"); got != "" {
		t.Fatalf("X-Forwarded-For not stripped: %q", got)
	}
	if !strings.EqualFold(req.Header.Get("Upgrade"), "websocket") {
		t.Fatalf("Upgrade was stripped: %q", req.Header.Get("Upgrade"))
	}
	if !strings.Contains(strings.ToLower(req.Header.Get("Connection")), "upgrade") {
		t.Fatalf("Connection lost upgrade token: %q", req.Header.Get("Connection"))
	}
	if req.Header.Get("Sec-WebSocket-Key") == "" {
		t.Fatalf("Sec-WebSocket-Key was stripped")
	}
}

// TestRelayWebSocketPassesThroughEchoEndToEnd runs a fake WS echo upstream and
// drives a single client through relayWebSocket. It verifies (1) the upstream
// receives the unmodified Upgrade handshake, (2) the client receives the 101
// response with Sec-WebSocket-Accept intact, (3) bidirectional bytes flow,
// and (4) the WebSocketSessions and WebSocketBytes metrics advance.
func TestRelayWebSocketPassesThroughEchoEndToEnd(t *testing.T) {
	clientConn, proxyClientSide := net.Pipe()
	proxyUpstreamSide, upstreamConn := net.Pipe()
	// In production the caller closes upstreamConn after relayWebSocket
	// returns (releaseCurrent(false)); we replicate that here so the
	// upstream goroutine's blocked Read unblocks.
	t.Cleanup(func() {
		_ = clientConn.Close()
		_ = proxyClientSide.Close()
		_ = proxyUpstreamSide.Close()
		_ = upstreamConn.Close()
	})

	upstreamErr := make(chan error, 1)
	go func() {
		r := bufio.NewReader(upstreamConn)
		req, err := http.ReadRequest(r)
		if err != nil {
			upstreamErr <- fmt.Errorf("upstream read req: %w", err)
			return
		}
		if !isWebSocketUpgrade(req) {
			upstreamErr <- fmt.Errorf("upstream did not see WS upgrade headers; got %+v", req.Header)
			return
		}
		if req.Header.Get("X-Forwarded-For") != "" {
			upstreamErr <- fmt.Errorf("X-Forwarded-For leaked to upstream")
			return
		}
		_, err = io.WriteString(upstreamConn,
			"HTTP/1.1 101 Switching Protocols\r\n"+
				"Upgrade: websocket\r\n"+
				"Connection: Upgrade\r\n"+
				"Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n"+
				"\r\n")
		if err != nil {
			upstreamErr <- fmt.Errorf("upstream write 101: %w", err)
			return
		}
		// Echo loop: read whatever bytes arrive, write them back. We do not
		// parse WS frames; the test is byte-level transparent forwarding.
		buf := make([]byte, 32*1024)
		for {
			n, rerr := upstreamConn.Read(buf)
			if n > 0 {
				if _, werr := upstreamConn.Write(buf[:n]); werr != nil {
					upstreamErr <- fmt.Errorf("upstream echo write: %w", werr)
					return
				}
			}
			if rerr != nil {
				upstreamErr <- nil
				return
			}
		}
	}()

	clientErr := make(chan error, 1)
	clientGot := make(chan []byte, 4)
	go func() {
		defer clientConn.Close()
		req := newWSRequest("GET")
		req.Header.Set("X-Forwarded-For", "should-be-stripped")
		if err := req.Write(clientConn); err != nil {
			clientErr <- fmt.Errorf("client write req: %w", err)
			return
		}
		resp, err := http.ReadResponse(bufio.NewReader(clientConn), req)
		if err != nil {
			clientErr <- fmt.Errorf("client read 101: %w", err)
			return
		}
		if resp.StatusCode != http.StatusSwitchingProtocols {
			clientErr <- fmt.Errorf("client got status %d, want 101", resp.StatusCode)
			return
		}
		if got := resp.Header.Get("Sec-WebSocket-Accept"); got != "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=" {
			clientErr <- fmt.Errorf("Sec-WebSocket-Accept mismatch: %q", got)
			return
		}
		payloads := [][]byte{[]byte("hello-world"), []byte("\x01\x02\x03ping")}
		for _, p := range payloads {
			if _, err := clientConn.Write(p); err != nil {
				clientErr <- fmt.Errorf("client write payload: %w", err)
				return
			}
			got := make([]byte, len(p))
			if _, err := io.ReadFull(clientConn, got); err != nil {
				clientErr <- fmt.Errorf("client read echo: %w", err)
				return
			}
			clientGot <- got
		}
		clientErr <- nil
	}()

	proxyReader := bufio.NewReader(proxyClientSide)
	req, err := http.ReadRequest(proxyReader)
	if err != nil {
		t.Fatalf("proxy read client req: %v", err)
	}

	openedBefore := counterValue(t, WebSocketSessions.WithLabelValues("opened"))
	inBefore := counterValue(t, WebSocketBytes.WithLabelValues("in"))
	outBefore := counterValue(t, WebSocketBytes.WithLabelValues("out"))

	if err := relayWebSocket(proxyClientSide, proxyUpstreamSide, bufio.NewReader(proxyUpstreamSide), req, time.Second, 5*time.Second); err != nil {
		t.Fatalf("relayWebSocket: %v", err)
	}
	// In production relayHTTPConnLease calls releaseCurrent(false) here,
	// which closes the upstream connection (the conn is not poolable after
	// a WS session). Replicate so the upstream echo goroutine unblocks.
	_ = proxyUpstreamSide.Close()

	if err := waitErr(t, clientErr, 2*time.Second, "client"); err != nil {
		t.Fatal(err)
	}
	if err := waitErr(t, upstreamErr, 2*time.Second, "upstream"); err != nil {
		t.Fatal(err)
	}
	collected := drainBytes(clientGot, 2)
	if len(collected) != 2 || !bytes.Equal(collected[0], []byte("hello-world")) || !bytes.Equal(collected[1], []byte("\x01\x02\x03ping")) {
		t.Fatalf("client echoes mismatch: %v", collected)
	}

	if got := counterValue(t, WebSocketSessions.WithLabelValues("opened")) - openedBefore; got != 1 {
		t.Fatalf("WebSocketSessions[opened] delta = %v, want 1", got)
	}
	minBytes := float64(len("hello-world") + len("\x01\x02\x03ping"))
	if got := counterValue(t, WebSocketBytes.WithLabelValues("in")) - inBefore; got < minBytes {
		t.Fatalf("WebSocketBytes[in] delta = %v, want >= %v", got, minBytes)
	}
	if got := counterValue(t, WebSocketBytes.WithLabelValues("out")) - outBefore; got < minBytes {
		t.Fatalf("WebSocketBytes[out] delta = %v, want >= %v", got, minBytes)
	}
}

// TestRelayWebSocketForwardsNon101Verbatim verifies that when upstream
// refuses the upgrade (e.g. 403), the proxy forwards the response to the
// client and increments the "upstream_refused" counter without entering
// the raw bidi mode.
func TestRelayWebSocketForwardsNon101Verbatim(t *testing.T) {
	clientConn, proxyClientSide := net.Pipe()
	proxyUpstreamSide, upstreamConn := net.Pipe()
	t.Cleanup(func() {
		_ = clientConn.Close()
		_ = proxyClientSide.Close()
		_ = proxyUpstreamSide.Close()
		_ = upstreamConn.Close()
	})

	upstreamDone := make(chan struct{})
	go func() {
		defer close(upstreamDone)
		_, _ = http.ReadRequest(bufio.NewReader(upstreamConn))
		_, _ = io.WriteString(upstreamConn,
			"HTTP/1.1 403 Forbidden\r\n"+
				"Content-Type: text/plain\r\n"+
				"Content-Length: 3\r\n"+
				"\r\n"+
				"no!")
		// Do NOT close upstreamConn here: with net.Pipe, closing while the
		// proxy still has to forward the body to the client introduces a
		// race in which body bytes (buffered in proxy's bufio) may still
		// need a subsequent zero-byte underlying Read that fails with
		// ErrClosedPipe. t.Cleanup handles the close after the test ends.
	}()

	type clientResult struct {
		resp *http.Response
		body []byte
		err  error
	}
	clientCh := make(chan clientResult, 1)
	go func() {
		req := newWSRequest("GET")
		if err := req.Write(clientConn); err != nil {
			clientCh <- clientResult{err: err}
			return
		}
		resp, err := http.ReadResponse(bufio.NewReader(clientConn), req)
		if err != nil {
			clientCh <- clientResult{err: err}
			return
		}
		// Drain the body BEFORE letting the goroutine exit; closing
		// clientConn early would race with the proxy's body Write.
		body, rerr := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		clientCh <- clientResult{resp: resp, body: body, err: rerr}
	}()

	proxyReader := bufio.NewReader(proxyClientSide)
	req, err := http.ReadRequest(proxyReader)
	if err != nil {
		t.Fatalf("proxy read client req: %v", err)
	}

	refusedBefore := counterValue(t, WebSocketSessions.WithLabelValues("upstream_refused"))
	openedBefore := counterValue(t, WebSocketSessions.WithLabelValues("opened"))

	if err := relayWebSocket(proxyClientSide, proxyUpstreamSide, bufio.NewReader(proxyUpstreamSide), req, time.Second, time.Second); err != nil {
		t.Fatalf("relayWebSocket: %v", err)
	}

	var got clientResult
	select {
	case got = <-clientCh:
	case <-time.After(2 * time.Second):
		t.Fatal("client never returned")
	}
	if got.err != nil {
		t.Fatalf("client error: %v", got.err)
	}
	if got.resp.StatusCode != http.StatusForbidden {
		t.Fatalf("client status = %d, want 403", got.resp.StatusCode)
	}
	if string(got.body) != "no!" {
		t.Fatalf("client body = %q, want %q", got.body, "no!")
	}
	select {
	case <-upstreamDone:
	case <-time.After(2 * time.Second):
		t.Fatal("upstream goroutine never returned")
	}
	if got := counterValue(t, WebSocketSessions.WithLabelValues("upstream_refused")) - refusedBefore; got != 1 {
		t.Fatalf("WebSocketSessions[upstream_refused] delta = %v, want 1", got)
	}
	if got := counterValue(t, WebSocketSessions.WithLabelValues("opened")) - openedBefore; got != 0 {
		t.Fatalf("WebSocketSessions[opened] advanced for a non-101 response: delta=%v", got)
	}
}

func TestRelayWebSocketHandshakeUsesHTTPTimeoutDeadlines(t *testing.T) {
	clientPeer, proxyClientRaw := net.Pipe()
	proxyUpstreamRaw, upstreamPeer := net.Pipe()
	proxyClientSide := &wsDeadlineRecordingConn{Conn: proxyClientRaw}
	proxyUpstreamSide := &wsDeadlineRecordingConn{Conn: proxyUpstreamRaw}
	t.Cleanup(func() {
		_ = clientPeer.Close()
		_ = proxyClientSide.Close()
		_ = proxyUpstreamSide.Close()
		_ = upstreamPeer.Close()
	})

	req := newWSRequest("GET")
	upstreamDone := make(chan error, 1)
	go func() {
		_, err := http.ReadRequest(bufio.NewReader(upstreamPeer))
		if err != nil {
			upstreamDone <- err
			return
		}
		_, err = io.WriteString(upstreamPeer,
			"HTTP/1.1 403 Forbidden\r\n"+
				"Content-Type: text/plain\r\n"+
				"Content-Length: 0\r\n"+
				"\r\n")
		upstreamDone <- err
	}()

	clientDone := make(chan error, 1)
	go func() {
		resp, err := http.ReadResponse(bufio.NewReader(clientPeer), req)
		if err != nil {
			clientDone <- err
			return
		}
		_ = resp.Body.Close()
		clientDone <- nil
	}()

	const handshakeTimeout = 250 * time.Millisecond
	if err := relayWebSocket(proxyClientSide, proxyUpstreamSide, bufio.NewReader(proxyUpstreamSide), req, handshakeTimeout, 10*time.Minute); err != nil {
		t.Fatalf("relayWebSocket: %v", err)
	}
	if err := waitErr(t, upstreamDone, 2*time.Second, "upstream"); err != nil {
		t.Fatal(err)
	}
	if err := waitErr(t, clientDone, 2*time.Second, "client"); err != nil {
		t.Fatal(err)
	}
	assertNearDeadline(t, "upstream write", proxyUpstreamSide.writeDeadline(), handshakeTimeout)
	assertNearDeadline(t, "upstream read", proxyUpstreamSide.readDeadline(), handshakeTimeout)
	assertNearDeadline(t, "client write", proxyClientSide.writeDeadline(), handshakeTimeout)
}

// TestRelayHTTPLoopHandlesWebSocketUpgrade exercises the full relay loop
// integration: the relay loop should detect the WS upgrade, branch into the
// dedicated path, perform bidi, and never sanitize away the Upgrade header.
func TestRelayHTTPLoopHandlesWebSocketUpgrade(t *testing.T) {
	clientConn, proxyClientSide := net.Pipe()
	proxyUpstreamSide, upstreamConn := net.Pipe()

	upstreamDone := make(chan error, 1)
	go func() {
		defer upstreamConn.Close()
		req, err := http.ReadRequest(bufio.NewReader(upstreamConn))
		if err != nil {
			upstreamDone <- err
			return
		}
		if !isWebSocketUpgrade(req) {
			upstreamDone <- fmt.Errorf("upstream did not see WS upgrade: %+v", req.Header)
			return
		}
		_, err = io.WriteString(upstreamConn,
			"HTTP/1.1 101 Switching Protocols\r\n"+
				"Upgrade: websocket\r\n"+
				"Connection: Upgrade\r\n"+
				"Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n"+
				"\r\n"+
				"frame-from-upstream")
		if err != nil {
			upstreamDone <- err
			return
		}
		buf := make([]byte, 64)
		n, _ := upstreamConn.Read(buf)
		if n > 0 {
			_, _ = upstreamConn.Write(append([]byte("echo:"), buf[:n]...))
		}
		upstreamDone <- nil
	}()

	clientDone := make(chan error, 1)
	clientGot := make(chan []byte, 4)
	go func() {
		defer clientConn.Close()
		req := newWSRequest("GET")
		if err := req.Write(clientConn); err != nil {
			clientDone <- err
			return
		}
		resp, err := http.ReadResponse(bufio.NewReader(clientConn), req)
		if err != nil {
			clientDone <- err
			return
		}
		if resp.StatusCode != http.StatusSwitchingProtocols {
			clientDone <- fmt.Errorf("status %d, want 101", resp.StatusCode)
			return
		}
		pre := make([]byte, len("frame-from-upstream"))
		if _, err := io.ReadFull(clientConn, pre); err != nil {
			clientDone <- err
			return
		}
		clientGot <- pre
		if _, err := clientConn.Write([]byte("ping")); err != nil {
			clientDone <- err
			return
		}
		echo := make([]byte, len("echo:ping"))
		if _, err := io.ReadFull(clientConn, echo); err != nil {
			clientDone <- err
			return
		}
		clientGot <- echo
		clientDone <- nil
	}()

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	dial := func() (net.Conn, error) { return proxyUpstreamSide, nil }
	if err := relayHTTPDial(proxyClientSide, dial, logger, RelayOptions{IOTimeout: time.Second}); err != nil {
		t.Fatalf("relayHTTPDial: %v", err)
	}

	if err := waitErr(t, clientDone, 2*time.Second, "client"); err != nil {
		t.Fatal(err)
	}
	if err := waitErr(t, upstreamDone, 2*time.Second, "upstream"); err != nil {
		t.Fatal(err)
	}
	got := drainBytes(clientGot, 2)
	if len(got) != 2 || string(got[0]) != "frame-from-upstream" || string(got[1]) != "echo:ping" {
		t.Fatalf("frames received = %q, want [frame-from-upstream, echo:ping]", got)
	}
}

// --- helpers ---

func newWSRequest(method string) *http.Request {
	req, _ := http.NewRequest(method, "http://example.test/chat", nil)
	req.Host = "example.test"
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Sec-WebSocket-Version", "13")
	req.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
	return req
}

type wsDeadlineRecordingConn struct {
	net.Conn
	mu sync.Mutex
	rd time.Time
	wd time.Time
}

func (c *wsDeadlineRecordingConn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	c.rd = t
	c.mu.Unlock()
	return c.Conn.SetReadDeadline(t)
}

func (c *wsDeadlineRecordingConn) SetWriteDeadline(t time.Time) error {
	c.mu.Lock()
	c.wd = t
	c.mu.Unlock()
	return c.Conn.SetWriteDeadline(t)
}

func (c *wsDeadlineRecordingConn) readDeadline() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.rd
}

func (c *wsDeadlineRecordingConn) writeDeadline() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.wd
}

func assertNearDeadline(t *testing.T, name string, got time.Time, timeout time.Duration) {
	t.Helper()
	if got.IsZero() {
		t.Fatalf("%s deadline was not set", name)
	}
	remaining := time.Until(got)
	if remaining <= 0 || remaining > timeout+500*time.Millisecond {
		t.Fatalf("%s deadline remaining = %s, want near %s", name, remaining, timeout)
	}
}

func waitErr(t *testing.T, ch <-chan error, d time.Duration, who string) error {
	t.Helper()
	select {
	case err := <-ch:
		return err
	case <-time.After(d):
		return fmt.Errorf("%s timed out after %s", who, d)
	}
}

func drainBytes(ch <-chan []byte, n int) [][]byte {
	got := make([][]byte, 0, n)
	for i := 0; i < n; i++ {
		select {
		case b := <-ch:
			got = append(got, b)
		case <-time.After(time.Second):
			return got
		}
	}
	return got
}
