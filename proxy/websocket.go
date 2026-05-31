package proxy

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// DefaultWebSocketIdleTimeout is the per-direction idle deadline applied to
// raw byte copies after a successful WebSocket Upgrade. WebSocket sessions
// (chat, live dashboards, terminal) are routinely idle for several minutes,
// so the value is intentionally larger than the per-exchange IOTimeout used
// for HTTP. The deadline is refreshed on every Read/Write iteration.
const DefaultWebSocketIdleTimeout = 5 * time.Minute

// isWebSocketUpgrade reports whether req is a WebSocket Upgrade handshake per
// RFC 6455 §4.1: GET method, a Connection header containing the "upgrade"
// token (case-insensitive, comma-separated), and an Upgrade header whose
// single token equals "websocket".
func isWebSocketUpgrade(req *http.Request) bool {
	if req == nil || !strings.EqualFold(req.Method, http.MethodGet) {
		return false
	}
	if !headerContainsToken(req.Header.Values("Connection"), "upgrade") {
		return false
	}
	return strings.EqualFold(strings.TrimSpace(req.Header.Get("Upgrade")), "websocket")
}

// headerContainsToken reports whether any of the comma-separated tokens in
// values matches the requested token (case-insensitive, trimmed).
func headerContainsToken(values []string, token string) bool {
	for _, v := range values {
		for _, part := range strings.Split(v, ",") {
			if strings.EqualFold(strings.TrimSpace(part), token) {
				return true
			}
		}
	}
	return false
}

// sanitizeWebSocketRequest removes only the proxy-hop headers, preserving the
// WebSocket handshake headers that SanitizeHeaders would otherwise delete
// (Connection, Upgrade, Sec-WebSocket-Key, Sec-WebSocket-Version, etc.).
func sanitizeWebSocketRequest(req *http.Request) {
	req.Header.Del("Proxy-Connection")
	req.Header.Del("X-Forwarded-For")
	req.Header.Del("Via")
	req.Header.Del("X-Real-IP")
}

// relayWebSocket forwards an Upgrade request to upstream, reads the response,
// and — if it is "101 Switching Protocols" — performs a raw bidirectional
// byte copy between client and upstream until either side closes or idles
// past idleTimeout in any direction. Non-101 responses are forwarded back to
// the client as a normal HTTP exchange and the connection is closed.
//
// The upstream connection is never reusable after this function returns
// (regardless of outcome): a WebSocket session ends with a half-closed TCP
// stream or framed garbage, neither of which is safe to pool for HTTP reuse.
//
// idleTimeout of 0 or negative falls back to DefaultWebSocketIdleTimeout.
func relayWebSocket(
	clientConn net.Conn,
	upstreamConn net.Conn,
	upstreamReader *bufio.Reader,
	req *http.Request,
	handshakeTimeout time.Duration,
	idleTimeout time.Duration,
) error {
	if handshakeTimeout <= 0 {
		handshakeTimeout = idleTimeout
	}
	if idleTimeout <= 0 {
		idleTimeout = DefaultWebSocketIdleTimeout
	}

	sanitizeWebSocketRequest(req)
	normalizeRequestURL(req)

	if err := setWriteDeadline(upstreamConn, handshakeTimeout); err != nil {
		WebSocketSessions.WithLabelValues("error").Inc()
		return fmt.Errorf("deadline upstream ws request write: %w", err)
	}
	if err := req.Write(upstreamConn); err != nil {
		WebSocketSessions.WithLabelValues("error").Inc()
		return fmt.Errorf("write upstream ws request: %w", err)
	}

	if err := setReadDeadline(upstreamConn, handshakeTimeout); err != nil {
		WebSocketSessions.WithLabelValues("error").Inc()
		return fmt.Errorf("deadline upstream ws response read: %w", err)
	}
	resp, err := http.ReadResponse(upstreamReader, req)
	if err != nil {
		WebSocketSessions.WithLabelValues("error").Inc()
		return fmt.Errorf("read upstream ws response: %w", err)
	}
	if stripHTTP3Advertising(resp.Header) {
		AltSvcStripped.Inc()
	}

	// Anything other than 101 is a refusal: forward verbatim and close.
	if resp.StatusCode != http.StatusSwitchingProtocols {
		defer closeResponseBody(resp)
		WebSocketSessions.WithLabelValues("upstream_refused").Inc()
		if err := setWriteDeadline(clientConn, handshakeTimeout); err != nil {
			return fmt.Errorf("deadline client ws-rejected response write: %w", err)
		}
		if werr := resp.Write(clientConn); werr != nil {
			return fmt.Errorf("write ws-rejected response: %w", werr)
		}
		return nil
	}

	// 101 accepted: forward the upstream's response headers verbatim so the
	// client completes the handshake (Sec-WebSocket-Accept et al).
	closeResponseBody(resp)
	if err := setWriteDeadline(clientConn, handshakeTimeout); err != nil {
		WebSocketSessions.WithLabelValues("error").Inc()
		return fmt.Errorf("deadline client ws 101 write: %w", err)
	}
	if werr := writeResponseHeader(clientConn, resp); werr != nil {
		WebSocketSessions.WithLabelValues("error").Inc()
		return fmt.Errorf("write 101 response header: %w", werr)
	}

	// Drain any bytes that the upstream already pushed into the bufio
	// reader past the response header (some servers send the first frame
	// immediately). They must be forwarded before swapping to raw copy or
	// the client will block waiting for them.
	if buffered := upstreamReader.Buffered(); buffered > 0 {
		leftover, _ := upstreamReader.Peek(buffered)
		if err := setWriteDeadline(clientConn, idleTimeout); err != nil {
			WebSocketSessions.WithLabelValues("error").Inc()
			return fmt.Errorf("deadline prebuffered ws frame write: %w", err)
		}
		if _, werr := clientConn.Write(leftover); werr != nil {
			WebSocketSessions.WithLabelValues("error").Inc()
			return fmt.Errorf("forward prebuffered ws frame: %w", werr)
		}
		_, _ = upstreamReader.Discard(buffered)
		WebSocketBytes.WithLabelValues("out").Add(float64(buffered))
	}

	WebSocketSessions.WithLabelValues("opened").Inc()
	pumpWebSocket(clientConn, upstreamConn, idleTimeout)
	return nil
}

// pumpWebSocket runs the bidirectional raw-byte copy with idle deadlines.
// When one direction returns (peer close or error), the deadlines on both
// sockets are tripped so the other goroutine's blocked Read unblocks
// immediately and the function returns without leaking a goroutine.
func pumpWebSocket(clientConn, upstreamConn net.Conn, idleTimeout time.Duration) {
	var wg sync.WaitGroup
	wg.Add(2)
	done := make(chan struct{}, 2)

	go func() {
		defer wg.Done()
		copyDirection(upstreamConn, clientConn, "in", idleTimeout)
		done <- struct{}{}
	}()
	go func() {
		defer wg.Done()
		copyDirection(clientConn, upstreamConn, "out", idleTimeout)
		done <- struct{}{}
	}()

	<-done
	// One direction has terminated; the WebSocket session is over. The
	// connections are NOT reusable (the protocol is no longer HTTP/1), so
	// close both to unblock the still-pending Read on the other side
	// immediately. SetDeadline alone is unreliable across all conn types
	// when one peer has already half-closed; Close is decisive.
	_ = clientConn.Close()
	_ = upstreamConn.Close()
	wg.Wait()
}

// copyDirection reads from src and writes to dst with an idle deadline on
// every Read and Write. direction is the label for the WebSocketBytes metric
// ("in" for client->upstream, "out" for upstream->client).
func copyDirection(dst, src net.Conn, direction string, idleTimeout time.Duration) {
	bufPtr := relayBufferPool.Get().(*[]byte)
	defer relayBufferPool.Put(bufPtr)
	buf := *bufPtr
	for {
		if err := src.SetReadDeadline(time.Now().Add(idleTimeout)); err != nil {
			return
		}
		n, rerr := src.Read(buf)
		if n > 0 {
			if err := dst.SetWriteDeadline(time.Now().Add(idleTimeout)); err != nil {
				return
			}
			if _, werr := dst.Write(buf[:n]); werr != nil {
				return
			}
			WebSocketBytes.WithLabelValues(direction).Add(float64(n))
		}
		if rerr != nil {
			if rerr == io.EOF {
				return
			}
			return
		}
	}
}
