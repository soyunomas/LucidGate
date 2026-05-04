package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"html"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"time"
)

const defaultAddr = "127.0.0.1:8080"

// downstreamSessionCache is shared across all hijacked TLS connections so
// browsers can resume sessions when reopening keep-alive-killed sockets to the
// same hostname. Combined with TLS 1.3 PSK this turns reconnects into 1-RTT
// (or 0-RTT) handshakes, which is the dominant cost of MITM at carrier scale.
var downstreamSessionCache = tls.NewLRUClientSessionCache(8192)

type CertificateProvider interface {
	Get(hostname string) (*tls.Certificate, error)
}

type UpstreamDialer interface {
	Dial(ctx context.Context, address, serverName string) (net.Conn, error)
}

type PlainHTTPDialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

type Server struct {
	httpServer *http.Server
	logger     *slog.Logger
	certs      CertificateProvider
	upstream   UpstreamDialer
	httpDialer PlainHTTPDialer
	handshake  time.Duration
	relay      atomic.Value
	limiter    atomic.Value
	rules      atomic.Value
	access     atomic.Value
	schedules  atomic.Value
	now        func() time.Time
}

type connLimiter struct {
	slots chan struct{}
}

func NewServer(addr string, logger *slog.Logger, certs ...CertificateProvider) *Server {
	if addr == "" {
		addr = defaultAddr
	}
	s := &Server{
		logger:    logger,
		handshake: 5 * time.Second,
		now:       time.Now,
	}
	s.relay.Store(RelayOptions{
		LogBodies:       true,
		MaxCaptureBytes: 1 << 20,
		IOTimeout:       30 * time.Second,
	})
	s.rules.Store(NewDomainRules(nil))
	access, _ := NewAccessRules(nil)
	s.access.Store(access)
	schedules, _ := NewScheduleRules(nil)
	s.schedules.Store(schedules)
	s.SetMaxConnections(1024)
	if len(certs) > 0 {
		s.certs = certs[0]
	}
	s.httpServer = &http.Server{
		Addr:              addr,
		Handler:           s,
		ReadHeaderTimeout: 5 * time.Second,
	}
	return s
}

func (s *Server) Addr() string {
	return s.httpServer.Addr
}

func (s *Server) SetUpstreamDialer(upstream UpstreamDialer) {
	s.upstream = upstream
}

func (s *Server) SetPlainHTTPDialer(dialer PlainHTTPDialer) {
	s.httpDialer = dialer
}

func (s *Server) SetHandshakeTimeout(timeout time.Duration) {
	if timeout > 0 {
		s.handshake = timeout
	}
}

func (s *Server) SetRelayOptions(opts RelayOptions) {
	s.relay.Store(opts)
}

func (s *Server) SetDomainRules(rules *DomainRules) {
	if rules == nil {
		rules = NewDomainRules(nil)
	}
	s.rules.Store(rules)
}

func (s *Server) SetAccessRules(rules *AccessRules) {
	if rules == nil {
		rules, _ = NewAccessRules(nil)
	}
	s.access.Store(rules)
}

func (s *Server) SetScheduleRules(rules *ScheduleRules) {
	if rules == nil {
		rules, _ = NewScheduleRules(nil)
	}
	s.schedules.Store(rules)
}

func (s *Server) SetClock(now func() time.Time) {
	if now == nil {
		now = time.Now
	}
	s.now = now
}

func (s *Server) SetMaxConnections(max int) {
	if max <= 0 {
		max = 1
	}
	s.limiter.Store(&connLimiter{slots: make(chan struct{}, max)})
}

func (s *Server) Serve(ctx context.Context) error {
	ln, err := net.Listen("tcp", s.httpServer.Addr)
	if err != nil {
		return fmt.Errorf("listen proxy: %w", err)
	}
	defer ln.Close()

	errCh := make(chan error, 1)
	go func() {
		errCh <- s.httpServer.Serve(ln)
	}()

	if s.logger != nil {
		s.logger.Info("proxy listening", slog.String("addr", ln.Addr().String()))
	}

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := s.httpServer.Shutdown(shutdownCtx); err != nil {
			return fmt.Errorf("shutdown proxy: %w", err)
		}
		err := <-errCh
		if errors.Is(err, http.ErrServerClosed) {
			return ctx.Err()
		}
		return err
	case err := <-errCh:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	profile, allowed := s.clientProfile(r.RemoteAddr)
	if !allowed {
		writeBlockPage(w, http.StatusForbidden, "Client access denied", "This client is not assigned to an allowed LucidGate access profile.")
		return
	}
	if !s.scheduleAllowed(profile) {
		writeBlockPage(w, http.StatusForbidden, "Access outside allowed schedule", "The active access profile is outside its configured time window.")
		return
	}
	if r.Method != http.MethodConnect {
		s.handlePlainHTTP(w, r)
		return
	}
	host, err := connectHostname(r)
	if err != nil {
		http.Error(w, "bad connect host", http.StatusBadRequest)
		return
	}
	if s.domainBlocked(host) {
		writeBlockPage(w, http.StatusForbidden, "Access denied", "LucidGate blocked this destination by domain policy.")
		return
	}
	permit, ok := s.acquireConn()
	if !ok {
		writeBlockPage(w, http.StatusServiceUnavailable, "Connection limit exceeded", "LucidGate is at the configured concurrent connection limit.")
		return
	}
	defer s.releaseConn(permit)
	s.handleHTTPS(w, r)
}

func (s *Server) handlePlainHTTP(w http.ResponseWriter, r *http.Request) {
	host, address, err := plainHTTPDestination(r)
	if err != nil {
		http.Error(w, "bad proxy request", http.StatusBadRequest)
		return
	}
	if s.domainBlocked(host) {
		writeBlockPage(w, http.StatusForbidden, "Access denied", "LucidGate blocked this destination by domain policy.")
		return
	}
	permit, ok := s.acquireConn()
	if !ok {
		writeBlockPage(w, http.StatusServiceUnavailable, "Connection limit exceeded", "LucidGate is at the configured concurrent connection limit.")
		return
	}
	defer s.releaseConn(permit)

	opts := s.relay.Load().(RelayOptions)
	upstreamConn, err := s.dialPlainHTTP(r.Context(), address, opts.IOTimeout)
	if err != nil {
		if s.logger != nil {
			s.logger.Error("dial http upstream", slog.String("address", address), slog.String("host", host), slog.Any("error", err))
		}
		writeBlockPage(w, http.StatusBadGateway, "Upstream unavailable", "LucidGate could not open a connection to the requested HTTP upstream.")
		return
	}
	defer upstreamConn.Close()

	if err := setHTTPReadDeadline(w, opts.IOTimeout); err != nil && s.logger != nil {
		s.logger.Error("deadline http client read", slog.String("address", address), slog.String("host", host), slog.Any("error", err))
	}
	if err := setWriteDeadline(upstreamConn, opts.IOTimeout); err != nil {
		closeRequestBody(r)
		if s.logger != nil {
			s.logger.Error("deadline http upstream write", slog.String("address", address), slog.String("host", host), slog.Any("error", err))
		}
		writeBlockPage(w, http.StatusBadGateway, "Upstream unavailable", "LucidGate could not prepare the upstream HTTP connection.")
		return
	}

	xid := newExchangeID()
	SanitizeHeaders(r)
	normalizeRequestURL(r)
	reqCap := newBodyCapture(r.Body != nil, opts)
	reqBytes, err := writeRequestStreaming(upstreamConn, r, reqCap, opts.RequestFilter)
	closeRequestBody(r)
	if opts.DumpDir != "" {
		data, trunc, skipped := reqCap.dumpPayload()
		emitDump(opts.DumpDir, "req", xid, r, nil, data, trunc, skipped, s.logger)
	}
	if err != nil {
		if s.logger != nil {
			s.logger.Error("write http upstream request", slog.String("address", address), slog.String("host", host), slog.Any("error", err))
		}
		return
	}

	if err := setReadDeadline(upstreamConn, opts.IOTimeout); err != nil {
		if s.logger != nil {
			s.logger.Error("deadline http upstream read", slog.String("address", address), slog.String("host", host), slog.Any("error", err))
		}
		writeBlockPage(w, http.StatusBadGateway, "Upstream unavailable", "LucidGate could not read from the upstream HTTP connection.")
		return
	}
	resp, err := http.ReadResponse(bufio.NewReader(upstreamConn), r)
	if err != nil {
		if s.logger != nil {
			s.logger.Error("read http upstream response", slog.String("address", address), slog.String("host", host), slog.Any("error", err))
		}
		writeBlockPage(w, http.StatusBadGateway, "Upstream unavailable", "LucidGate received an invalid response from the upstream HTTP connection.")
		return
	}
	defer closeResponseBody(resp)

	if err := setHTTPWriteDeadline(w, opts.IOTimeout); err != nil && s.logger != nil {
		s.logger.Error("deadline http client write", slog.String("address", address), slog.String("host", host), slog.Any("error", err))
	}
	respCap := newBodyCapture(resp.Body != nil, opts)
	respBytes, err := writeResponseStreamingHTTP(w, resp, respCap, opts.Filter)
	logExchange(s.logger, r, resp, reqBytes, respBytes)
	if opts.DumpDir != "" {
		data, trunc, skipped := respCap.dumpPayload()
		emitDump(opts.DumpDir, "resp", xid, r, resp, data, trunc, skipped, s.logger)
	}
	if err != nil && s.logger != nil {
		s.logger.Error("write http client response", slog.String("address", address), slog.String("host", host), slog.Any("error", err))
	}
}

func (s *Server) dialPlainHTTP(ctx context.Context, address string, timeout time.Duration) (net.Conn, error) {
	dialer := s.httpDialer
	if dialer == nil {
		dialer = &net.Dialer{Timeout: timeout}
	}
	return dialer.DialContext(ctx, "tcp", address)
}

func (s *Server) domainBlocked(host string) bool {
	rules := s.rules.Load().(*DomainRules)
	return rules.Blocked(host)
}

func (s *Server) clientProfile(remoteAddr string) (string, bool) {
	rules := s.access.Load().(*AccessRules)
	return rules.ProfileForRemoteAddr(remoteAddr)
}

func (s *Server) scheduleAllowed(profile string) bool {
	rules := s.schedules.Load().(*ScheduleRules)
	return rules.Allowed(profile, s.now())
}

func (s *Server) acquireConn() (*connLimiter, bool) {
	limiter := s.limiter.Load().(*connLimiter)
	select {
	case limiter.slots <- struct{}{}:
		return limiter, true
	default:
		return nil, false
	}
}

func (s *Server) releaseConn(limiter *connLimiter) {
	select {
	case <-limiter.slots:
	default:
	}
}

func writeBlockPage(w http.ResponseWriter, status int, title, detail string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	_, _ = fmt.Fprintf(w, `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>%s - LucidGate</title>
<style>
:root { color-scheme: light dark; font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; }
body { margin: 0; min-height: 100vh; display: grid; place-items: center; background: #f6f7f9; color: #111827; }
main { width: min(42rem, calc(100%% - 2rem)); border: 1px solid #d8dee8; border-radius: 8px; background: #ffffff; padding: 2rem; box-shadow: 0 16px 40px rgb(15 23 42 / 10%%); }
.brand { color: #4b5563; font-size: .875rem; font-weight: 700; letter-spacing: .08em; text-transform: uppercase; }
h1 { margin: .75rem 0 1rem; font-size: clamp(1.75rem, 2vw, 2.25rem); line-height: 1.15; }
p { margin: 0; color: #374151; line-height: 1.55; }
.code { margin-top: 1.5rem; color: #6b7280; font-size: .875rem; }
@media (prefers-color-scheme: dark) {
body { background: #111827; color: #f9fafb; }
main { background: #1f2937; border-color: #374151; box-shadow: none; }
.brand, p, .code { color: #d1d5db; }
}
</style>
</head>
<body>
<main>
<div class="brand">LucidGate</div>
<h1>%s</h1>
<p>%s</p>
<p class="code">HTTP %d %s</p>
</main>
</body>
</html>
`, html.EscapeString(title), html.EscapeString(title), html.EscapeString(detail), status, html.EscapeString(http.StatusText(status)))
}

func (s *Server) handleHTTPS(w http.ResponseWriter, r *http.Request) {
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijacking not supported", http.StatusInternalServerError)
		return
	}

	conn, bufrw, err := hijacker.Hijack()
	if err != nil {
		if s.logger != nil {
			s.logger.Error("hijack failed", slog.String("host", r.Host), slog.Any("error", err))
		}
		return
	}
	defer conn.Close()

	if err := conn.SetDeadline(time.Now().Add(s.handshake)); err != nil && s.logger != nil {
		s.logger.Error("set deadline failed", slog.String("host", r.Host), slog.Any("error", err))
	}
	if bufrw.Reader.Buffered() > 0 && s.logger != nil {
		s.logger.Warn("discarding buffered client bytes after CONNECT", slog.String("host", r.Host), slog.Int("bytes", bufrw.Reader.Buffered()))
	}

	if _, err := bufrw.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		if s.logger != nil {
			s.logger.Error("write connect response", slog.String("host", r.Host), slog.Any("error", err))
		}
		return
	}
	if err := bufrw.Flush(); err != nil && s.logger != nil {
		s.logger.Error("flush connect response", slog.String("host", r.Host), slog.Any("error", err))
	}
	if s.certs == nil {
		return
	}

	host, _ := connectHostname(r)
	cert, err := s.certs.Get(host)
	if err != nil {
		if s.logger != nil {
			s.logger.Error("get leaf cert", slog.String("host", host), slog.Any("error", err))
		}
		return
	}

	tlsConn := tls.Server(conn, &tls.Config{
		Certificates:[]tls.Certificate{*cert},
		MinVersion:         tls.VersionTLS12,
		ClientSessionCache: downstreamSessionCache,
	})
	if err := tlsConn.Handshake(); err != nil {
		if s.logger != nil {
			s.logger.Error("local tls handshake", slog.String("host", host), slog.Any("error", err))
		}
		return
	}
	if err := conn.SetDeadline(time.Time{}); err != nil && s.logger != nil {
		s.logger.Error("clear deadline", slog.String("host", host), slog.Any("error", err))
	}
	if s.upstream == nil {
		return
	}

	address := connectAddress(r)
	remoteConn, err := s.upstream.Dial(r.Context(), address, host)
	if err != nil {
		if s.logger != nil {
			s.logger.Error("dial upstream", slog.String("address", address), slog.String("host", host), slog.Any("error", err))
		}
		writeTLSBadGateway(tlsConn)
		return
	}
	defer remoteConn.Close()
	opts := s.relay.Load().(RelayOptions)
	if err := relayHTTP(tlsConn, remoteConn, s.logger, opts); err != nil && s.logger != nil {
		s.logger.Error("relay failed", slog.String("address", address), slog.String("host", host), slog.Any("error", err))
	}
}

func connectHostname(r *http.Request) (string, error) {
	if host := r.URL.Hostname(); host != "" {
		return host, nil
	}
	if host, _, err := net.SplitHostPort(r.Host); err == nil {
		return host, nil
	}
	if r.Host != "" {
		return r.Host, nil
	}
	return "", errors.New("empty connect host")
}

func connectAddress(r *http.Request) string {
	address := r.URL.Host
	if address == "" {
		address = r.Host
	}
	if address == "" {
		return ""
	}
	if _, _, err := net.SplitHostPort(address); err == nil {
		return address
	}
	if strings.Contains(address, ":") && strings.HasPrefix(address, "[") {
		return address
	}
	return net.JoinHostPort(address, "443")
}

func plainHTTPDestination(r *http.Request) (host string, address string, err error) {
	if r == nil {
		return "", "", errors.New("nil request")
	}
	if r.URL != nil && r.URL.IsAbs() {
		if !strings.EqualFold(r.URL.Scheme, "http") {
			return "", "", fmt.Errorf("unsupported scheme %q", r.URL.Scheme)
		}
		host = r.URL.Hostname()
		address = r.URL.Host
	} else {
		host = r.Host
		address = r.Host
		if splitHost, _, splitErr := net.SplitHostPort(host); splitErr == nil {
			host = splitHost
		}
	}
	if host == "" || address == "" {
		return "", "", errors.New("empty http host")
	}
	if _, _, splitErr := net.SplitHostPort(address); splitErr == nil {
		return host, address, nil
	}
	return host, net.JoinHostPort(host, "80"), nil
}

func setHTTPReadDeadline(w http.ResponseWriter, timeout time.Duration) error {
	if timeout <= 0 {
		return nil
	}
	err := http.NewResponseController(w).SetReadDeadline(time.Now().Add(timeout))
	if errors.Is(err, http.ErrNotSupported) {
		return nil
	}
	return err
}

func setHTTPWriteDeadline(w http.ResponseWriter, timeout time.Duration) error {
	if timeout <= 0 {
		return nil
	}
	err := http.NewResponseController(w).SetWriteDeadline(time.Now().Add(timeout))
	if errors.Is(err, http.ErrNotSupported) {
		return nil
	}
	return err
}

func writeTLSBadGateway(conn net.Conn) {
	_, _ = conn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\nContent-Length: 0\r\n\r\n"))
}
