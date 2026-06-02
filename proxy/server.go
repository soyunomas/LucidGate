package proxy

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"html"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go/http3"
	utls "github.com/refraction-networking/utls"
	"github.com/sony/gobreaker"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"golang.org/x/net/http2"
	"golang.org/x/sync/semaphore"
)

const defaultAddr = "127.0.0.1:8080"

var errNegotiatedH2 = errors.New("negotiated HTTP/2 with upstream")

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
	httpServer   *http.Server
	logger       *slog.Logger
	certs        CertificateProvider
	upstream     UpstreamDialer
	h2Upstream   UpstreamDialer
	httpDialer   PlainHTTPDialer
	handshake    time.Duration
	waitTimeout  int64 // atomic nanoseconds
	certWorkers  int32
	certQueue    chan string
	relay        atomic.Value
	limiter      atomic.Value
	rules        atomic.Value
	policy       atomic.Value
	access       atomic.Value
	schedules    atomic.Value
	upstreamPool atomic.Value
	mitmBypass   atomic.Value
	greySSLSites atomic.Value
	greySSLIps   atomic.Value
	now          func() time.Time
	rateLimiter  *ipRateLimiter
	h2Transport  *http2.Transport
	h2Hosts      sync.Map
	h2Conns      sync.Map
	reusePort    bool
	activeConns  sync.Map
	upgrader     Upgrader
	breakers     *CircuitBreakers
	dnsResolver  *DNSResolver
	http3Enabled bool
}

type bypassMatcher struct {
	trie domainTrie
}

func (m *bypassMatcher) Match(host string) bool {
	if m == nil {
		return false
	}
	return m.trie.Match(host)
}

type connLimiter struct {
	globalSem   *semaphore.Weighted
	profileSems map[string]*semaphore.Weighted
}

type connLimiterPermit struct {
	limiter    *connLimiter
	profile    string
	hasProfile bool
}

func NewServer(addr string, logger *slog.Logger, certs ...CertificateProvider) *Server {
	if addr == "" {
		addr = defaultAddr
	}
	s := &Server{
		logger:      logger,
		handshake:   5 * time.Second,
		now:         time.Now,
		rateLimiter: newIPRateLimiter(16384),
		upgrader:    NewFallbackUpgrader(),
		breakers:    NewCircuitBreakers(true, 5, 30*time.Second),
		dnsResolver: NewDNSResolver(false, 60*time.Second),
	}
	s.h2Transport = &http2.Transport{
		DialTLSContext: func(ctx context.Context, network, addr string, cfg *tls.Config) (net.Conn, error) {
			host, _, err := net.SplitHostPort(addr)
			if err != nil {
				host = addr
			}
			dialer := s.h2Upstream
			if dialer == nil {
				dialer = s.upstream
			}
			if dialer == nil {
				return nil, fmt.Errorf("no upstream dialer configured")
			}
			dialAddr, err := s.resolveDialAddress(ctx, addr)
			if err != nil {
				return nil, err
			}
			if s.breakers == nil {
				return dialer.Dial(ctx, dialAddr, host)
			}
			return s.breakers.Execute(host, func() (net.Conn, error) {
				return dialer.Dial(ctx, dialAddr, host)
			})
		},
		DisableCompression: true,
	}
	s.SetWaitTimeout(250 * time.Millisecond)
	s.certQueue = make(chan string, 4096)
	s.SetCertWorkers(4)
	s.SetUpstreamPool(UpstreamPoolConfig{
		MaxIdlePerHost: defaultUpstreamMaxIdlePerHost,
		IdleTimeout:    defaultUpstreamIdleTimeout,
	})
	s.relay.Store(RelayOptions{
		LogBodies:       true,
		MaxCaptureBytes: 1 << 20,
		IOTimeout:       30 * time.Second,
	})
	s.rules.Store(NewDomainRules(nil))
	policy, _ := NewPolicy(PolicyConfig{})
	s.policy.Store(policy)
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

func (s *Server) SetH2UpstreamDialer(dialer UpstreamDialer) {
	s.h2Upstream = dialer
}

func (s *Server) SetPlainHTTPDialer(dialer PlainHTTPDialer) {
	s.httpDialer = dialer
}

func (s *Server) SetUpstreamPool(cfg UpstreamPoolConfig) {
	s.closeIdleUpstreamConnections()
	s.upstreamPool.Store(newUpstreamConnPool(cfg))
}

func (s *Server) SetHTTP3Enabled(enabled bool) {
	s.http3Enabled = enabled
	opts := s.relay.Load().(RelayOptions)
	opts.HTTP3Enabled = enabled
	_, port, err := net.SplitHostPort(s.httpServer.Addr)
	if err != nil || port == "" {
		port = "443"
	}
	opts.HTTP3Port = port
	s.relay.Store(opts)
}

func (s *Server) SetMITMBypass(hosts []string) {
	m := &bypassMatcher{}
	for _, host := range hosts {
		host = strings.TrimPrefix(host, "*.")
		m.trie.Add(host)
	}
	s.mitmBypass.Store(m)
}

func (s *Server) SetGreySSLRules(sites *DomainMatcher, ips *IPMatcher) {
	s.greySSLSites.Store(sites)
	s.greySSLIps.Store(ips)
}

func (s *Server) shouldBypassMITM(host string) bool {
	if val := s.greySSLSites.Load(); val != nil {
		if sites, ok := val.(*DomainMatcher); ok && sites.Match(host) {
			return false
		}
	}
	if val := s.greySSLIps.Load(); val != nil {
		if ips, ok := val.(*IPMatcher); ok {
			hostStr := host
			if h, _, err := net.SplitHostPort(host); err == nil {
				hostStr = h
			}
			if addr, err := netip.ParseAddr(hostStr); err == nil {
				if ips.Match(addr) {
					return false
				}
			}
		}
	}

	val := s.mitmBypass.Load()
	if val == nil {
		return false
	}
	m, _ := val.(*bypassMatcher)
	return m.Match(host)
}

func (s *Server) SetHandshakeTimeout(timeout time.Duration) {
	if timeout > 0 {
		s.handshake = timeout
	}
}

func (s *Server) SetWaitTimeout(timeout time.Duration) {
	atomic.StoreInt64(&s.waitTimeout, int64(timeout))
}

func (s *Server) WaitTimeout() time.Duration {
	return time.Duration(atomic.LoadInt64(&s.waitTimeout))
}

func (s *Server) SetCertWorkers(n int) {
	atomic.StoreInt32(&s.certWorkers, int32(n))
}

func (s *Server) CertWorkers() int {
	return int(atomic.LoadInt32(&s.certWorkers))
}

func (s *Server) SetReusePort(enable bool) {
	s.reusePort = enable
}

func (s *Server) ReusePort() bool {
	return s.reusePort
}

func (s *Server) SetUpgrader(u Upgrader) {
	s.upgrader = u
}

func (s *Server) SetCircuitBreaker(enabled bool, failures int, timeout time.Duration) {
	s.breakers = NewCircuitBreakers(enabled, failures, timeout)
}

func (s *Server) SetDNSResolver(enabled bool, ttl time.Duration) {
	s.dnsResolver = NewDNSResolver(enabled, ttl)
}

func (s *Server) IsSaturated() bool {
	limiter, ok := s.limiter.Load().(*connLimiter)
	if !ok || limiter == nil {
		return false
	}
	if limiter.globalSem != nil {
		if limiter.globalSem.TryAcquire(1) {
			limiter.globalSem.Release(1)
		} else {
			return true
		}
	}
	return false
}

func (s *Server) trackConn(c net.Conn) {
	s.activeConns.Store(c, struct{}{})
}

func (s *Server) untrackConn(c net.Conn) {
	s.activeConns.Delete(c)
}

func (s *Server) drainHijacked(timeout time.Duration) {
	if s.logger != nil {
		s.logger.Info("draining active hijacked connections", slog.Duration("timeout", timeout))
	}
	start := s.now()
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	for s.now().Sub(start) < timeout {
		count := 0
		s.activeConns.Range(func(key, value any) bool {
			count++
			return true
		})
		if count == 0 {
			if s.logger != nil {
				s.logger.Info("all hijacked connections drained successfully")
			}
			return
		}
		<-ticker.C
	}

	// Force close any remaining hijacked connections
	s.activeConns.Range(func(key, value any) bool {
		if c, ok := key.(net.Conn); ok {
			_ = c.Close()
		}
		return true
	})
	if s.logger != nil {
		s.logger.Warn("graceful drain timeout exceeded, remaining connections force-closed")
	}
}

func (s *Server) PrewarmCertificates(hosts []string) int {
	if len(hosts) == 0 || s.certs == nil {
		return 0
	}
	enqueued := 0
	seen := make(map[string]struct{}, len(hosts))
	for _, host := range hosts {
		host = strings.TrimSpace(host)
		if host == "" {
			continue
		}
		if _, ok := seen[host]; ok {
			continue
		}
		seen[host] = struct{}{}
		if s.preGenerateCert(host) {
			enqueued++
		}
	}
	if enqueued > 0 && s.logger != nil {
		s.logger.Info("queued certificate prewarm", slog.Int("hosts", enqueued))
	}
	return enqueued
}

func (s *Server) SetRelayOptions(opts RelayOptions) {
	if opts.Policy == nil {
		if policy, ok := s.policy.Load().(*Policy); ok {
			opts.Policy = policy
		}
	}
	opts.HTTP3Enabled = s.http3Enabled
	_, port, err := net.SplitHostPort(s.httpServer.Addr)
	if err != nil || port == "" {
		port = "443"
	}
	opts.HTTP3Port = port
	s.relay.Store(opts)
}

func (s *Server) RelayOptions() RelayOptions {
	return s.relay.Load().(RelayOptions)
}

func (s *Server) SetDomainRules(rules *DomainRules) {
	if rules == nil {
		rules = NewDomainRules(nil)
	}
	s.rules.Store(rules)
	policy := &Policy{domains: rules, urls: &URLRules{}}
	s.policy.Store(policy)
	s.updateRelayPolicy(policy)
}

func (s *Server) SetPolicy(policy *Policy) {
	if policy == nil {
		policy, _ = NewPolicy(PolicyConfig{})
	}
	s.policy.Store(policy)
	s.updateRelayPolicy(policy)
}

func (s *Server) updateRelayPolicy(policy *Policy) {
	opts := s.relay.Load().(RelayOptions)
	opts.Policy = policy
	s.relay.Store(opts)
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
	var profileSems map[string]*semaphore.Weighted
	if current, ok := s.limiter.Load().(*connLimiter); ok && current != nil {
		profileSems = current.profileSems
	}
	s.limiter.Store(&connLimiter{
		globalSem:   semaphore.NewWeighted(int64(max)),
		profileSems: profileSems,
	})
}

func (s *Server) SetProfileMaxConnections(profiles []AccessProfile) {
	var globalSem *semaphore.Weighted
	if current, ok := s.limiter.Load().(*connLimiter); ok && current != nil {
		globalSem = current.globalSem
	}
	if globalSem == nil {
		globalSem = semaphore.NewWeighted(1024)
	}

	sems := make(map[string]*semaphore.Weighted)
	for _, p := range profiles {
		if p.MaxConns != nil && *p.MaxConns > 0 {
			sems[p.Name] = semaphore.NewWeighted(int64(*p.MaxConns))
		}
	}

	s.limiter.Store(&connLimiter{
		globalSem:   globalSem,
		profileSems: sems,
	})
}

func (s *Server) Serve(ctx context.Context) error {
	if s.upgrader == nil {
		var err error
		s.upgrader, err = NewUpgrader()
		if err != nil {
			return fmt.Errorf("create upgrader: %w", err)
		}
	}

	listeners, err := s.upgrader.Listen("tcp", s.httpServer.Addr, s.reusePort)
	if err != nil {
		return fmt.Errorf("listen proxy: %w", err)
	}

	defer func() {
		for _, ln := range listeners {
			ln.Close()
		}
	}()
	defer s.closeIdleUpstreamConnections()

	s.startCertWorkers(ctx)

	numListeners := len(listeners)
	errCh := make(chan error, numListeners)
	for _, ln := range listeners {
		go func(l net.Listener) {
			errCh <- s.httpServer.Serve(l)
		}(ln)
	}

	if s.logger != nil {
		s.logger.Info("proxy listening",
			slog.String("addr", listeners[0].Addr().String()),
			slog.Bool("reuseport", s.reusePort),
			slog.Int("listeners", numListeners),
		)
	}

	var h3Server *http3.Server
	var h3ErrCh chan error
	if s.http3Enabled && s.certs != nil {
		h3TLSConfig := &tls.Config{
			GetConfigForClient: func(info *tls.ClientHelloInfo) (*tls.Config, error) {
				name := info.ServerName
				if name == "" {
					name = "localhost"
				}
				cert, err := s.certs.Get(name)
				if err != nil {
					return nil, err
				}
				return &tls.Config{
					Certificates: []tls.Certificate{*cert},
					NextProtos:   []string{"h3"},
				}, nil
			},
			MinVersion:         tls.VersionTLS13,
			ClientSessionCache: downstreamSessionCache,
		}

		h3Server = &http3.Server{
			Addr:      s.httpServer.Addr,
			Handler:   s,
			TLSConfig: h3TLSConfig,
		}

		udpAddr, err := net.ResolveUDPAddr("udp", s.httpServer.Addr)
		if err != nil {
			return fmt.Errorf("resolve udp addr: %w", err)
		}

		udpConn, err := net.ListenUDP("udp", udpAddr)
		if err != nil {
			return fmt.Errorf("listen udp proxy: %w", err)
		}
		defer udpConn.Close()

		h3ErrCh = make(chan error, 1)
		go func() {
			if s.logger != nil {
				s.logger.Info("http3 downstream listener started", slog.String("addr", udpAddr.String()))
			}
			err := h3Server.Serve(udpConn)
			if err != nil && errors.Is(err, http.ErrServerClosed) {
				h3ErrCh <- nil
			} else {
				h3ErrCh <- err
			}
		}()
	}

	if err := s.upgrader.Ready(); err != nil {
		return fmt.Errorf("upgrader ready: %w", err)
	}

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		if h3Server != nil {
			if err := h3Server.Close(); err != nil && s.logger != nil {
				s.logger.Error("close http3 server failed", slog.Any("error", err))
			}
		}

		if err := s.httpServer.Shutdown(shutdownCtx); err != nil {
			return fmt.Errorf("shutdown proxy: %w", err)
		}

		// Graceful drain of active hijacked connections
		s.drainHijacked(30 * time.Second)

		// wait for all listeners to finish
		for i := 0; i < numListeners; i++ {
			err := <-errCh
			if err != nil && !errors.Is(err, http.ErrServerClosed) {
				return err
			}
		}

		if h3ErrCh != nil {
			err := <-h3ErrCh
			if err != nil {
				return err
			}
		}

		return ctx.Err()

	case err := <-errCh:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err

	case err := <-h3ErrCh:
		if err != nil {
			return err
		}
		return nil
	}
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ActiveConnections.Inc()
	defer ActiveConnections.Dec()

	if s.http3Enabled {
		_, port, err := net.SplitHostPort(s.httpServer.Addr)
		if err != nil || port == "" {
			port = "443"
		}
		w.Header().Set("Alt-Svc", fmt.Sprintf(`h3=":%s"; ma=86400`, port))
	}

	profile, allowed := s.clientProfile(r.RemoteAddr)
	if !allowed {
		writeBlockPage(w, http.StatusForbidden, "Client access denied", "This client is not assigned to an allowed LucidGate access profile.")
		return
	}
	if !s.scheduleAllowed(profile) {
		writeBlockPage(w, http.StatusForbidden, "Access outside allowed schedule", "The active access profile is outside its configured time window.")
		return
	}

	// Fail Fast Rate Limiter Check
	if limit, burst, hasLimit := s.profileRateLimit(profile); hasLimit {
		hostIP, _, _ := net.SplitHostPort(r.RemoteAddr)
		if hostIP == "" {
			hostIP = r.RemoteAddr
		}
		limiter := s.rateLimiter.getOrCreate(hostIP, limit, burst)
		if !limiter.Allow() {
			ConnectionsRejected.WithLabelValues("rate_limit").Inc()
			if s.logger != nil {
				s.logger.Warn("client rate limit exceeded",
					slog.String("ip", hostIP),
					slog.String("profile", profile),
					slog.Float64("limit", limit),
					slog.Int("burst", burst),
				)
			}
			writeBlockPage(w, http.StatusTooManyRequests, "Too many requests", "This client has exceeded the allowed request rate.")
			return
		}
	}

	if strings.HasPrefix(r.Proto, "HTTP/3") {
		host := r.Host
		if host == "" && r.URL != nil {
			host = r.URL.Host
		}
		if splitHost, _, err := net.SplitHostPort(host); err == nil {
			host = splitHost
		}
		if host == "" {
			http.Error(w, "missing host in http3 request", http.StatusBadRequest)
			return
		}

		dec := s.policyBlocked(host, r, "https")
		if dec.Blocked {
			RuleHits.WithLabelValues("default", dec.MatchType, "block").Inc()
			opts := s.relay.Load().(RelayOptions)
			logExchangeBlocked(s.logger, r, dec, opts)
			writeBlockPage(w, http.StatusForbidden, "Access denied", "LucidGate blocked this destination by domain policy.")
			return
		}

		permit, ok, reason := s.acquireConnForProfile(r.Context(), profile)
		if !ok {
			ConnectionsRejected.WithLabelValues(reason).Inc()
			writeBlockPage(w, http.StatusServiceUnavailable, "Connection limit exceeded", "LucidGate is at the configured concurrent connection limit.")
			return
		}
		defer s.releaseConn(permit)

		address := net.JoinHostPort(host, "443")
		s.handleHTTPSStream(w, r, host, address)
		return
	}

	if r.Method != http.MethodConnect {
		s.handlePlainHTTP(w, r, profile)
		return
	}
	host, err := connectHostname(r)
	if err != nil {
		http.Error(w, "bad connect host", http.StatusBadRequest)
		return
	}
	dec := s.policyBlocked(host, nil, "https")
	if dec.Blocked {
		RuleHits.WithLabelValues("default", dec.MatchType, "block").Inc()
		opts := s.relay.Load().(RelayOptions)
		logExchangeBlocked(s.logger, r, dec, opts)
		writeBlockPage(w, http.StatusForbidden, "Access denied", "LucidGate blocked this destination by domain policy.")
		return
	}
	if s.shouldBypassMITM(host) {
		permit, ok, reason := s.acquireConnForProfile(r.Context(), profile)
		if !ok {
			ConnectionsRejected.WithLabelValues(reason).Inc()
			writeBlockPage(w, http.StatusServiceUnavailable, "Connection limit exceeded", "LucidGate is at the configured concurrent connection limit.")
			return
		}
		defer s.releaseConn(permit)
		s.handleBypassMITM(w, r, host)
		return
	}

	s.preGenerateCert(host)
	permit, ok, reason := s.acquireConnForProfile(r.Context(), profile)
	if !ok {
		ConnectionsRejected.WithLabelValues(reason).Inc()
		writeBlockPage(w, http.StatusServiceUnavailable, "Connection limit exceeded", "LucidGate is at the configured concurrent connection limit.")
		return
	}
	defer s.releaseConn(permit)
	s.handleHTTPS(w, r)
}

func (s *Server) handlePlainHTTP(w http.ResponseWriter, r *http.Request, profile string) {
	ctx, span := GlobalTracer.Start(r.Context(), "Exchange")
	defer span.End()
	r = r.WithContext(ctx)

	span.SetAttributes(
		attribute.String("http.method", r.Method),
		attribute.String("http.url", r.URL.String()),
		attribute.String("http.proto", r.Proto),
		attribute.String("net.peer.ip", r.RemoteAddr),
	)

	opts := s.relay.Load().(RelayOptions)
	host, address, err := plainHTTPDestination(r)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		http.Error(w, "bad proxy request", http.StatusBadRequest)
		return
	}
	isWS := isWebSocketUpgrade(r)
	dec := s.policyBlocked(host, r, "http")
	if dec.Blocked {
		RuleHits.WithLabelValues("default", dec.MatchType, "block").Inc()
		logExchangeBlocked(s.logger, r, dec, opts)
		if isWS {
			WebSocketSessions.WithLabelValues("denied").Inc()
		}
		writeBlockPage(w, http.StatusForbidden, "Access denied", "LucidGate blocked this destination by domain policy.")
		return
	}
	if dec.BypassFilters {
		r = r.WithContext(context.WithValue(r.Context(), BypassFiltersCtxKey{}, true))
	}
	permit, ok, reason := s.acquireConnForProfile(r.Context(), profile)
	if !ok {
		ConnectionsRejected.WithLabelValues(reason).Inc()
		writeBlockPage(w, http.StatusServiceUnavailable, "Connection limit exceeded", "LucidGate is at the configured concurrent connection limit.")
		return
	}
	defer s.releaseConn(permit)

	lease, err := s.acquirePlainHTTP(r.Context(), address, host, opts.IOTimeout)
	if err != nil {
		if decision, ok := policyDecisionFromError(err); ok {
			RuleHits.WithLabelValues("default", decision.MatchType, "block").Inc()
			logExchangeBlocked(s.logger, r, decision, opts)
			if isWS {
				WebSocketSessions.WithLabelValues("denied").Inc()
			}
			writeBlockPage(w, http.StatusForbidden, "Access denied", "LucidGate blocked this destination by IP policy.")
			return
		}
		if s.logger != nil {
			s.logger.Error("dial http upstream", slog.String("address", address), slog.String("host", host), slog.Any("error", err))
		}
		if errors.Is(err, gobreaker.ErrOpenState) {
			writeBlockPage(w, http.StatusBadGateway, "Service Suspended", "LucidGate circuit breaker is open. The upstream host is currently unreachable.")
		} else {
			writeBlockPage(w, http.StatusBadGateway, "Upstream unavailable", "LucidGate could not open a connection to the requested HTTP upstream.")
		}
		return
	}
	upstreamConn := lease.conn
	upstreamReader := lease.reader
	reusable := false
	defer func() {
		lease.release(reusable)
	}()

	if isWS {
		hijacker, ok := w.(http.Hijacker)
		if !ok {
			closeRequestBody(r)
			WebSocketSessions.WithLabelValues("error").Inc()
			writeBlockPage(w, http.StatusInternalServerError, "WebSocket unavailable", "LucidGate could not take over the client connection.")
			return
		}
		localConn, clientRW, err := hijacker.Hijack()
		if err != nil {
			closeRequestBody(r)
			WebSocketSessions.WithLabelValues("error").Inc()
			if s.logger != nil {
				s.logger.Error("hijack websocket client", slog.String("address", address), slog.String("host", host), slog.Any("error", err))
			}
			return
		}
		s.trackConn(localConn)
		defer s.untrackConn(localConn)
		defer localConn.Close()
		if clientRW.Reader.Buffered() > 0 && s.logger != nil {
			s.logger.Warn("websocket client sent early buffered bytes before 101", slog.String("address", address), slog.String("host", host), slog.Int("buffered", clientRW.Reader.Buffered()))
		}
		wsIdle := opts.WSIdleTimeout
		if wsIdle <= 0 {
			wsIdle = DefaultWebSocketIdleTimeout
		}
		if err := relayWebSocket(localConn, upstreamConn, upstreamReader, r, opts.IOTimeout, wsIdle); err != nil && s.logger != nil {
			s.logger.Error("relay websocket", slog.String("address", address), slog.String("host", host), slog.Any("error", err))
		}
		closeRequestBody(r)
		reusable = false
		return
	}

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
	r.Close = false
	reqCap := newBodyCapture(r.Body != nil, opts)
	r.Body = readCloserWithIdleDeadline(r.Body, httpReadDeadlineRefresher(w, opts.IOTimeout))
	upstreamWriter := writerWithIdleDeadline(upstreamConn, connWriteDeadlineRefresher(upstreamConn, opts.IOTimeout))

	var reqDumpFunc func(action string)
	if opts.DumpDir != "" {
		reqDumpFunc = func(action string) {
			data, trunc, skipped := reqCap.dumpPayload()
			emitDump(opts, "req", xid, r, nil, data, trunc, skipped, action, s.logger)
		}
	}
	var reqDumped bool
	safeReqDump := func(action string) {
		if reqDumpFunc != nil && !reqDumped {
			reqDumpFunc(action)
			reqDumped = true
		}
	}

	_, reqSpan := GlobalTracer.Start(r.Context(), "Request Processing")
	reqBytes, reqDec, err := writeRequestStreaming(upstreamWriter, r, reqCap, opts, s.logger)
	if err != nil {
		reqSpan.RecordError(err)
		reqSpan.SetStatus(codes.Error, err.Error())
	}
	reqSpan.End()
	closeRequestBody(r)
	if err != nil {
		if !opts.DumpOnPolicyHit || reqDec.Blocked {
			safeReqDump(determineAction(r, nil, reqDec, PolicyDecision{}, opts.Policy))
		}
		if s.logger != nil {
			s.logger.Error("write http upstream request", slog.String("address", address), slog.String("host", host), slog.Any("error", err))
		}
		return
	}
	if reqDec.Blocked {
		RuleHits.WithLabelValues("default", reqDec.MatchType, "block").Inc()
		logExchangeBlocked(s.logger, r, reqDec, opts)
		if !opts.DumpOnPolicyHit || reqDec.Blocked {
			safeReqDump("blocked")
		}
		detail := "LucidGate blocked this request by content policy."
		if reqDec.MatchType == "exfiltration preventer" {
			detail = "LucidGate blocked this request to prevent sensitive data exfiltration."
		}
		writeBlockPage(w, http.StatusForbidden, "Access denied", detail)
		return
	}

	if err := setReadDeadline(upstreamConn, opts.IOTimeout); err != nil {
		if !opts.DumpOnPolicyHit {
			safeReqDump("allowed")
		}
		if s.logger != nil {
			s.logger.Error("deadline http upstream read", slog.String("address", address), slog.String("host", host), slog.Any("error", err))
		}
		writeBlockPage(w, http.StatusBadGateway, "Upstream unavailable", "LucidGate could not read from the upstream HTTP connection.")
		return
	}
	resp, err := http.ReadResponse(upstreamReader, r)
	if err != nil {
		if !opts.DumpOnPolicyHit {
			safeReqDump("allowed")
		}
		if s.logger != nil {
			s.logger.Error("read http upstream response", slog.String("address", address), slog.String("host", host), slog.Any("error", err))
		}
		writeBlockPage(w, http.StatusBadGateway, "Upstream unavailable", "LucidGate received an invalid response from the upstream HTTP connection.")
		return
	}
	defer closeResponseBody(resp)
	if stripHTTP3Advertising(resp.Header) {
		AltSvcStripped.Inc()
	}
	if s.http3Enabled {
		_, port, err := net.SplitHostPort(s.httpServer.Addr)
		if err != nil || port == "" {
			port = "443"
		}
		resp.Header.Set("Alt-Svc", fmt.Sprintf(`h3=":%s"; ma=86400`, port))
	}
	decResp := s.policyResponseBlocked(resp, "http")
	if decResp.Blocked {
		RuleHits.WithLabelValues("default", decResp.MatchType, "block").Inc()
		logExchangeBlocked(s.logger, r, decResp, opts)
		if !opts.DumpOnPolicyHit || decResp.Blocked {
			safeReqDump("blocked")
		}
		writeBlockPage(w, http.StatusForbidden, "Access denied", "LucidGate blocked this download by file policy.")
		return
	}

	if err := setHTTPWriteDeadline(w, opts.IOTimeout); err != nil && s.logger != nil {
		s.logger.Error("deadline http client write", slog.String("address", address), slog.String("host", host), slog.Any("error", err))
	}
	respCap := newBodyCapture(resp.Body != nil, opts)
	resp.Body = readCloserWithIdleDeadline(resp.Body, connReadDeadlineRefresher(upstreamConn, opts.IOTimeout))
	clientWriter := responseWriterWithIdleDeadline(w, httpWriteDeadlineRefresher(w, opts.IOTimeout))
	_, respSpan := GlobalTracer.Start(r.Context(), "Response Processing")
	respBytes, dec, err := writeResponseStreamingHTTP(clientWriter, resp, respCap, opts.Filter)
	if err != nil {
		respSpan.RecordError(err)
		respSpan.SetStatus(codes.Error, err.Error())
	}
	respSpan.End()

	policyHit := isPolicyHit(r, resp, reqDec, dec, opts.Policy)

	if dec.Blocked {
		RuleHits.WithLabelValues("default", dec.MatchType, "block").Inc()
		logExchangeBlocked(s.logger, r, dec, opts)
	} else {
		logExchange(s.logger, r, resp, reqBytes, respBytes, opts)
	}
	if !opts.DumpOnPolicyHit || policyHit {
		action := determineAction(r, resp, reqDec, dec, opts.Policy)
		safeReqDump(action)
		if opts.DumpDir != "" {
			data, trunc, skipped := respCap.dumpPayload()
			emitDump(opts, "resp", xid, r, resp, data, trunc, skipped, action, s.logger)
		}
	}
	if err != nil && s.logger != nil {
		s.logger.Error("write http client response", slog.String("address", address), slog.String("host", host), slog.Any("error", err))
	}
	reusable = err == nil && !dec.Blocked && !resp.Close && upstreamReader.Buffered() == 0
}

func (s *Server) dialPlainHTTP(ctx context.Context, address string, timeout time.Duration) (net.Conn, error) {
	dialer := s.httpDialer
	if dialer == nil {
		dialer = &net.Dialer{Timeout: timeout, KeepAlive: 30 * time.Second}
	}
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		host = address
	}
	dialAddr, err := s.resolveDialAddress(ctx, address)
	if err != nil {
		return nil, err
	}
	if s.breakers == nil {
		return dialer.DialContext(ctx, "tcp", dialAddr)
	}
	return s.breakers.Execute(host, func() (net.Conn, error) {
		return dialer.DialContext(ctx, "tcp", dialAddr)
	})
}

func (s *Server) acquirePlainHTTP(ctx context.Context, address, host string, timeout time.Duration) (*upstreamConnLease, error) {
	key := upstreamPoolKey{
		scheme:     "http",
		address:    address,
		serverName: host,
		alpn:       "http/1.1",
		specID:     "plain",
	}
	return s.acquireUpstream(ctx, key, func(ctx context.Context) (net.Conn, error) {
		return s.dialPlainHTTP(ctx, address, timeout)
	})
}

func (s *Server) domainBlocked(host string) bool {
	rules := s.rules.Load().(*DomainRules)
	return rules.Blocked(host)
}

func (s *Server) policyBlocked(host string, req *http.Request, scheme string) PolicyDecision {
	policy := s.policy.Load().(*Policy)
	return policy.EvaluateRequest(host, req, scheme)
}

func (s *Server) policyResponseBlocked(resp *http.Response, scheme string) PolicyDecision {
	policy := s.policy.Load().(*Policy)
	return policy.EvaluateResponse(resp, scheme)
}

func (s *Server) resolveDialAddress(ctx context.Context, address string) (string, error) {
	policy, _ := s.policy.Load().(*Policy)
	forceResolve := policy != nil && policy.RequiresResolvedSiteIP()

	dialAddr := address
	resolvedHost := addressHost(address)
	if s.dnsResolver != nil {
		resolved, host, err := s.dnsResolver.ResolveAddrForPolicy(ctx, address, forceResolve)
		if err != nil {
			if forceResolve {
				return "", err
			}
		} else {
			dialAddr = resolved
			resolvedHost = host
		}
	}

	if policy != nil {
		if decision := policy.EvaluateResolvedDestinationIP(resolvedHost); decision.Blocked {
			return "", &policyBlockError{decision: decision}
		}
	}
	return dialAddr, nil
}

func addressHost(address string) string {
	host, _, err := net.SplitHostPort(address)
	if err == nil {
		return host
	}
	return strings.TrimPrefix(strings.TrimSuffix(address, "]"), "[")
}

func (s *Server) clientProfile(remoteAddr string) (string, bool) {
	rules := s.access.Load().(*AccessRules)
	return rules.ProfileForRemoteAddr(remoteAddr)
}

func (s *Server) scheduleAllowed(profile string) bool {
	rules := s.schedules.Load().(*ScheduleRules)
	return rules.Allowed(profile, s.now())
}

func (s *Server) acquireConn(ctx context.Context) (*connLimiterPermit, bool) {
	permit, ok, _ := s.acquireConnForProfile(ctx, "")
	return permit, ok
}

func (s *Server) acquireConnForProfile(ctx context.Context, profile string) (*connLimiterPermit, bool, string) {
	limiter := s.limiter.Load().(*connLimiter)
	timeout := s.WaitTimeout()

	var profSem *semaphore.Weighted
	if profile != "" && limiter.profileSems != nil {
		profSem = limiter.profileSems[profile]
	}

	var acquiredProfile bool

	if timeout <= 0 {
		if profSem != nil {
			if !profSem.TryAcquire(1) {
				return nil, false, "profile_max_connections"
			}
			acquiredProfile = true
		}
		if limiter.globalSem != nil {
			if !limiter.globalSem.TryAcquire(1) {
				if acquiredProfile {
					profSem.Release(1)
				}
				return nil, false, "max_connections"
			}
		}
		return &connLimiterPermit{limiter: limiter, profile: profile, hasProfile: acquiredProfile}, true, ""
	}

	waitCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	if profSem != nil {
		err := profSem.Acquire(waitCtx, 1)
		if err != nil {
			return nil, false, "profile_max_connections"
		}
		acquiredProfile = true
	}

	if limiter.globalSem != nil {
		err := limiter.globalSem.Acquire(waitCtx, 1)
		if err != nil {
			if acquiredProfile {
				profSem.Release(1)
			}
			return nil, false, "max_connections"
		}
	}

	return &connLimiterPermit{limiter: limiter, profile: profile, hasProfile: acquiredProfile}, true, ""
}

func (s *Server) releaseConn(permit *connLimiterPermit) {
	if permit == nil {
		return
	}
	if permit.limiter.globalSem != nil {
		permit.limiter.globalSem.Release(1)
	}
	if permit.hasProfile && permit.limiter.profileSems != nil {
		if profSem := permit.limiter.profileSems[permit.profile]; profSem != nil {
			profSem.Release(1)
		}
	}
}

func (s *Server) profileRateLimit(profile string) (float64, int, bool) {
	rules, ok := s.access.Load().(*AccessRules)
	if !ok || rules == nil {
		return 0, 0, false
	}
	_, rateLimit, rateBurst, exists := rules.ProfileLimits(profile)
	if !exists || rateLimit == nil || rateBurst == nil {
		return 0, 0, false
	}
	return *rateLimit, *rateBurst, true
}

func (s *Server) ResetIPRateLimiter() {
	if s.rateLimiter != nil {
		s.rateLimiter.reset()
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

func (s *Server) handleBypassMITM(w http.ResponseWriter, r *http.Request, host string) {
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijacking not supported", http.StatusInternalServerError)
		return
	}

	conn, bufrw, err := hijacker.Hijack()
	if err != nil {
		if s.logger != nil {
			s.logger.Error("hijack for bypass failed", slog.String("host", host), slog.Any("error", err))
		}
		return
	}
	s.trackConn(conn)
	defer s.untrackConn(conn)
	defer conn.Close()

	if err := conn.SetDeadline(time.Now().Add(s.handshake)); err != nil && s.logger != nil {
		s.logger.Error("set bypass deadline failed", slog.String("host", host), slog.Any("error", err))
	}
	if bufrw.Reader.Buffered() > 0 && s.logger != nil {
		s.logger.Warn("discarding buffered client bytes before bypass", slog.String("host", host), slog.Int("bytes", bufrw.Reader.Buffered()))
	}

	address := connectAddress(r)
	upstreamConn, err := s.dialPlainHTTP(r.Context(), address, 10*time.Second)
	if err != nil {
		if decision, ok := policyDecisionFromError(err); ok {
			RuleHits.WithLabelValues("default", decision.MatchType, "block").Inc()
			opts := s.relay.Load().(RelayOptions)
			logExchangeBlocked(s.logger, r, decision, opts)
			_, _ = bufrw.WriteString("HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
			_ = bufrw.Flush()
			return
		}
		if s.logger != nil {
			s.logger.Error("bypass dial upstream", slog.String("address", address), slog.String("host", host), slog.Any("error", err))
		}
		_, _ = bufrw.WriteString("HTTP/1.1 502 Bad Gateway\r\n\r\n")
		_ = bufrw.Flush()
		return
	}
	defer upstreamConn.Close()

	if _, err := bufrw.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		if s.logger != nil {
			s.logger.Error("write bypass connect response", slog.String("host", host), slog.Any("error", err))
		}
		return
	}
	if err := bufrw.Flush(); err != nil && s.logger != nil {
		s.logger.Error("flush bypass connect response", slog.String("host", host), slog.Any("error", err))
	}

	if err := conn.SetDeadline(time.Time{}); err != nil && s.logger != nil {
		s.logger.Error("clear bypass local deadline", slog.String("host", host), slog.Any("error", err))
	}

	errChan := make(chan error, 2)
	go func() {
		if bufrw.Reader.Buffered() > 0 {
			_, err := io.CopyN(upstreamConn, bufrw.Reader, int64(bufrw.Reader.Buffered()))
			if err != nil {
				_ = upstreamConn.SetDeadline(time.Now())
				errChan <- err
				return
			}
		}
		tcpConn, ok1 := conn.(*net.TCPConn)
		tcpUpstream, ok2 := upstreamConn.(*net.TCPConn)
		var err error
		if ok1 && ok2 {
			_, err = io.Copy(tcpUpstream, tcpConn)
		} else {
			bufRef := relayBufferPool.Get().(*[]byte)
			buf := *bufRef
			defer func() {
				relayBufferPool.Put(bufRef)
			}()
			_, err = io.CopyBuffer(upstreamConn, conn, buf)
		}
		_ = upstreamConn.SetDeadline(time.Now())
		errChan <- err
	}()

	go func() {
		tcpConn, ok1 := conn.(*net.TCPConn)
		tcpUpstream, ok2 := upstreamConn.(*net.TCPConn)
		var err error
		if ok1 && ok2 {
			_, err = io.Copy(tcpConn, tcpUpstream)
		} else {
			bufRef := relayBufferPool.Get().(*[]byte)
			buf := *bufRef
			defer func() {
				relayBufferPool.Put(bufRef)
			}()
			_, err = io.CopyBuffer(conn, upstreamConn, buf)
		}
		_ = conn.SetDeadline(time.Now())
		errChan <- err
	}()

	<-errChan
	if s.logger != nil {
		s.logger.Info("bypass session complete", slog.String("address", address), slog.String("host", host))
	}
}

func (s *Server) roundTripH2(req *http.Request, host string) (*http.Response, error) {
	h := req.URL.Host
	if h == "" {
		h = host
	}
	if val, ok := s.h2Conns.Load(h); ok {
		if cc, ok := val.(*http2.ClientConn); ok && cc.CanTakeNewRequest() {
			return cc.RoundTrip(req)
		}
	}
	return s.h2Transport.RoundTrip(req)
}

func (s *Server) acquireHTTPSUpstream(ctx context.Context, address, host string) (*upstreamConnLease, error) {
	key := upstreamPoolKey{
		scheme:     "https",
		address:    address,
		serverName: host,
		alpn:       "h2,http/1.1",
		specID:     "utls-firefox-120",
	}
	dialer := s.h2Upstream
	if dialer == nil {
		dialer = s.upstream
	}
	if dialer == nil {
		return nil, fmt.Errorf("no upstream dialer configured")
	}
	lease, err := s.acquireUpstream(ctx, key, func(cctx context.Context) (net.Conn, error) {
		cctx, dialSpan := GlobalTracer.Start(cctx, "Exchange Upstream Dial")
		defer dialSpan.End()

		dialAddr, err := s.resolveDialAddress(cctx, address)
		if err != nil {
			dialSpan.RecordError(err)
			dialSpan.SetStatus(codes.Error, err.Error())
			return nil, err
		}
		if s.dnsResolver != nil {
			_, dnsSpan := GlobalTracer.Start(cctx, "DNS Lookup")
			dnsSpan.SetAttributes(
				attribute.String("net.peer.name", address),
				attribute.String("net.peer.ip", dialAddr),
			)
			dnsSpan.End()
		}

		dialSpan.SetAttributes(
			attribute.String("net.peer.name", host),
			attribute.String("net.peer.ip", dialAddr),
		)

		var conn net.Conn
		var dialErr error
		if s.breakers == nil {
			conn, dialErr = dialer.Dial(cctx, dialAddr, host)
		} else {
			conn, dialErr = s.breakers.Execute(host, func() (net.Conn, error) {
				return dialer.Dial(cctx, dialAddr, host)
			})
		}

		if dialErr != nil {
			dialSpan.RecordError(dialErr)
			dialSpan.SetStatus(codes.Error, dialErr.Error())
		}
		return conn, dialErr
	})
	if err != nil {
		return nil, err
	}

	if uconn, ok := lease.conn.(*utls.UConn); ok {
		alpn := uconn.ConnectionState().NegotiatedProtocol
		if alpn == "h2" {
			s.h2Hosts.Store(host, true)
			if cc, err := s.h2Transport.NewClientConn(uconn); err == nil {
				s.h2Conns.Store(host, cc)
				return nil, errNegotiatedH2
			} else if s.logger != nil {
				s.logger.Error("h2 NewClientConn failed for uconn", slog.String("host", host), slog.Any("error", err))
			}
		} else {
			s.h2Hosts.Store(host, false)
		}
	} else if tlsConnParsed, ok := lease.conn.(*tls.Conn); ok {
		alpn := tlsConnParsed.ConnectionState().NegotiatedProtocol
		if alpn == "h2" {
			s.h2Hosts.Store(host, true)
			if cc, err := s.h2Transport.NewClientConn(tlsConnParsed); err == nil {
				s.h2Conns.Store(host, cc)
				return nil, errNegotiatedH2
			} else if s.logger != nil {
				s.logger.Error("h2 NewClientConn failed for tlsConn", slog.String("host", host), slog.Any("error", err))
			}
		} else {
			s.h2Hosts.Store(host, false)
		}
	}

	return lease, nil
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
	s.trackConn(conn)
	defer s.untrackConn(conn)
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
	tlsConn := tls.Server(conn, &tls.Config{
		GetCertificate: func(info *tls.ClientHelloInfo) (*tls.Certificate, error) {
			name := info.ServerName
			if name == "" {
				name = host
			}
			return s.certs.Get(name)
		},
		MinVersion:         tls.VersionTLS12,
		NextProtos:         []string{"h2", "http/1.1"},
		ClientSessionCache: downstreamSessionCache,
	})
	_, handshakeSpan := GlobalTracer.Start(r.Context(), "TLS Handshake Downstream")
	handshakeStart := time.Now()
	err = tlsConn.Handshake()
	if err != nil {
		handshakeSpan.RecordError(err)
		handshakeSpan.SetStatus(codes.Error, err.Error())
	} else {
		handshakeSpan.SetAttributes(
			attribute.String("tls.cipher", tls.CipherSuiteName(tlsConn.ConnectionState().CipherSuite)),
			attribute.String("tls.version", tlsVersionToString(tlsConn.ConnectionState().Version)),
		)
	}
	handshakeSpan.End()
	if err != nil {
		if s.logger != nil {
			s.logger.Error("local tls handshake", slog.String("host", host), slog.Any("error", err))
		}
		return
	}
	TLSHandshakeDuration.WithLabelValues("downstream").Observe(time.Since(handshakeStart).Seconds())
	if err := conn.SetDeadline(time.Time{}); err != nil && s.logger != nil {
		s.logger.Error("clear deadline", slog.String("host", host), slog.Any("error", err))
	}
	if s.upstream == nil {
		return
	}

	address := connectAddress(r)
	opts := s.relay.Load().(RelayOptions)

	if tlsConn.ConnectionState().NegotiatedProtocol == http2.NextProtoTLS {
		h2Server := &http2.Server{
			IdleTimeout:          opts.IOTimeout,
			ReadIdleTimeout:      opts.IOTimeout,
			PingTimeout:          opts.IOTimeout,
			WriteByteTimeout:     opts.IOTimeout,
			MaxConcurrentStreams: 100,
		}
		h2Server.ServeConn(tlsConn, &http2.ServeConnOpts{
			Handler: http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				s.handleHTTPSStream(w, req, host, address)
			}),
		})
		return
	}

	opts.H2Hosts = &s.h2Hosts
	opts.RoundTripH2 = func(req *http.Request) (*http.Response, error) {
		return s.roundTripH2(req, host)
	}
	if err := relayHTTPLease(tlsConn, func() (*upstreamConnLease, error) {
		lease, err := s.acquireHTTPSUpstream(r.Context(), address, host)
		if err != nil {
			if s.logger != nil {
				s.logger.Error("dial upstream", slog.String("address", address), slog.String("host", host), slog.Any("error", err))
			}
			return nil, err
		}
		return lease, nil
	}, s.logger, opts); err != nil {
		if strings.Contains(err.Error(), "dial upstream") {
			writeTLSBadGateway(tlsConn)
		}
		if s.logger != nil {
			if benign, ok := err.(interface{ Benign() bool }); ok && benign.Benign() {
				s.logger.Info("relay connection closed", slog.String("address", address), slog.String("host", host), slog.Any("error", err))
			} else {
				s.logger.Error("relay failed", slog.String("address", address), slog.String("host", host), slog.Any("error", err))
			}
		}
	}
}

func (s *Server) handleHTTPSStream(w http.ResponseWriter, r *http.Request, connectHost, address string) {
	ctx, span := GlobalTracer.Start(r.Context(), "Exchange")
	defer span.End()
	r = r.WithContext(ctx)

	span.SetAttributes(
		attribute.String("http.method", r.Method),
		attribute.String("http.url", r.URL.String()),
		attribute.String("http.proto", r.Proto),
		attribute.String("net.peer.ip", r.RemoteAddr),
	)

	opts := s.relay.Load().(RelayOptions)
	xid := newExchangeID()
	host := r.Host
	if host == "" {
		host = connectHost
	}
	if splitHost, _, err := net.SplitHostPort(host); err == nil {
		host = splitHost
	}

	upReq := r.Clone(r.Context())
	upReq.URL.Scheme = "https"
	if upReq.URL.Host == "" {
		upReq.URL.Host = r.Host
	}
	if upReq.URL.Host == "" {
		upReq.URL.Host = connectHost
	}
	upReq.RequestURI = ""
	upReq.Close = false
	SanitizeHeaders(upReq)

	if opts.Policy != nil {
		if decision := opts.Policy.EvaluateRequest(host, upReq, "https"); decision.Blocked {
			closeRequestBody(upReq)
			RuleHits.WithLabelValues("default", decision.MatchType, "block").Inc()
			logExchangeBlocked(s.logger, upReq, decision, opts)
			writeBlockPage(w, http.StatusForbidden, "Access denied", "LucidGate blocked this request by URL policy.")
			return
		}
	}

	if isHostH2(&s.h2Hosts, host) {
		s.handleHTTPSStreamH2Upstream(w, upReq, host, xid, opts)
		return
	}

	lease, err := s.acquireHTTPSUpstream(r.Context(), address, host)
	if err != nil {
		if errors.Is(err, errNegotiatedH2) {
			s.handleHTTPSStreamH2Upstream(w, upReq, host, xid, opts)
			return
		}
		if decision, ok := policyDecisionFromError(err); ok {
			closeRequestBody(upReq)
			RuleHits.WithLabelValues("default", decision.MatchType, "block").Inc()
			logExchangeBlocked(s.logger, upReq, decision, opts)
			writeBlockPage(w, http.StatusForbidden, "Access denied", "LucidGate blocked this destination by IP policy.")
			return
		}
		closeRequestBody(upReq)
		if s.logger != nil {
			s.logger.Error("dial h2 downstream upstream", slog.String("address", address), slog.String("host", host), slog.Any("error", err))
		}
		writeBlockPage(w, http.StatusBadGateway, "Upstream unavailable", "LucidGate could not open a connection to the requested HTTPS upstream.")
		return
	}
	reusable := false
	defer func() {
		lease.release(reusable)
	}()

	if err := setWriteDeadline(lease.conn, opts.IOTimeout); err != nil {
		closeRequestBody(upReq)
		writeBlockPage(w, http.StatusBadGateway, "Upstream unavailable", "LucidGate could not prepare the upstream HTTPS connection.")
		return
	}
	upReq.Body = readCloserWithIdleDeadline(upReq.Body, httpReadDeadlineRefresher(w, opts.IOTimeout))
	upstreamWriter := writerWithIdleDeadline(lease.conn, connWriteDeadlineRefresher(lease.conn, opts.IOTimeout))
	reqCap := newBodyCapture(upReq.Body != nil, opts)

	var reqDumpFunc func(action string)
	if opts.DumpDir != "" {
		reqDumpFunc = func(action string) {
			data, trunc, skipped := reqCap.dumpPayload()
			emitDump(opts, "req", xid, upReq, nil, data, trunc, skipped, action, s.logger)
		}
	}
	var reqDumped bool
	safeReqDump := func(action string) {
		if reqDumpFunc != nil && !reqDumped {
			reqDumpFunc(action)
			reqDumped = true
		}
	}

	_, reqSpan := GlobalTracer.Start(r.Context(), "Request Processing")
	reqBytes, reqDec, err := writeRequestStreaming(upstreamWriter, upReq, reqCap, opts, s.logger)
	if err != nil {
		reqSpan.RecordError(err)
		reqSpan.SetStatus(codes.Error, err.Error())
	}
	reqSpan.End()
	closeRequestBody(upReq)
	if err != nil {
		if !opts.DumpOnPolicyHit || reqDec.Blocked {
			safeReqDump(determineAction(upReq, nil, reqDec, PolicyDecision{}, opts.Policy))
		}
		if s.logger != nil {
			s.logger.Error("write h2 downstream upstream request", slog.String("address", address), slog.String("host", host), slog.Any("error", err))
		}
		return
	}
	if reqDec.Blocked {
		RuleHits.WithLabelValues("default", reqDec.MatchType, "block").Inc()
		logExchangeBlocked(s.logger, upReq, reqDec, opts)
		if !opts.DumpOnPolicyHit || reqDec.Blocked {
			safeReqDump("blocked")
		}
		detail := "LucidGate blocked this request by content policy."
		if reqDec.MatchType == "exfiltration preventer" {
			detail = "LucidGate blocked this request to prevent sensitive data exfiltration."
		}
		writeBlockPage(w, http.StatusForbidden, "Access denied", detail)
		return
	}

	if err := setReadDeadline(lease.conn, opts.IOTimeout); err != nil {
		if !opts.DumpOnPolicyHit {
			safeReqDump("allowed")
		}
		writeBlockPage(w, http.StatusBadGateway, "Upstream unavailable", "LucidGate could not read from the upstream HTTPS connection.")
		return
	}
	resp, err := http.ReadResponse(lease.reader, upReq)
	if err != nil {
		if !opts.DumpOnPolicyHit {
			safeReqDump("allowed")
		}
		if s.logger != nil {
			s.logger.Error("read h2 downstream upstream response", slog.String("address", address), slog.String("host", host), slog.Any("error", err))
		}
		writeBlockPage(w, http.StatusBadGateway, "Upstream unavailable", "LucidGate received an invalid response from the upstream HTTPS connection.")
		return
	}
	defer closeResponseBody(resp)
	if stripHTTP3Advertising(resp.Header) {
		AltSvcStripped.Inc()
	}
	if s.http3Enabled {
		_, port, err := net.SplitHostPort(s.httpServer.Addr)
		if err != nil || port == "" {
			port = "443"
		}
		resp.Header.Set("Alt-Svc", fmt.Sprintf(`h3=":%s"; ma=86400`, port))
	}
	if opts.Policy != nil {
		if decision := opts.Policy.EvaluateResponse(resp, "https"); decision.Blocked {
			RuleHits.WithLabelValues("default", decision.MatchType, "block").Inc()
			logExchangeBlocked(s.logger, upReq, decision, opts)
			if !opts.DumpOnPolicyHit || decision.Blocked {
				safeReqDump("blocked")
			}
			writeBlockPage(w, http.StatusForbidden, "Access denied", "LucidGate blocked this download by file policy.")
			return
		}
	}

	if err := setHTTPWriteDeadline(w, opts.IOTimeout); err != nil && s.logger != nil {
		s.logger.Error("deadline h2 downstream client write", slog.String("address", address), slog.String("host", host), slog.Any("error", err))
	}
	respCap := newBodyCapture(resp.Body != nil, opts)
	resp.Body = readCloserWithIdleDeadline(resp.Body, connReadDeadlineRefresher(lease.conn, opts.IOTimeout))
	_, respSpan := GlobalTracer.Start(r.Context(), "Response Processing")
	respBytes, decision, err := writeResponseStreamingHTTP(w, resp, respCap, opts.Filter)
	if err != nil {
		respSpan.RecordError(err)
		respSpan.SetStatus(codes.Error, err.Error())
	}
	respSpan.End()

	policyHit := isPolicyHit(upReq, resp, reqDec, decision, opts.Policy)

	if decision.Blocked {
		RuleHits.WithLabelValues("default", decision.MatchType, "block").Inc()
		logExchangeBlocked(s.logger, upReq, decision, opts)
	} else {
		logExchange(s.logger, upReq, resp, reqBytes, respBytes, opts)
	}
	if !opts.DumpOnPolicyHit || policyHit {
		action := determineAction(upReq, resp, reqDec, decision, opts.Policy)
		safeReqDump(action)
		if opts.DumpDir != "" {
			data, trunc, skipped := respCap.dumpPayload()
			emitDump(opts, "resp", xid, upReq, resp, data, trunc, skipped, action, s.logger)
		}
	}
	if err != nil && s.logger != nil {
		s.logger.Error("write h2 downstream client response", slog.String("address", address), slog.String("host", host), slog.Any("error", err))
	}
	reusable = err == nil && !decision.Blocked && !resp.Close && lease.reader.Buffered() == 0
}

func (s *Server) handleHTTPSStreamH2Upstream(w http.ResponseWriter, req *http.Request, host, xid string, opts RelayOptions) {
	if req.Body != nil {
		body := io.Reader(req.Body)
		var inspect *InspectReader
		var reqSubInspect *InspectReader
		origBody := req.Body

		if shouldInspectRequest(req) {
			inspect = newInspectReader(origBody, reqFilter(opts.RequestFilter))
			body = inspect
		}

		if opts.RequestSubstitutionFilter != nil && opts.RequestSubstitutionFilter.HasRules() {
			if shouldSubstituteRequest(req) {
				if req.ProtoAtLeast(1, 1) {
					subEngine := opts.RequestSubstitutionFilter.NewFilter()
					if shouldBlockOnMatch(req) {
						if subStreamFilter, ok := subEngine.(*multiSubstitutionStreamFilter); ok {
							subStreamFilter.BlockOnMatch = true
						}
					}
					reqSubInspect = newInspectReader(body, subEngine)
					body = reqSubInspect
				}
			}
		}

		if inspect != nil || reqSubInspect != nil {
			req.Body = readCloser{
				Reader: body,
				close: func() error {
					var firstErr error
					if reqSubInspect != nil {
						if err := reqSubInspect.Close(); err != nil && firstErr == nil {
							firstErr = err
						}
					}
					if inspect != nil {
						if err := inspect.Close(); err != nil && firstErr == nil {
							firstErr = err
						}
					}
					if err := origBody.Close(); err != nil && firstErr == nil {
						firstErr = err
					}
					return firstErr
				},
			}
		}
	}

	resp, err := s.roundTripH2(req, host)
	closeRequestBody(req)
	if err != nil {
		if decision, ok := policyDecisionFromError(err); ok {
			RuleHits.WithLabelValues("default", decision.MatchType, "block").Inc()
			logExchangeBlocked(s.logger, req, decision, opts)
			detail := "LucidGate blocked this destination by IP policy."
			if decision.MatchType == "exfiltration preventer" {
				detail = "LucidGate blocked this request to prevent sensitive data exfiltration."
			}
			writeBlockPage(w, http.StatusForbidden, "Access denied", detail)
			return
		}
		if s.logger != nil {
			s.logger.Error("h2 downstream h2 upstream roundtrip", slog.String("host", host), slog.Any("error", err))
		}
		writeBlockPage(w, http.StatusBadGateway, "Upstream unavailable", "LucidGate could not complete the HTTP/2 upstream request.")
		return
	}
	defer closeResponseBody(resp)
	if stripHTTP3Advertising(resp.Header) {
		AltSvcStripped.Inc()
	}
	if s.http3Enabled {
		_, port, err := net.SplitHostPort(s.httpServer.Addr)
		if err != nil || port == "" {
			port = "443"
		}
		resp.Header.Set("Alt-Svc", fmt.Sprintf(`h3=":%s"; ma=86400`, port))
	}
	if opts.Policy != nil {
		if decision := opts.Policy.EvaluateResponse(resp, "https"); decision.Blocked {
			RuleHits.WithLabelValues("default", decision.MatchType, "block").Inc()
			logExchangeBlocked(s.logger, req, decision, opts)
			writeBlockPage(w, http.StatusForbidden, "Access denied", "LucidGate blocked this download by file policy.")
			return
		}
	}
	respCap := newBodyCapture(resp.Body != nil, opts)
	respBytes, decision, err := writeResponseStreamingHTTP(w, resp, respCap, opts.Filter)

	policyHit := isPolicyHit(req, resp, PolicyDecision{}, decision, opts.Policy)

	if decision.Blocked {
		RuleHits.WithLabelValues("default", decision.MatchType, "block").Inc()
		logExchangeBlocked(s.logger, req, decision, opts)
	} else {
		logExchange(s.logger, req, resp, BodyBytesNotCaptured, respBytes, opts)
	}
	if !opts.DumpOnPolicyHit || policyHit {
		if opts.DumpDir != "" {
			action := determineAction(req, resp, PolicyDecision{}, decision, opts.Policy)
			data, trunc, skipped := respCap.dumpPayload()
			emitDump(opts, "resp", xid, req, resp, data, trunc, skipped, action, s.logger)
		}
	}
	if err != nil && s.logger != nil {
		s.logger.Error("write h2 downstream h2 response", slog.String("host", host), slog.Any("error", err))
	}
}

func (s *Server) acquireUpstream(ctx context.Context, key upstreamPoolKey, dial func(context.Context) (net.Conn, error)) (*upstreamConnLease, error) {
	pool, _ := s.upstreamPool.Load().(*upstreamConnPool)
	return pool.acquire(ctx, key, dial)
}

func (s *Server) closeIdleUpstreamConnections() {
	pool, _ := s.upstreamPool.Load().(*upstreamConnPool)
	pool.closeIdle()
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

func httpReadDeadlineRefresher(w http.ResponseWriter, timeout time.Duration) deadlineRefresher {
	if w == nil || timeout <= 0 {
		return nil
	}
	return func() error {
		return setHTTPReadDeadline(w, timeout)
	}
}

func httpWriteDeadlineRefresher(w http.ResponseWriter, timeout time.Duration) deadlineRefresher {
	if w == nil || timeout <= 0 {
		return nil
	}
	return func() error {
		return setHTTPWriteDeadline(w, timeout)
	}
}

func writeTLSBadGateway(conn net.Conn) {
	_, _ = conn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\nContent-Length: 0\r\n\r\n"))
}

func (s *Server) preGenerateCert(host string) bool {
	select {
	case s.certQueue <- host:
		return true
	default:
		if s.logger != nil {
			s.logger.Warn("certificate pre-generation queue full, discarding request", slog.String("host", host))
		}
		return false
	}
}

func (s *Server) startCertWorkers(ctx context.Context) {
	numWorkers := s.CertWorkers()
	if numWorkers <= 0 {
		return
	}
	if s.logger != nil {
		s.logger.Info("starting background certificate pre-generation workers", slog.Int("count", numWorkers))
	}
	for i := 0; i < numWorkers; i++ {
		go func() {
			for {
				select {
				case <-ctx.Done():
					return
				case host := <-s.certQueue:
					if s.certs != nil {
						_, _ = s.certs.Get(host)
					}
				}
			}
		}()
	}
}

func tlsVersionToString(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("0x%04X", v)
	}
}
