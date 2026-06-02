package proxy

import (
	"bufio"
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unicode/utf8"

	"github.com/klauspost/compress/flate"
	"github.com/klauspost/compress/gzip"
	"github.com/klauspost/compress/zstd"
)

type BypassFiltersCtxKey struct{}

// BodyBytesNotCaptured is returned in log fields when the body length is
// unknown or capture was deliberately skipped.
const BodyBytesNotCaptured int64 = -1

// defaultDumpCaptureBytes caps how much of a streaming/oversized body we mirror
// to disk when DumpDir is set without an explicit MaxCaptureBytes. Keeps memory
// bounded on long SSE / chunked responses (e.g. Gemini streaming output).
const defaultDumpCaptureBytes int64 = 8 << 20 // 8 MiB

const relayBufferSize = 32 * 1024

var relayBufferPool = sync.Pool{
	New: func() any {
		buf := make([]byte, relayBufferSize)
		return &buf
	},
}

var pool4K = sync.Pool{
	New: func() any {
		buf := make([]byte, 4096)
		return &buf
	},
}

var pool32K = sync.Pool{
	New: func() any {
		buf := make([]byte, 32*1024)
		return &buf
	},
}

var pool64K = sync.Pool{
	New: func() any {
		buf := make([]byte, 64*1024)
		return &buf
	},
}

var bufioReaderPool = sync.Pool{
	New: func() any {
		return bufio.NewReaderSize(nil, 4096)
	},
}

// RelayOptions controls request/response body capture behaviour.
//
//   - LogBodies + MaxCaptureBytes drive the legacy in-memory capture used to
//     report ReqBytes/RespBytes in the structured log line.
//   - DumpDir, when non-empty, also writes the cleartext (decompressed) body
//     of every textual request and response to a single JSONL file inside that
//     directory, intended for offline Blue-Team inspection.
type RelayOptions struct {
	LogBodies                bool
	LogBodiesSampleRate      float64
	MaxCaptureBytes          int64
	DumpDir                  string
	DumpOnPolicyHit          bool
	DumpCredentialsCleartext bool
	AuditKey                 string
	DumpMaxSizeMB            int
	DumpMaxBackups           int
	DumpMinFreeSpaceMB       int64
	DumpCompress             bool
	IOTimeout                time.Duration
	WSIdleTimeout            time.Duration
	Filter                   FilterEngine
	RequestFilter            FilterEngine
	RequestSubstitutionFilter *SubstitutionFilter
	Policy                   *Policy
	RoundTripH2              func(*http.Request) (*http.Response, error)
	H2Hosts                  *sync.Map
	HTTP3Enabled             bool
	HTTP3Port                string
	AccessLogger             *slog.Logger
	AlertLogger              *slog.Logger
	AlertCategories          map[string]bool
}

type FilterEngine interface {
	ProcessChunk(in []byte) (out []byte, blocked bool, err error)
}

type filterFactory interface {
	NewFilter() FilterEngine
}

type passThroughFilter struct{}

func (passThroughFilter) ProcessChunk(in []byte) ([]byte, bool, error) {
	return in, false, nil
}

func relayHTTP(localConn net.Conn, upstreamConn net.Conn, logger *slog.Logger, opts RelayOptions) error {
	return relayHTTPConn(localConn, upstreamConn, nil, logger, opts)
}

func relayHTTPDial(localConn net.Conn, dial func() (net.Conn, error), logger *slog.Logger, opts RelayOptions) error {
	return relayHTTPConn(localConn, nil, dial, logger, opts)
}

func relayHTTPLease(localConn net.Conn, acquire func() (*upstreamConnLease, error), logger *slog.Logger, opts RelayOptions) error {
	return relayHTTPConnLease(localConn, nil, nil, acquire, logger, opts)
}

func relayHTTPConn(localConn net.Conn, upstreamConn net.Conn, dial func() (net.Conn, error), logger *slog.Logger, opts RelayOptions) error {
	return relayHTTPConnLease(localConn, upstreamConn, dial, nil, logger, opts)
}

func relayHTTPConnLease(localConn net.Conn, upstreamConn net.Conn, dial func() (net.Conn, error), acquire func() (*upstreamConnLease, error), logger *slog.Logger, opts RelayOptions) error {
	brRef := bufioReaderPool.Get().(*bufio.Reader)
	brRef.Reset(localConn)
	defer func() {
		brRef.Reset(nil)
		bufioReaderPool.Put(brRef)
	}()
	localReader := brRef
	var upstreamReader *bufio.Reader
	var releaseUpstream func(bool)
	if upstreamConn != nil {
		upstreamReader = bufio.NewReader(upstreamConn)
	}
	releaseCurrent := func(reusable bool) {
		if upstreamConn == nil {
			return
		}
		if releaseUpstream != nil {
			releaseUpstream(reusable)
		} else if dial != nil || acquire != nil {
			_ = upstreamConn.Close()
		}
		upstreamConn = nil
		upstreamReader = nil
		releaseUpstream = nil
	}
	defer func() {
		releaseCurrent(false)
	}()

	exchanges := 0
	var doH2RoundTrip func(*http.Request, string) error
	if opts.RoundTripH2 != nil {
		doH2RoundTrip = func(req *http.Request, host string) error {
			req.URL.Scheme = "https"
			req.URL.Host = host
			req.RequestURI = ""

			resp, err := opts.RoundTripH2(req)
			if err != nil {
				closeRequestBody(req)
				return fmt.Errorf("h2 roundtrip: %w", err)
			}
			closeRequestBody(req)

			if stripHTTP3Advertising(resp.Header) {
				AltSvcStripped.Inc()
			}

			if opts.HTTP3Enabled {
				resp.Header.Set("Alt-Svc", fmt.Sprintf(`h3=":%s"; ma=86400`, opts.HTTP3Port))
			}

			if opts.Policy != nil {
				if decision := opts.Policy.EvaluateResponse(resp, "https"); decision.Blocked {
					closeResponseBody(resp)
					RuleHits.WithLabelValues("default", decision.MatchType, "block").Inc()
					logExchangeBlocked(logger, req, decision, opts)
					if err := setWriteDeadline(localConn, opts.IOTimeout); err != nil {
						return fmt.Errorf("deadline local policy response block write: %w", err)
					}
					_, _ = io.WriteString(localConn, policyBlockResponse())
					return nil
				}
			}

			respCap := newBodyCapture(resp.Body != nil, opts)
			if err := setWriteDeadline(localConn, opts.IOTimeout); err != nil {
				closeResponseBody(resp)
				return fmt.Errorf("deadline local write: %w", err)
			}
			resp.Body = readCloserWithIdleDeadline(resp.Body, connReadDeadlineRefresher(localConn, opts.IOTimeout))
			localWriter := writerWithIdleDeadline(localConn, connWriteDeadlineRefresher(localConn, opts.IOTimeout))
			_, decision, err := writeResponseStreaming(localWriter, resp, respCap, opts.Filter)
			if err != nil {
				closeResponseBody(resp)
				if decision.Blocked {
					RuleHits.WithLabelValues("default", decision.MatchType, "block").Inc()
					logExchangeBlocked(logger, req, decision, opts)
				}
				return fmt.Errorf("write local response: %w", err)
			}
			closeResponseBody(resp)

			exchanges++
			return nil
		}
	}

	for {
		if err := setReadDeadline(localConn, opts.IOTimeout); err != nil {
			return fmt.Errorf("deadline local read: %w", err)
		}
		req, err := http.ReadRequest(localReader)
		if err != nil {
			if errors.Is(err, io.EOF) {
				releaseCurrent(upstreamConn != nil && upstreamReader != nil && upstreamReader.Buffered() == 0)
				return nil
			}
			if exchanges > 0 && isTimeoutError(err) {
				releaseCurrent(upstreamConn != nil && upstreamReader != nil && upstreamReader.Buffered() == 0)
				return nil
			}
			return fmt.Errorf("read local request: %w", err)
		}

		xid := newExchangeID()
		localClose := req.Close
		isWS := isWebSocketUpgrade(req)
		if !isWS {
			SanitizeHeaders(req)
		}
		if opts.Policy != nil {
			opts.Policy.RewriteRequestHeaders(req.Header)
			rawURL := canonicalPolicyURL(req, "https")
			opts.Policy.AddRequestHeaders(req.Header, rawURL)
		}
		normalizeRequestURL(req)
		if opts.Policy != nil && opts.Policy.urls != nil {
			rawURL := canonicalPolicyURL(req, "https")
			if rewrittenURL, modified := opts.Policy.urls.RewriteURL(rawURL); modified {
				if parsed, err := url.Parse(rewrittenURL); err == nil {
					req.URL = parsed
					req.Host = parsed.Host
				}
			}
		}
		if opts.Policy != nil && opts.Policy.urls != nil {
			rawURL := canonicalPolicyURL(req, "https")
			if dec, redirected := opts.Policy.urls.RedirectDecision(rawURL); redirected {
				closeRequestBody(req)
				RuleHits.WithLabelValues("default", dec.MatchType, "redirect").Inc()
				logExchangeBlocked(logger, req, dec, opts)
				if err := setWriteDeadline(localConn, opts.IOTimeout); err != nil {
					return fmt.Errorf("deadline local redirect write: %w", err)
				}
				_, _ = io.WriteString(localConn, redirectResponse(dec.RedirectURL))
				return nil
			}
		}
		req.Close = false
		host := req.Host
		if req.URL != nil && req.URL.Hostname() != "" {
			host = req.URL.Hostname()
		}
		var reqDec PolicyDecision
		if opts.Policy != nil {
			reqDec = opts.Policy.EvaluateRequest(host, req, "https")
			if reqDec.Blocked {
				closeRequestBody(req)
				RuleHits.WithLabelValues("default", reqDec.MatchType, "block").Inc()
				logExchangeBlocked(logger, req, reqDec, opts)
				if isWS {
					WebSocketSessions.WithLabelValues("denied").Inc()
				}
				if err := setWriteDeadline(localConn, opts.IOTimeout); err != nil {
					return fmt.Errorf("deadline local policy block write: %w", err)
				}
				_, _ = io.WriteString(localConn, policyBlockResponse())
				return nil
			}
			if reqDec.BypassFilters {
				req = req.WithContext(context.WithValue(req.Context(), BypassFiltersCtxKey{}, true))
			}
		}

		if isWS {
			if upstreamConn == nil {
				if acquire != nil {
					lease, aerr := acquire()
					if aerr != nil {
						if decision, ok := policyDecisionFromError(aerr); ok {
							RuleHits.WithLabelValues("default", decision.MatchType, "block").Inc()
							logExchangeBlocked(logger, req, decision, opts)
							WebSocketSessions.WithLabelValues("denied").Inc()
							closeRequestBody(req)
							if err := setWriteDeadline(localConn, opts.IOTimeout); err != nil {
								return fmt.Errorf("deadline local policy block write: %w", err)
							}
							_, _ = io.WriteString(localConn, policyBlockResponse())
							return nil
						}
						if errors.Is(aerr, errNegotiatedH2) {
							WebSocketSessions.WithLabelValues("error").Inc()
							closeRequestBody(req)
							return fmt.Errorf("websocket over h2 not supported by upstream")
						}
						closeRequestBody(req)
						return fmt.Errorf("dial upstream for ws: %w", aerr)
					}
					upstreamConn = lease.conn
					upstreamReader = lease.reader
					releaseUpstream = lease.release
				} else if dial != nil {
					var derr error
					upstreamConn, derr = dial()
					if derr != nil {
						closeRequestBody(req)
						return fmt.Errorf("dial upstream for ws: %w", derr)
					}
					upstreamReader = bufio.NewReader(upstreamConn)
					releaseUpstream = func(bool) {
						_ = upstreamConn.Close()
					}
				} else {
					closeRequestBody(req)
					return fmt.Errorf("missing upstream connection for ws")
				}
			}
			// Clear deadlines so the WS handshake and bidi pump manage their own.
			_ = localConn.SetDeadline(time.Time{})
			_ = upstreamConn.SetDeadline(time.Time{})
			wsIdle := opts.WSIdleTimeout
			if wsIdle <= 0 {
				wsIdle = DefaultWebSocketIdleTimeout
			}
			wsErr := relayWebSocket(localConn, upstreamConn, upstreamReader, req, opts.IOTimeout, wsIdle)
			closeRequestBody(req)
			// A WebSocket exchange always terminates the upstream connection
			// for pool purposes: after raw bidi the connection state is no
			// longer HTTP/1.1 idle.
			releaseCurrent(false)
			return wsErr
		}

		if doH2RoundTrip != nil && isHostH2(opts.H2Hosts, host) {
			if err := doH2RoundTrip(req, host); err != nil {
				return err
			}
			if localClose {
				return nil
			}
			continue
		}

		if upstreamConn == nil {
			if dial == nil && acquire == nil {
				closeRequestBody(req)
				return fmt.Errorf("missing upstream connection")
			}
			if acquire != nil {
				lease, err := acquire()
				if err != nil {
					if decision, ok := policyDecisionFromError(err); ok {
						RuleHits.WithLabelValues("default", decision.MatchType, "block").Inc()
						logExchangeBlocked(logger, req, decision, opts)
						closeRequestBody(req)
						if err := setWriteDeadline(localConn, opts.IOTimeout); err != nil {
							return fmt.Errorf("deadline local policy block write: %w", err)
						}
						_, _ = io.WriteString(localConn, policyBlockResponse())
						return nil
					}
					if errors.Is(err, errNegotiatedH2) {
						if doH2RoundTrip != nil {
							if err := doH2RoundTrip(req, host); err != nil {
								return err
							}
							if localClose {
								return nil
							}
							continue
						}
					}
					closeRequestBody(req)
					return fmt.Errorf("dial upstream: %w", err)
				}
				upstreamConn = lease.conn
				upstreamReader = lease.reader
				releaseUpstream = lease.release
			} else {
				var err error
				upstreamConn, err = dial()
				if err != nil {
					closeRequestBody(req)
					return fmt.Errorf("dial upstream: %w", err)
				}
				upstreamReader = bufio.NewReader(upstreamConn)
				releaseUpstream = func(bool) {
					_ = upstreamConn.Close()
				}
			}
		}

		exchangeOpts := opts
		if opts.LogBodies && opts.LogBodiesSampleRate > 0 && opts.LogBodiesSampleRate < 1.0 {
			if rand.Float64() >= opts.LogBodiesSampleRate {
				exchangeOpts.LogBodies = false
				exchangeOpts.DumpDir = ""
			}
		}

		reqCap := newBodyCapture(req.Body != nil, exchangeOpts)
		if err := setWriteDeadline(upstreamConn, exchangeOpts.IOTimeout); err != nil {
			closeRequestBody(req)
			return fmt.Errorf("deadline upstream write: %w", err)
		}
		req.Body = readCloserWithIdleDeadline(req.Body, connReadDeadlineRefresher(localConn, exchangeOpts.IOTimeout))
		upstreamWriter := writerWithIdleDeadline(upstreamConn, connWriteDeadlineRefresher(upstreamConn, exchangeOpts.IOTimeout))

		var reqDumpFunc func(action string)
		if exchangeOpts.DumpDir != "" {
			reqDumpFunc = func(action string) {
				data, trunc, skipped := reqCap.dumpPayload()
				emitDump(exchangeOpts, "req", xid, req, nil, data, trunc, skipped, action, logger)
			}
		}
		var reqDumped bool
		safeReqDump := func(action string) {
			if reqDumpFunc != nil && !reqDumped {
				reqDumpFunc(action)
				reqDumped = true
			}
		}

		reqBytes, reqDec, err := writeRequestStreaming(upstreamWriter, req, reqCap, exchangeOpts, logger)
		if err != nil {
			closeRequestBody(req)
			if !exchangeOpts.DumpOnPolicyHit || reqDec.Blocked {
				safeReqDump(determineAction(req, nil, reqDec, PolicyDecision{}, exchangeOpts.Policy))
			}
			return fmt.Errorf("write upstream request: %w", err)
		}
		closeRequestBody(req)
		if reqDec.Blocked {
			RuleHits.WithLabelValues("default", reqDec.MatchType, "block").Inc()
			logExchangeBlocked(logger, req, reqDec, exchangeOpts)
			if !exchangeOpts.DumpOnPolicyHit || reqDec.Blocked {
				safeReqDump("blocked")
			}
			if err := setWriteDeadline(localConn, exchangeOpts.IOTimeout); err != nil {
				return fmt.Errorf("deadline local policy request block write: %w", err)
			}
			_, _ = io.WriteString(localConn, policyBlockResponse())
			return nil
		}

		if err := setReadDeadline(upstreamConn, exchangeOpts.IOTimeout); err != nil {
			if !exchangeOpts.DumpOnPolicyHit {
				safeReqDump("allowed")
			}
			return fmt.Errorf("deadline upstream read: %w", err)
		}
		resp, err := http.ReadResponse(upstreamReader, req)
		if err != nil {
			if !exchangeOpts.DumpOnPolicyHit {
				safeReqDump("allowed")
			}
			return fmt.Errorf("read upstream response: %w", err)
		}
		if exchangeOpts.Policy != nil {
			exchangeOpts.Policy.RewriteResponseHeaders(resp.Header)
		}
		if stripHTTP3Advertising(resp.Header) {
			AltSvcStripped.Inc()
		}

		if exchangeOpts.HTTP3Enabled {
			resp.Header.Set("Alt-Svc", fmt.Sprintf(`h3=":%s"; ma=86400`, exchangeOpts.HTTP3Port))
		}

		if exchangeOpts.Policy != nil {
			if decision := exchangeOpts.Policy.EvaluateResponse(resp, "https"); decision.Blocked {
				closeResponseBody(resp)
				RuleHits.WithLabelValues("default", decision.MatchType, "block").Inc()
				logExchangeBlocked(logger, req, decision, exchangeOpts)
				if !exchangeOpts.DumpOnPolicyHit || decision.Blocked {
					safeReqDump("blocked")
				}
				if err := setWriteDeadline(localConn, exchangeOpts.IOTimeout); err != nil {
					return fmt.Errorf("deadline local policy response block write: %w", err)
				}
				_, _ = io.WriteString(localConn, policyBlockResponse())
				return nil
			}
		}
		respCap := newBodyCapture(resp.Body != nil, exchangeOpts)
		if err := setWriteDeadline(localConn, exchangeOpts.IOTimeout); err != nil {
			closeResponseBody(resp)
			if !exchangeOpts.DumpOnPolicyHit {
				safeReqDump("allowed")
			}
			return fmt.Errorf("deadline local write: %w", err)
		}
		resp.Body = readCloserWithIdleDeadline(resp.Body, connReadDeadlineRefresher(upstreamConn, exchangeOpts.IOTimeout))
		localWriter := writerWithIdleDeadline(localConn, connWriteDeadlineRefresher(localConn, exchangeOpts.IOTimeout))
		respBytes, respDec, err := writeResponseStreaming(localWriter, resp, respCap, exchangeOpts.Filter)

		policyHit := isPolicyHit(req, resp, reqDec, respDec, exchangeOpts.Policy)

		if err != nil {
			closeResponseBody(resp)
			if respDec.Blocked {
				RuleHits.WithLabelValues("default", respDec.MatchType, "block").Inc()
				logExchangeBlocked(logger, req, respDec, exchangeOpts)
			}
			if !exchangeOpts.DumpOnPolicyHit || policyHit {
				action := determineAction(req, resp, reqDec, respDec, exchangeOpts.Policy)
				safeReqDump(action)
				if exchangeOpts.DumpDir != "" {
					data, trunc, skipped := respCap.dumpPayload()
					emitDump(exchangeOpts, "resp", xid, req, resp, data, trunc, skipped, action, logger)
				}
			}
			if isBenignRelayError(err, respBytes, resp.ContentLength, resp) {
				return benignError{err: fmt.Errorf("write local response: %w", err)}
			}
			return fmt.Errorf("write local response: %w", err)
		}
		if respDec.Blocked {
			RuleHits.WithLabelValues("default", respDec.MatchType, "block").Inc()
			logExchangeBlocked(logger, req, respDec, exchangeOpts)
		} else {
			logExchange(logger, req, resp, reqBytes, respBytes, exchangeOpts)
		}
		if !exchangeOpts.DumpOnPolicyHit || policyHit {
			action := determineAction(req, resp, reqDec, respDec, exchangeOpts.Policy)
			safeReqDump(action)
			if exchangeOpts.DumpDir != "" {
				data, trunc, skipped := respCap.dumpPayload()
				emitDump(exchangeOpts, "resp", xid, req, resp, data, trunc, skipped, action, logger)
			}
		}

		exchanges++
		upstreamReusable := !resp.Close && upstreamReader != nil && upstreamReader.Buffered() == 0
		closeConn := localClose || resp.Close
		closeResponseBody(resp)
		if closeConn {
			releaseCurrent(upstreamReusable)
			return nil
		}
	}
}

func policyBlockResponse() string {
	const body = `<!doctype html><html lang="en"><head><meta charset="utf-8"><title>Access denied - LucidGate</title></head><body><h1>Access denied</h1><p>LucidGate blocked this request by URL policy.</p></body></html>`
	return fmt.Sprintf("HTTP/1.1 403 Forbidden\r\nContent-Type: text/html; charset=utf-8\r\nCache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\nConnection: close\r\nContent-Length: %d\r\n\r\n%s", len(body), body)
}

func isPolicyHit(req *http.Request, resp *http.Response, reqDec, respDec PolicyDecision, policy *Policy) bool {
	if reqDec.Blocked || respDec.Blocked {
		return true
	}
	if req == nil {
		return false
	}
	if policy != nil {
		host := req.Host
		if host == "" && req.URL != nil {
			host = req.URL.Host
		}
		if req.URL != nil && req.URL.Hostname() != "" {
			host = req.URL.Hostname()
		}
		scheme := "http"
		if req.TLS != nil {
			scheme = "https"
		}
		shouldLog, suppressed, _, _, _ := policy.EvaluateLogging(host, req, scheme)
		if suppressed {
			// Suppressed by exceptionlog* lists: skip dump
			return false
		}
		if shouldLog {
			return true
		}
	}
	if pm, ok := req.Context().Value(LogPhraseCtxKey{}).(LogPhraseMatch); ok {
		if pm.Suppressed {
			// Suppressed by exceptionlogphraselist: skip dump
			return false
		}
		if pm.Matched {
			return true
		}
	}
	if resp != nil && resp.Request != nil {
		if pm, ok := resp.Request.Context().Value(LogPhraseCtxKey{}).(LogPhraseMatch); ok {
			if pm.Suppressed {
				return false
			}
			if pm.Matched {
				return true
			}
		}
	}
	return false
}

func determineAction(req *http.Request, resp *http.Response, reqDec, respDec PolicyDecision, policy *Policy) string {
	if reqDec.Blocked || respDec.Blocked {
		return "blocked"
	}
	if isPolicyHit(req, resp, reqDec, respDec, policy) {
		return "audited"
	}
	return "allowed"
}

func setReadDeadline(conn net.Conn, timeout time.Duration) error {
	if timeout <= 0 {
		return nil
	}
	return conn.SetReadDeadline(time.Now().Add(timeout))
}

func setWriteDeadline(conn net.Conn, timeout time.Duration) error {
	if timeout <= 0 {
		return nil
	}
	return conn.SetWriteDeadline(time.Now().Add(timeout))
}

type readDeadliner interface {
	SetReadDeadline(time.Time) error
}

type writeDeadliner interface {
	SetWriteDeadline(time.Time) error
}

type deadlineRefresher func() error

type idleDeadlineReader struct {
	r       io.Reader
	refresh deadlineRefresher
}

func (r idleDeadlineReader) Read(p []byte) (int, error) {
	var deadlineErr error
	if r.refresh != nil {
		deadlineErr = r.refresh()
		if deadlineErr != nil && !canReadPastDeadlineRefreshError(deadlineErr) {
			return 0, deadlineErr
		}
	}
	n, err := r.r.Read(p)
	if err == nil && n == 0 && deadlineErr != nil {
		return 0, deadlineErr
	}
	return n, err
}

type idleDeadlineReadCloser struct {
	io.ReadCloser
	refresh deadlineRefresher
}

func (r idleDeadlineReadCloser) Read(p []byte) (int, error) {
	var deadlineErr error
	if r.refresh != nil {
		deadlineErr = r.refresh()
		if deadlineErr != nil && !canReadPastDeadlineRefreshError(deadlineErr) {
			return 0, deadlineErr
		}
	}
	n, err := r.ReadCloser.Read(p)
	if err == nil && n == 0 && deadlineErr != nil {
		return 0, deadlineErr
	}
	return n, err
}

type idleDeadlineWriter struct {
	w       io.Writer
	refresh deadlineRefresher
}

func (w idleDeadlineWriter) Write(p []byte) (int, error) {
	if w.refresh != nil {
		if err := w.refresh(); err != nil {
			return 0, err
		}
	}
	return w.w.Write(p)
}

type idleDeadlineResponseWriter struct {
	http.ResponseWriter
	refresh deadlineRefresher
}

func (w idleDeadlineResponseWriter) Write(p []byte) (int, error) {
	if w.refresh != nil {
		if err := w.refresh(); err != nil {
			return 0, err
		}
	}
	return w.ResponseWriter.Write(p)
}

func readCloserWithIdleDeadline(r io.ReadCloser, refresh deadlineRefresher) io.ReadCloser {
	if r == nil || refresh == nil {
		return r
	}
	return idleDeadlineReadCloser{ReadCloser: r, refresh: refresh}
}

func readerWithIdleDeadline(r io.Reader, refresh deadlineRefresher) io.Reader {
	if r == nil || refresh == nil {
		return r
	}
	return idleDeadlineReader{r: r, refresh: refresh}
}

func writerWithIdleDeadline(w io.Writer, refresh deadlineRefresher) io.Writer {
	if w == nil || refresh == nil {
		return w
	}
	return idleDeadlineWriter{w: w, refresh: refresh}
}

func responseWriterWithIdleDeadline(w http.ResponseWriter, refresh deadlineRefresher) http.ResponseWriter {
	if w == nil || refresh == nil {
		return w
	}
	return idleDeadlineResponseWriter{ResponseWriter: w, refresh: refresh}
}

func connReadDeadlineRefresher(conn readDeadliner, timeout time.Duration) deadlineRefresher {
	if conn == nil || timeout <= 0 {
		return nil
	}
	return func() error {
		return conn.SetReadDeadline(time.Now().Add(timeout))
	}
}

func connWriteDeadlineRefresher(conn writeDeadliner, timeout time.Duration) deadlineRefresher {
	if conn == nil || timeout <= 0 {
		return nil
	}
	return func() error {
		return conn.SetWriteDeadline(time.Now().Add(timeout))
	}
}

func isTimeoutError(err error) bool {
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}

func canReadPastDeadlineRefreshError(err error) bool {
	return errors.Is(err, io.ErrClosedPipe) || errors.Is(err, net.ErrClosed)
}

func SanitizeHeaders(req *http.Request) {
	req.Header.Del("Connection")
	req.Header.Del("Keep-Alive")
	req.Header.Del("Proxy-Connection")
	req.Header.Del("X-Forwarded-For")
	req.Header.Del("Via")
	req.Header.Del("X-Real-IP")
}

func normalizeRequestURL(req *http.Request) {
	req.RequestURI = ""
	if req.URL == nil {
		return
	}
	if req.URL.IsAbs() {
		req.URL.Scheme = ""
		req.URL.Host = ""
	}
}

func closeRequestBody(req *http.Request) {
	if req.Body != nil {
		_ = req.Body.Close()
	}
}

func closeResponseBody(resp *http.Response) {
	if resp.Body != nil {
		_ = resp.Body.Close()
	}
}

// teeBuffer mirrors a bounded prefix of the bytes written to it. Used to
// capture streaming response bodies without growing memory unbounded.
type teeBuffer struct {
	limit int64
	buf   bytes.Buffer
	full  bool
}

func (t *teeBuffer) Write(p []byte) (int, error) {
	if t.full {
		return len(p), nil
	}
	remaining := t.limit - int64(t.buf.Len())
	if remaining <= 0 {
		t.full = true
		return len(p), nil
	}
	if int64(len(p)) > remaining {
		t.buf.Write(p[:remaining])
		t.full = true
	} else {
		t.buf.Write(p)
	}
	return len(p), nil
}

type bodyCapture struct {
	wantLog bool
	tee     *teeBuffer
	skipped string
}

func newBodyCapture(hasBody bool, opts RelayOptions) *bodyCapture {
	c := &bodyCapture{
		wantLog: opts.LogBodies && opts.MaxCaptureBytes != 0,
	}
	if !hasBody {
		return c
	}
	if opts.DumpDir == "" {
		if !c.wantLog {
			c.skipped = "capture disabled"
		}
		return c
	}
	limit := opts.MaxCaptureBytes
	if limit <= 0 {
		limit = defaultDumpCaptureBytes
	}
	c.tee = &teeBuffer{limit: limit}
	return c
}

func (c *bodyCapture) reader(src io.Reader) io.Reader {
	if c == nil || c.tee == nil {
		return src
	}
	return io.TeeReader(src, c.tee)
}

func (c *bodyCapture) logBytes(n int64) int64 {
	if c == nil || !c.wantLog {
		return BodyBytesNotCaptured
	}
	return n
}

func (c *bodyCapture) dumpPayload() ([]byte, bool, string) {
	if c == nil || c.tee == nil {
		if c != nil {
			return nil, false, c.skipped
		}
		return nil, false, ""
	}
	return c.tee.buf.Bytes(), c.tee.full, ""
}

func writeRequestStreaming(w io.Writer, req *http.Request, cap *bodyCapture, opts RelayOptions, logger *slog.Logger) (int64, PolicyDecision, error) {
	var dec PolicyDecision
	if req.Body == nil {
		if err := req.Write(w); err != nil {
			return 0, dec, err
		}
		return 0, dec, nil
	}
	body := io.Reader(req.Body)
	var inspect *InspectReader
	var activeFilter FilterEngine
	if shouldInspectRequest(req) {
		activeFilter = reqFilter(opts.RequestFilter)
		inspect = newInspectReader(req.Body, activeFilter)
		defer inspect.Close()
		body = inspect
	}

	var reqSubInspect *InspectReader
	if opts.RequestSubstitutionFilter != nil && opts.RequestSubstitutionFilter.HasRules() {
		if shouldSubstituteRequest(req) {
			if !req.ProtoAtLeast(1, 1) {
				RequestSubstitutionSkippedTotal.WithLabelValues("framing").Inc()
				if logger != nil {
					logger.Warn("Request body substitution skipped due to unsupported framing", slog.String("proto", req.Proto))
				}
			} else {
				subEngine := opts.RequestSubstitutionFilter.NewFilter()
				if shouldBlockOnMatch(req) {
					if subStreamFilter, ok := subEngine.(*multiSubstitutionStreamFilter); ok {
						subStreamFilter.BlockOnMatch = true
					}
				}
				reqSubInspect = newInspectReader(body, subEngine)
				defer reqSubInspect.Close()
				body = reqSubInspect
			}
		}
	}

	if err := writeRequestHeader(w, req); err != nil {
		return 0, dec, err
	}
	n, err := writeBodyStreaming(w, body, requestUsesChunked(req), req.ContentLength, req.Trailer, cap)

	if err != nil && errors.Is(err, ErrSecretExfiltrationBlocked) {
		dec = PolicyDecision{
			Blocked:   true,
			MatchType: "exfiltration preventer",
			Value:     "sensitive data exfiltration blocked",
		}
		err = nil
	} else if err != nil && errors.Is(err, ErrAntivirusBlocked) {
		val := "antivirus signature"
		errMsg := err.Error()
		prefix := "antivirus blocked response: "
		if strings.HasPrefix(errMsg, prefix) {
			val = errMsg[len(prefix):]
		}
		dec = PolicyDecision{
			Blocked:   true,
			MatchType: "antivirus",
			Value:     val,
		}
	} else if activeFilter != nil {
		if decEngine, ok := activeFilter.(Decisioner); ok {
			if blocked, matchType, val := decEngine.Decision(); blocked {
				dec = PolicyDecision{
					Blocked:   true,
					MatchType: matchType,
					Value:     val,
				}
			}
		}
		if ld, ok := activeFilter.(LogDecisioner); ok {
			if matched, suppressed, matchType, val := ld.LogDecision(); matched || suppressed {
				ctx := context.WithValue(req.Context(), LogPhraseCtxKey{}, LogPhraseMatch{
					Matched:    matched,
					Suppressed: suppressed,
					MatchType:  matchType,
					Value:      val,
				})
				*req = *req.WithContext(ctx)
			}
		}
	}

	return cap.logBytes(n), dec, err
}

func shouldSubstituteRequest(req *http.Request) bool {
	if req == nil || req.Body == nil {
		return false
	}
	switch req.Method {
	case http.MethodPost, http.MethodPut, http.MethodPatch:
	default:
		return false
	}
	ce := normalizeContentEncoding(req.Header.Get("Content-Encoding"))
	if ce != "" && ce != "identity" {
		return false
	}
	ct := req.Header.Get("Content-Type")
	if isMutableRequestContentType(ct) {
		return true
	}
	mt := strings.ToLower(strings.TrimSpace(strings.SplitN(ct, ";", 2)[0]))
	if mt == "multipart/form-data" {
		return true
	}
	return false
}

func shouldBlockOnMatch(req *http.Request) bool {
	if req == nil {
		return false
	}
	host := strings.ToLower(req.Host)
	if strings.Contains(host, "aistudio.google") ||
		strings.Contains(host, "googleapis.com") ||
		strings.Contains(host, "clients6.google.com") {
		return true
	}
	ct := strings.ToLower(req.Header.Get("Content-Type"))
	if strings.Contains(ct, "protobuf") || strings.Contains(ct, "grpc") {
		return true
	}
	return false
}

func reqFilter(engine FilterEngine) FilterEngine {
	if content, ok := engine.(*ContentFilter); ok {
		if content.Semantic != nil {
			return content.Semantic.NewFilter()
		}
		return passThroughFilter{}
	}
	if engine != nil {
		if factory, ok := engine.(filterFactory); ok {
			return factory.NewFilter()
		}
		return engine
	}
	return passThroughFilter{}
}

func writeResponseStreaming(w io.Writer, resp *http.Response, cap *bodyCapture, filter FilterEngine) (int64, PolicyDecision, error) {
	var dec PolicyDecision
	if resp.Body == nil {
		if err := resp.Write(w); err != nil {
			return 0, dec, err
		}
		return 0, dec, nil
	}
	body := io.Reader(resp.Body)
	originalContentLength := resp.ContentLength
	var transformed io.ReadCloser
	
	var bypassFilters bool
	if resp.Request != nil {
		if b, ok := resp.Request.Context().Value(BypassFiltersCtxKey{}).(bool); ok && b {
			bypassFilters = true
		}
	}

	inspectResponse := shouldInspectResponse(resp, filter) && !bypassFilters
	var antivirus *Antivirus
	if !bypassFilters {
		antivirus = antivirusForResponse(resp, filter)
	}
	var activeFilter FilterEngine
	if inspectResponse {
		inspected, active, err := newResponseInspectReader(resp.Body, resp.Header.Get("Content-Encoding"), respFilter(filter, resp.Header.Get("Content-Type"), resp.Request))
		if err != nil {
			return 0, dec, err
		}
		activeFilter = active
		transformed = inspected
		defer transformed.Close()
		body = inspected
		resp.ContentLength = -1
		resp.TransferEncoding = []string{"chunked"}
		resp.Header.Del("Content-Length")
	}
	if antivirus != nil {
		src, ok := body.(io.ReadCloser)
		if !ok {
			src = readCloser{Reader: body}
		}
		transformed = newAntivirusTricklingReader(requestContext(resp.Request), src, antivirus)
		defer transformed.Close()
		body = transformed
		resp.ContentLength = -1
		resp.TransferEncoding = []string{"chunked"}
		resp.Header.Del("Content-Length")
	}
	if err := writeResponseHeader(w, resp); err != nil {
		return 0, dec, err
	}
	n, err := writeBodyStreaming(w, body, responseUsesChunked(resp), originalContentLength, resp.Trailer, cap)

	if err != nil && errors.Is(err, ErrAntivirusBlocked) {
		val := "antivirus signature"
		errMsg := err.Error()
		prefix := "antivirus blocked response: "
		if strings.HasPrefix(errMsg, prefix) {
			val = errMsg[len(prefix):]
		}
		dec = PolicyDecision{
			Blocked:   true,
			MatchType: "antivirus",
			Value:     val,
		}
	} else if activeFilter != nil {
		if decEngine, ok := activeFilter.(Decisioner); ok {
			if blocked, matchType, val := decEngine.Decision(); blocked {
				dec = PolicyDecision{
					Blocked:   true,
					MatchType: matchType,
					Value:     val,
				}
			}
		}
		if ld, ok := activeFilter.(LogDecisioner); ok {
			if matched, suppressed, matchType, val := ld.LogDecision(); matched || suppressed {
				if resp.Request != nil {
					ctx := context.WithValue(resp.Request.Context(), LogPhraseCtxKey{}, LogPhraseMatch{
						Matched:    matched,
						Suppressed: suppressed,
						MatchType:  matchType,
						Value:      val,
					})
					*resp.Request = *resp.Request.WithContext(ctx)
				}
			}
		}
	}

	return cap.logBytes(n), dec, err
}

func writeResponseStreamingHTTP(w http.ResponseWriter, resp *http.Response, cap *bodyCapture, filter FilterEngine) (int64, PolicyDecision, error) {
	var dec PolicyDecision
	if resp.Body == nil {
		copyResponseHeaders(w.Header(), resp.Header)
		w.WriteHeader(resp.StatusCode)
		return 0, dec, nil
	}
	body := io.Reader(resp.Body)
	var transformed io.ReadCloser

	var bypassFilters bool
	if resp.Request != nil {
		if b, ok := resp.Request.Context().Value(BypassFiltersCtxKey{}).(bool); ok && b {
			bypassFilters = true
		}
	}

	inspectResponse := shouldInspectResponse(resp, filter) && !bypassFilters
	var antivirus *Antivirus
	if !bypassFilters {
		antivirus = antivirusForResponse(resp, filter)
	}
	forceChunked := inspectResponse || antivirus != nil
	var activeFilter FilterEngine
	if inspectResponse {
		inspected, active, err := newResponseInspectReader(resp.Body, resp.Header.Get("Content-Encoding"), respFilter(filter, resp.Header.Get("Content-Type"), resp.Request))
		if err != nil {
			return 0, dec, err
		}
		activeFilter = active
		transformed = inspected
		defer transformed.Close()
		body = inspected
		resp.ContentLength = -1
		resp.TransferEncoding = []string{"chunked"}
		resp.Header.Del("Content-Length")
	}
	if antivirus != nil {
		src, ok := body.(io.ReadCloser)
		if !ok {
			src = readCloser{Reader: body}
		}
		transformed = newAntivirusTricklingReader(requestContext(resp.Request), src, antivirus)
		defer transformed.Close()
		body = transformed
		resp.ContentLength = -1
		resp.TransferEncoding = []string{"chunked"}
		resp.Header.Del("Content-Length")
	}
	copyResponseHeaders(w.Header(), resp.Header)
	if resp.ContentLength >= 0 && !forceChunked {
		w.Header().Set("Content-Length", fmt.Sprintf("%d", resp.ContentLength))
	} else {
		w.Header().Del("Content-Length")
	}
	w.WriteHeader(resp.StatusCode)
	n, err := copyBufferPooled(w, cap.reader(body))

	if err != nil && errors.Is(err, ErrAntivirusBlocked) {
		val := "antivirus signature"
		errMsg := err.Error()
		prefix := "antivirus blocked response: "
		if strings.HasPrefix(errMsg, prefix) {
			val = errMsg[len(prefix):]
		}
		dec = PolicyDecision{
			Blocked:   true,
			MatchType: "antivirus",
			Value:     val,
		}
	} else if activeFilter != nil {
		if decEngine, ok := activeFilter.(Decisioner); ok {
			if blocked, matchType, val := decEngine.Decision(); blocked {
				dec = PolicyDecision{
					Blocked:   true,
					MatchType: matchType,
					Value:     val,
				}
			}
		}
		if ld, ok := activeFilter.(LogDecisioner); ok {
			if matched, suppressed, matchType, val := ld.LogDecision(); matched || suppressed {
				if resp.Request != nil {
					ctx := context.WithValue(resp.Request.Context(), LogPhraseCtxKey{}, LogPhraseMatch{
						Matched:    matched,
						Suppressed: suppressed,
						MatchType:  matchType,
						Value:      val,
					})
					*resp.Request = *resp.Request.WithContext(ctx)
				}
			}
		}
	}

	return cap.logBytes(n), dec, err
}

func copyResponseHeaders(dst, src http.Header) {
	for key := range dst {
		delete(dst, key)
	}
	for key, values := range src {
		if isResponseWriterManagedHeader(key) {
			continue
		}
		for _, value := range values {
			dst.Add(key, value)
		}
	}
}

func isResponseWriterManagedHeader(key string) bool {
	switch http.CanonicalHeaderKey(key) {
	case "Content-Length", "Transfer-Encoding":
		return true
	default:
		return false
	}
}

// shouldInjectHTMLBanner decide si una respuesta HTML debe llevar el banner.
// Inyectamos solo en el documento principal: sub-recursos como iframes (ads,
// widgets, embebidos) generarían un banner por iframe y saturan la página.
//
// Heurística (Sec-Fetch-Dest, RFC Fetch Metadata):
//   - "document"  -> top-level navigation: SÍ inyectar.
//   - "iframe", "frame", "embed", "object"... -> NO inyectar.
//   - cabecera ausente (curl, clientes legacy, HTTP/1.0): SÍ inyectar
//     (preserva el comportamiento de pruebas y clientes no-browser).
func shouldInjectHTMLBanner(req *http.Request) bool {
	if req == nil {
		return true
	}
	dest := strings.ToLower(strings.TrimSpace(req.Header.Get("Sec-Fetch-Dest")))
	if dest == "" {
		return true
	}
	return dest == "document"
}

func respFilter(engine FilterEngine, contentType string, req *http.Request) FilterEngine {
	if engine == nil {
		return passThroughFilter{}
	}
	content, isContent := engine.(*ContentFilter)
	if !isContent {
		if factory, ok := engine.(filterFactory); ok {
			engine = factory.NewFilter()
		}
		if isHTMLContentType(contentType) && isSemanticPhraseFilter(engine) {
			return newHTMLTextFilter(engine)
		}
		if isScriptOrStyleContentType(contentType) {
			return passThroughFilter{}
		}
		return engine
	}
	var filters []FilterEngine
	if content.Magic != nil && len(content.Magic.blocked) > 0 {
		filters = append(filters, content.Magic.NewFilter())
	}
	if isFilterMutableResponseType(contentType) {
		if isHTMLContentType(contentType) {
			if content.Semantic != nil {
				filters = append(filters, newHTMLTextFilter(content.Semantic.NewFilter()))
			}
			if content.LogSemantic != nil {
				lf := content.LogSemantic.NewFilter()
				if psf, ok := lf.(*phraseStreamFilter); ok {
					psf.observeOnly = true
				}
				filters = append(filters, newHTMLTextFilter(lf))
			}
			if content.Substitution != nil && content.Substitution.HasRules() {
				// htmlTextFilter es solo "observador" (descarta la salida del inner)
				// y rompería las sustituciones, así que aplicamos Substitution
				// directamente sobre los bytes crudos del cuerpo.
				filters = append(filters, content.Substitution.NewFilter())
			}
			if content.HTML != nil && len(content.HTML.banner) > 0 && shouldInjectHTMLBanner(req) {
				filters = append(filters, content.HTML.NewFilter())
			}
		} else {
			if content.Semantic != nil {
				filters = append(filters, content.Semantic.NewFilter())
			}
			if content.LogSemantic != nil {
				lf := content.LogSemantic.NewFilter()
				if psf, ok := lf.(*phraseStreamFilter); ok {
					psf.observeOnly = true
				}
				filters = append(filters, lf)
			}
			if content.Masking != nil && content.Masking.maxLen > 0 {
				filters = append(filters, content.Masking.NewFilter())
			}
			if content.Substitution != nil {
				filters = append(filters, content.Substitution.NewFilter())
			}
		}
	}
	return newChainOrPassThrough(filters)
}

func newChainOrPassThrough(filters []FilterEngine) FilterEngine {
	switch len(filters) {
	case 0:
		return passThroughFilter{}
	case 1:
		return filters[0]
	default:
		return &chainFilter{filters: filters}
	}
}

func isSemanticPhraseFilter(engine FilterEngine) bool {
	_, ok := engine.(*phraseStreamFilter)
	return ok
}

func newResponseInspectReader(src io.ReadCloser, encoding string, engine FilterEngine) (io.ReadCloser, FilterEngine, error) {
	encoding = normalizeContentEncoding(encoding)
	if encoding == "" || encoding == "identity" {
		return newInspectReader(src, engine), engine, nil
	}
	r, err := newEncodedInspectReader(src, encoding, engine)
	if err != nil {
		return nil, nil, err
	}
	return r, engine, nil
}

type InspectReader struct {
	src     io.Reader
	engine  FilterEngine
	scratch *[]byte
	out     []byte
	blocked bool
	flushed bool
}

func newInspectReader(src io.Reader, engine FilterEngine) *InspectReader {
	bufp := relayBufferPool.Get().(*[]byte)
	return &InspectReader{
		src:     src,
		engine:  engine,
		scratch: bufp,
	}
}

func (r *InspectReader) Read(p []byte) (int, error) {
	for len(r.out) == 0 {
		if r.blocked {
			return 0, io.EOF
		}
		n, err := r.src.Read(*r.scratch)
		if n > 0 {
			start := time.Now()
			out, blocked, filterErr := r.engine.ProcessChunk((*r.scratch)[:n])
			InspectionDuration.Observe(time.Since(start).Seconds())
			r.blocked = blocked
			if filterErr != nil {
				return 0, filterErr
			}
			r.out = out
		}
		if err != nil {
			if len(r.out) > 0 && errors.Is(err, io.EOF) {
				break
			}
			if errors.Is(err, io.EOF) {
				if flushErr := r.flushEngine(); flushErr != nil {
					return 0, flushErr
				}
				if len(r.out) > 0 {
					break
				}
			}
			return 0, err
		}
	}
	n := copy(p, r.out)
	r.out = r.out[n:]
	return n, nil
}

func (r *InspectReader) flushEngine() error {
	if r.flushed {
		return nil
	}
	r.flushed = true
	flush, ok := r.engine.(flushingFilter)
	if !ok {
		return nil
	}
	out, err := flush.Flush()
	if err != nil {
		return err
	}
	r.out = out
	return nil
}

func (r *InspectReader) Close() error {
	if r.scratch != nil {
		relayBufferPool.Put(r.scratch)
		r.scratch = nil
	}
	return nil
}

type encodedInspectReader struct {
	pr   *io.PipeReader
	done chan struct{}
	src  io.Closer
	once sync.Once
	err  error
}

func newEncodedInspectReader(src io.ReadCloser, encoding string, engine FilterEngine) (*encodedInspectReader, error) {
	pr, pw := io.Pipe()
	r := &encodedInspectReader{
		pr:   pr,
		done: make(chan struct{}),
		src:  src,
	}
	go r.run(pw, src, encoding, engine)
	return r, nil
}

func (r *encodedInspectReader) run(pw *io.PipeWriter, src io.Reader, encoding string, engine FilterEngine) {
	defer close(r.done)
	decoder, err := newContentDecoder(src, encoding)
	if err != nil {
		_ = pw.CloseWithError(err)
		return
	}
	defer decoder.Close()
	encoder, err := newContentEncoder(pw, encoding)
	if err != nil {
		_ = pw.CloseWithError(err)
		return
	}
	inspect := newInspectReader(decoder, engine)
	_, copyErr := copyBufferPooled(encoder, inspect)
	inspect.Close()
	closeErr := encoder.Close()
	if copyErr != nil {
		_ = pw.CloseWithError(copyErr)
		return
	}
	if closeErr != nil {
		_ = pw.CloseWithError(closeErr)
		return
	}
	_ = pw.Close()
}

func (r *encodedInspectReader) Read(p []byte) (int, error) {
	return r.pr.Read(p)
}

func (r *encodedInspectReader) Close() error {
	r.once.Do(func() {
		r.err = r.pr.Close()
		if closeErr := r.src.Close(); r.err == nil {
			r.err = closeErr
		}
		<-r.done
	})
	return r.err
}

type readCloser struct {
	io.Reader
	close func() error
}

func (r readCloser) Close() error {
	if r.close == nil {
		return nil
	}
	return r.close()
}

func newContentDecoder(src io.Reader, encoding string) (io.ReadCloser, error) {
	switch encoding {
	case "gzip", "x-gzip":
		r, err := gzip.NewReader(src)
		if err != nil {
			return nil, fmt.Errorf("gzip decoder: %w", err)
		}
		return r, nil
	case "deflate":
		return flate.NewReader(src), nil
	case "br":
		return newBrotliReader(src), nil
	case "zstd":
		r, err := zstd.NewReader(src)
		if err != nil {
			return nil, fmt.Errorf("zstd decoder: %w", err)
		}
		return readCloser{Reader: r, close: func() error { r.Close(); return nil }}, nil
	default:
		return nil, fmt.Errorf("unsupported content encoding %q", encoding)
	}
}

func newContentEncoder(dst io.Writer, encoding string) (io.WriteCloser, error) {
	switch encoding {
	case "gzip", "x-gzip":
		return gzip.NewWriter(dst), nil
	case "deflate":
		return flate.NewWriter(dst, flate.DefaultCompression)
	case "br":
		return newBrotliWriter(dst), nil
	case "zstd":
		return zstd.NewWriter(dst)
	default:
		return nil, fmt.Errorf("unsupported content encoding %q", encoding)
	}
}

func writeRequestHeader(w io.Writer, req *http.Request) error {
	uri := "/"
	if req.URL != nil {
		uri = req.URL.RequestURI()
		if uri == "" {
			uri = "/"
		}
	}
	if _, err := fmt.Fprintf(w, "%s %s HTTP/1.1\r\n", req.Method, uri); err != nil {
		return err
	}
	host := req.Host
	if host == "" && req.URL != nil {
		host = req.URL.Host
	}
	if host != "" {
		if _, err := fmt.Fprintf(w, "Host: %s\r\n", host); err != nil {
			return err
		}
	}
	return writeMessageHeaders(w, req.Header, req.ContentLength, requestUsesChunked(req), req.Close)
}

func writeResponseHeader(w io.Writer, resp *http.Response) error {
	status := resp.Status
	if status == "" {
		status = fmt.Sprintf("%d %s", resp.StatusCode, http.StatusText(resp.StatusCode))
	}
	if _, err := fmt.Fprintf(w, "HTTP/1.1 %s\r\n", status); err != nil {
		return err
	}
	return writeMessageHeaders(w, resp.Header, resp.ContentLength, responseUsesChunked(resp), resp.Close)
}

func writeMessageHeaders(w io.Writer, h http.Header, contentLength int64, chunked bool, closeConn bool) error {
	exclude := map[string]bool{
		"Content-Length":    true,
		"Transfer-Encoding": true,
	}
	if err := h.WriteSubset(w, exclude); err != nil {
		return err
	}
	if contentLength >= 0 && !chunked {
		if _, err := fmt.Fprintf(w, "Content-Length: %d\r\n", contentLength); err != nil {
			return err
		}
	}
	if chunked {
		if _, err := io.WriteString(w, "Transfer-Encoding: chunked\r\n"); err != nil {
			return err
		}
	}
	if closeConn {
		if _, err := io.WriteString(w, "Connection: close\r\n"); err != nil {
			return err
		}
	}
	_, err := io.WriteString(w, "\r\n")
	return err
}

func writeBodyStreaming(w io.Writer, body io.Reader, chunked bool, sizeHint int64, trailers http.Header, cap *bodyCapture) (int64, error) {
	dst := w
	var chunkWriter io.WriteCloser
	if chunked {
		chunkWriter = httputil.NewChunkedWriter(w)
		dst = chunkWriter
	}
	n, err := copyBufferPooledSize(dst, cap.reader(body), sizeHint)
	if closeErr := closeChunkedBody(w, chunkWriter, trailers); err == nil {
		err = closeErr
	}
	return n, err
}

func closeChunkedBody(w io.Writer, chunkWriter io.WriteCloser, trailers http.Header) error {
	if chunkWriter == nil {
		return nil
	}
	if err := chunkWriter.Close(); err != nil {
		return err
	}
	if len(trailers) > 0 {
		if err := trailers.Write(w); err != nil {
			return err
		}
	}
	_, err := io.WriteString(w, "\r\n")
	return err
}

func requestUsesChunked(req *http.Request) bool {
	if req.ContentLength >= 0 {
		return false
	}
	return hasChunked(req.TransferEncoding)
}

func responseUsesChunked(resp *http.Response) bool {
	if resp.ContentLength >= 0 {
		return false
	}
	return hasChunked(resp.TransferEncoding) || !resp.Close
}

func shouldInspectResponse(resp *http.Response, filter FilterEngine) bool {
	if resp == nil {
		return false
	}
	if !isSupportedInspectEncoding(resp.Header.Get("Content-Encoding")) {
		return false
	}
	if isRangeOrMediaResponse(resp) {
		return false
	}
	if isFilterMutableResponseType(resp.Header.Get("Content-Type")) {
		return true
	}
	return hasMagicFilter(filter)
}

func antivirusForResponse(resp *http.Response, filter FilterEngine) *Antivirus {
	if resp == nil || resp.Body == nil || resp.StatusCode != http.StatusOK {
		return nil
	}
	if isRangeOrMediaResponse(resp) {
		return nil
	}
	if isMutableContentType(resp.Header.Get("Content-Type")) {
		return nil
	}
	content, ok := filter.(*ContentFilter)
	if !ok || content == nil || content.Antivirus == nil || content.Antivirus.Scanner == nil {
		return nil
	}
	return content.Antivirus
}

func isRangeOrMediaResponse(resp *http.Response) bool {
	if resp == nil {
		return false
	}
	if resp.StatusCode == http.StatusPartialContent {
		return true
	}
	if resp.Request != nil && resp.Request.Header.Get("Range") != "" {
		return true
	}
	ct := strings.ToLower(strings.TrimSpace(strings.SplitN(resp.Header.Get("Content-Type"), ";", 2)[0]))
	return strings.HasPrefix(ct, "video/") || strings.HasPrefix(ct, "audio/")
}

func requestContext(req *http.Request) context.Context {
	if req == nil {
		return context.Background()
	}
	return req.Context()
}

func hasMagicFilter(engine FilterEngine) bool {
	content, ok := engine.(*ContentFilter)
	if !ok || content == nil || content.Magic == nil {
		return false
	}
	return len(content.Magic.blocked) > 0
}

func shouldInspectRequest(req *http.Request) bool {
	if req == nil || req.Body == nil {
		return false
	}
	switch req.Method {
	case http.MethodPost, http.MethodPut, http.MethodPatch:
	default:
		return false
	}
	if !isSupportedInspectEncoding(req.Header.Get("Content-Encoding")) {
		return false
	}
	return isMutableRequestContentType(req.Header.Get("Content-Type"))
}

func isMutableRequestContentType(ct string) bool {
	if ct == "" {
		return false
	}
	mt := strings.ToLower(strings.TrimSpace(strings.SplitN(ct, ";", 2)[0]))
	if strings.HasPrefix(mt, "multipart/") {
		return false
	}
	return isMutableContentType(ct)
}

func isSupportedInspectEncoding(encoding string) bool {
	switch normalizeContentEncoding(encoding) {
	case "", "identity", "gzip", "x-gzip", "deflate", "br", "zstd":
		return true
	default:
		return false
	}
}

func normalizeContentEncoding(encoding string) string {
	return strings.ToLower(strings.TrimSpace(encoding))
}

func isMutableContentType(ct string) bool {
	if ct == "" {
		return false
	}
	mt := strings.ToLower(strings.TrimSpace(strings.SplitN(ct, ";", 2)[0]))
	if isStructuredStreamContentType(mt) {
		return false
	}
	if strings.HasPrefix(mt, "text/") {
		return true
	}
	if strings.Contains(mt, "json") || strings.Contains(mt, "xml") {
		return true
	}
	switch mt {
	case "application/javascript",
		"application/x-javascript",
		"application/ecmascript",
		"application/x-www-form-urlencoded",
		"application/grpc-web-text",
		"application/x-ndjson":
		return true
	}
	return false
}

func isStructuredStreamContentType(mt string) bool {
	switch mt {
	case "text/event-stream":
		return true
	default:
		return false
	}
}

func isFilterMutableResponseType(ct string) bool {
	if !isMutableContentType(ct) {
		return false
	}
	return !isScriptOrStyleContentType(ct)
}

func isScriptOrStyleContentType(ct string) bool {
	mt := strings.ToLower(strings.TrimSpace(strings.SplitN(ct, ";", 2)[0]))
	switch mt {
	case "application/javascript",
		"application/x-javascript",
		"application/ecmascript",
		"text/javascript",
		"text/ecmascript",
		"text/css":
		return true
	default:
		return false
	}
}

func isHTMLContentType(ct string) bool {
	mt := strings.ToLower(strings.TrimSpace(strings.SplitN(ct, ";", 2)[0]))
	switch mt {
	case "text/html", "application/xhtml+xml":
		return true
	default:
		return false
	}
}

func hasChunked(values []string) bool {
	for _, value := range values {
		if strings.EqualFold(value, "chunked") {
			return true
		}
	}
	return false
}

func copyBufferPooled(dst io.Writer, src io.Reader) (int64, error) {
	return copyBufferPooledSize(dst, src, 32*1024)
}

func copyBufferPooledSize(dst io.Writer, src io.Reader, sizeHint int64) (int64, error) {
	var pool *sync.Pool
	if sizeHint > 0 && sizeHint <= 4096 {
		pool = &pool4K
	} else if sizeHint > 4096 && sizeHint <= 32*1024 {
		pool = &pool32K
	} else if sizeHint > 32*1024 {
		pool = &pool64K
	} else {
		pool = &pool32K
	}
	bufp := pool.Get().(*[]byte)
	defer pool.Put(bufp)
	return io.CopyBuffer(dst, src, *bufp)
}

func logExchange(logger *slog.Logger, req *http.Request, resp *http.Response, reqBytes int64, respBytes int64, opts RelayOptions) {
	if req == nil {
		return
	}
	targetLogger := logger
	if opts.AccessLogger != nil {
		targetLogger = opts.AccessLogger
	}
	if targetLogger == nil {
		return
	}

	path := ""
	if req.URL != nil {
		path = req.URL.RequestURI()
	}
	if path == "" {
		path = "/"
	}

	// Track transferred bytes metrics safely (Prometheus counters must be strictly monotonic, never add negative values)
	if reqBytes > 0 {
		BytesTransferred.WithLabelValues("in").Add(float64(reqBytes))
	}
	if respBytes > 0 {
		BytesTransferred.WithLabelValues("out").Add(float64(respBytes))
	}

	var policyLog bool
	var matchType, listName, matchVal string

	if opts.Policy != nil {
		host := req.Host
		if host == "" && req.URL != nil {
			host = req.URL.Host
		}
		var suppressed bool
		policyLog, suppressed, matchType, listName, matchVal = opts.Policy.EvaluateLogging(host, req, "https")
		if suppressed {
			// Suppressed by exceptionlog* lists: skip exchange log completely
			return
		}
	}

	if pm, ok := req.Context().Value(LogPhraseCtxKey{}).(LogPhraseMatch); ok {
		if pm.Suppressed {
			// Suppressed by exceptionlogphraselist: skip exchange log completely
			return
		}
		if pm.Matched && !policyLog {
			policyLog = true
			matchType = pm.MatchType
			listName = "logphraselist"
			matchVal = pm.Value
		}
	}

	attrs := []slog.Attr{
		slog.String("method", req.Method),
		slog.String("host", req.Host),
		slog.String("path", path),
		slog.Int64("req_bytes", reqBytes),
	}
	if resp != nil {
		attrs = append(attrs, slog.Int("status", resp.StatusCode))
		attrs = append(attrs, slog.Int64("resp_bytes", respBytes))
	}
	if policyLog {
		attrs = append(attrs, slog.Bool("policy_log", true))
		attrs = append(attrs, slog.String("policy_match_type", matchType))
		attrs = append(attrs, slog.String("policy_list", listName))
		attrs = append(attrs, slog.String("policy_value", matchVal))

		// Record rule hit metric
		RuleHits.WithLabelValues("default", listName, "log").Inc()
	}

	targetLogger.LogAttrs(context.Background(), slog.LevelInfo, "exchange", attrs...)

	if policyLog && listName != "" && len(opts.AlertCategories) > 0 && opts.AlertCategories[listName] {
		AlertsTotal.WithLabelValues(listName).Inc()
		if opts.AlertLogger != nil {
			opts.AlertLogger.LogAttrs(context.Background(), slog.LevelInfo, "exchange", attrs...)
		}
	}
}

func logExchangeBlocked(logger *slog.Logger, req *http.Request, decision PolicyDecision, opts RelayOptions) {
	if req == nil {
		return
	}
	targetLogger := logger
	if opts.AccessLogger != nil {
		targetLogger = opts.AccessLogger
	}
	if targetLogger == nil {
		return
	}

	path := ""
	if req.URL != nil {
		path = req.URL.RequestURI()
	}
	if path == "" {
		path = "/"
	}

	attrs := []slog.Attr{
		slog.String("method", req.Method),
		slog.String("host", req.Host),
		slog.String("path", path),
		slog.Int("status", http.StatusForbidden),
		slog.Bool("policy_blocked", true),
		slog.String("policy_match_type", decision.MatchType),
		slog.String("policy_value", decision.Value),
		slog.String("profile", "default"),
	}

	targetLogger.LogAttrs(context.Background(), slog.LevelInfo, "exchange", attrs...)

	if decision.MatchType != "" && len(opts.AlertCategories) > 0 && opts.AlertCategories[decision.MatchType] {
		AlertsTotal.WithLabelValues(decision.MatchType).Inc()
		if opts.AlertLogger != nil {
			opts.AlertLogger.LogAttrs(context.Background(), slog.LevelInfo, "exchange", attrs...)
		}
	}
}

// ---------- Cleartext dumping (Phase 1: Blue-Team capture) ----------

type dumpEntry struct {
	Timestamp                    string            `json:"ts"`
	ExchangeID                   string            `json:"xid"`
	Direction                    string            `json:"dir"` // "req" | "resp"
	Method                       string            `json:"method,omitempty"`
	Host                         string            `json:"host,omitempty"`
	Path                         string            `json:"path,omitempty"`
	Status                       int               `json:"status,omitempty"`
	ContentType                  string            `json:"content_type,omitempty"`
	Encoding                     string            `json:"content_encoding,omitempty"`
	Headers                      map[string]string `json:"headers,omitempty"`
	Body                         string            `json:"body,omitempty"`
	BodyB64                      bool              `json:"body_b64,omitempty"`
	BodyBytes                    int               `json:"body_bytes"`
	Truncated                    bool              `json:"truncated,omitempty"`
	Skipped                      string            `json:"skipped,omitempty"`
	ContainsCleartextCredentials bool              `json:"contains_cleartext_credentials,omitempty"`
	ClientIP                     string            `json:"client_ip,omitempty"`
	ClientDevice                 string            `json:"client_device,omitempty"`
	User                         string            `json:"user,omitempty"`
	PolicyAction                 string            `json:"policy_action,omitempty"`
	PolicyList                   string            `json:"policy_list,omitempty"`
	BodyHash                     string            `json:"body_hash,omitempty"`
}

type dumpTask struct {
	line   []byte
	opts   RelayOptions
	logger *slog.Logger
}

type ForensicDumper struct {
	opts     RelayOptions
	dumpChan chan dumpTask
	wg       sync.WaitGroup
	ctx      context.Context
	cancel   context.CancelFunc
}

func newForensicDumper(opts RelayOptions) (*ForensicDumper, error) {
	ctx, cancel := context.WithCancel(context.Background())
	d := &ForensicDumper{
		opts:     opts,
		dumpChan: make(chan dumpTask, 4096),
		ctx:      ctx,
		cancel:   cancel,
	}
	d.wg.Add(1)
	go d.asyncDumpLoop()
	return d, nil
}

func (d *ForensicDumper) Close() {
	d.cancel()
	d.wg.Wait()
}

var (
	globalDumper   atomic.Pointer[ForensicDumper]
	globalDumperMu sync.Mutex
	exchangeSeq    atomic.Uint64
)

func newExchangeID() string {
	return fmt.Sprintf("%x-%x", time.Now().UnixNano(), exchangeSeq.Add(1))
}

func initDumper(opts RelayOptions) error {
	if globalDumper.Load() != nil {
		return nil
	}

	globalDumperMu.Lock()
	defer globalDumperMu.Unlock()

	if globalDumper.Load() != nil {
		return nil
	}

	d, err := newForensicDumper(opts)
	if err != nil {
		return err
	}
	globalDumper.Store(d)
	return nil
}

var (
	jsonKeyRegex = regexp.MustCompile(`(?i)"(password|token|api_key|secret|client_secret)"\s*:\s*"[^"]*"`)
	formKeyRegex = regexp.MustCompile(`(?i)(password|token|api_key|secret|client_secret)=[^&]*`)
	jwtRegex     = regexp.MustCompile(`eyJ[a-zA-Z0-9_-]{2,}\.[a-zA-Z0-9_-]{2,}\.[a-zA-Z0-9_-]{2,}`)
)

func hmacString(key, val string) string {
	if key == "" {
		return "[REDACTED]"
	}
	h := hmac.New(sha256.New, []byte(key))
	h.Write([]byte(val))
	return "[REDACTED:HMAC-" + hex.EncodeToString(h.Sum(nil)) + "]"
}

func redactHeaders(h map[string]string, auditKey string, dumpCleartext bool) map[string]string {
	if h == nil {
		return nil
	}
	if dumpCleartext {
		return h
	}
	out := make(map[string]string, len(h))
	for k, v := range h {
		kl := strings.ToLower(k)
		if kl == "authorization" || kl == "cookie" || kl == "set-cookie" || kl == "proxy-authorization" {
			out[k] = hmacString(auditKey, v)
		} else {
			out[k] = v
		}
	}
	return out
}

func redactBody(body string, contentType string, auditKey string, dumpCleartext bool) string {
	if body == "" {
		return ""
	}
	if dumpCleartext {
		return body
	}
	mt := strings.ToLower(strings.TrimSpace(strings.SplitN(contentType, ";", 2)[0]))

	// Redact JWTs everywhere
	body = jwtRegex.ReplaceAllStringFunc(body, func(match string) string {
		return hmacString(auditKey, match)
	})

	if strings.Contains(mt, "json") {
		body = jsonKeyRegex.ReplaceAllStringFunc(body, func(match string) string {
			parts := strings.SplitN(match, ":", 2)
			if len(parts) == 2 {
				val := strings.Trim(parts[1], ` "`)
				return parts[0] + `: "` + hmacString(auditKey, val) + `"`
			}
			return match
		})
	} else if mt == "application/x-www-form-urlencoded" {
		body = formKeyRegex.ReplaceAllStringFunc(body, func(match string) string {
			parts := strings.SplitN(match, "=", 2)
			if len(parts) == 2 {
				return parts[0] + "=" + hmacString(auditKey, parts[1])
			}
			return match
		})
	}

	// General fallback: if it contains any sensitive keywords, redact them in plain text key=val/key:val patterns
	body = regexp.MustCompile(`(?i)(password|token|api_key|secret|client_secret)([:=])\s*([^\s"&']+)`).ReplaceAllStringFunc(body, func(match string) string {
		sep := ":"
		if strings.Contains(match, "=") {
			sep = "="
		}
		parts := strings.SplitN(match, sep, 2)
		if len(parts) == 2 {
			return parts[0] + sep + hmacString(auditKey, parts[1])
		}
		return match
	})

	return body
}

// emitDump writes one JSONL record describing a request or response. Failures
// are logged but never propagate: an inspection sidecar must not break relay.
func emitDump(opts RelayOptions, direction, xid string, req *http.Request, resp *http.Response, raw []byte, truncated bool, skipped string, policyAction string, logger *slog.Logger) {
	if isDiskSpaceLow(opts.DumpDir, opts.DumpMinFreeSpaceMB) {
		if skipped == "" {
			skipped = "low disk space warning"
		}
	}

	entry := dumpEntry{
		Timestamp:  time.Now().UTC().Format(time.RFC3339Nano),
		ExchangeID: xid,
		Direction:  direction,
		Truncated:  truncated,
		Skipped:    skipped,
	}
	if req != nil {
		entry.Method = req.Method
		entry.Host = req.Host
		if req.URL != nil {
			entry.Path = req.URL.RequestURI()
		}

		// Client IP
		ip, _, err := net.SplitHostPort(req.RemoteAddr)
		if err == nil {
			entry.ClientIP = ip
		} else {
			entry.ClientIP = req.RemoteAddr
		}

		// Client Device (User-Agent)
		entry.ClientDevice = req.Header.Get("User-Agent")

		// Authenticated User
		user := req.Header.Get("X-User")
		if user == "" {
			user = req.Header.Get("X-Forwarded-User")
		}
		if user == "" {
			user = req.Header.Get("X-Auth-Username")
		}
		if user == "" {
			if auth := req.Header.Get("Proxy-Authorization"); strings.HasPrefix(strings.ToLower(auth), "basic ") {
				payload, err := base64.StdEncoding.DecodeString(auth[6:])
				if err == nil {
					pair := strings.SplitN(string(payload), ":", 2)
					if len(pair) > 0 {
						user = pair[0]
					}
				}
			}
		}
		entry.User = user
	}
	entry.PolicyAction = policyAction
	if opts.Policy != nil && req != nil {
		host := req.Host
		if req.URL != nil && req.URL.Hostname() != "" {
			host = req.URL.Hostname()
		}
		scheme := "http"
		if req.TLS != nil {
			scheme = "https"
		}
		_, _, _, listName, _ := opts.Policy.EvaluateLogging(host, req, scheme)
		entry.PolicyList = listName
	}
	if entry.PolicyList == "" && req != nil {
		if pm, ok := req.Context().Value(LogPhraseCtxKey{}).(LogPhraseMatch); ok && pm.Matched {
			entry.PolicyList = "logphraselist"
		}
	}
	entry.ContainsCleartextCredentials = opts.DumpCredentialsCleartext

	var headers http.Header
	switch direction {
	case "req":
		if req != nil {
			headers = req.Header
		}
	case "resp":
		if resp != nil {
			entry.Status = resp.StatusCode
			headers = resp.Header
		}
	}
	if headers != nil {
		entry.Headers = redactHeaders(flattenHeaders(headers), opts.AuditKey, opts.DumpCredentialsCleartext)
		entry.ContentType = headers.Get("Content-Type")
		entry.Encoding = headers.Get("Content-Encoding")
	}

	if len(raw) > 0 {
		h := sha256.New()
		h.Write(raw)
		entry.BodyHash = hex.EncodeToString(h.Sum(nil))

		if entry.Skipped != "" {
			entry.BodyBytes = len(raw)
		} else if !isTextualContentType(entry.ContentType) {
			if entry.Skipped == "" {
				entry.Skipped = "non-textual content-type"
			}
			entry.BodyBytes = len(raw)
		} else {
			decoded, err := decompressBody(raw, entry.Encoding)
			if err != nil {
				if entry.Skipped == "" {
					entry.Skipped = "decompress error: " + err.Error()
				}
				decoded = raw
			}
			if utf8.Valid(decoded) {
				entry.Body = redactBody(string(decoded), entry.ContentType, opts.AuditKey, opts.DumpCredentialsCleartext)
			} else {
				entry.Body = base64.StdEncoding.EncodeToString(decoded)
				entry.BodyB64 = true
			}
			entry.BodyBytes = len(decoded)
		}
	}

	writeDumpLine(opts, &entry, logger)
}

func writeDumpLine(opts RelayOptions, entry *dumpEntry, logger *slog.Logger) {
	if err := initDumper(opts); err != nil {
		if logger != nil {
			logger.Error("dump open failed", slog.Any("error", err))
		}
		return
	}
	line, err := json.Marshal(entry)
	if err != nil {
		if logger != nil {
			logger.Error("dump marshal failed", slog.Any("error", err))
		}
		return
	}
	line = append(line, '\n')

	d := globalDumper.Load()
	if d != nil {
		select {
		case d.dumpChan <- dumpTask{line: line, opts: opts, logger: logger}:
		default:
			if logger != nil {
				logger.Warn("dump channel full, dropping record", slog.String("xid", entry.ExchangeID))
			}
		}
	}
}

func isDiskSpaceLow(dir string, thresholdMB int64) bool {
	if thresholdMB <= 0 {
		return false
	}
	checkDir := dir
	for {
		_, err := os.Stat(checkDir)
		if err == nil {
			break
		}
		parent := filepath.Dir(checkDir)
		if parent == checkDir {
			break
		}
		checkDir = parent
	}
	var stat syscall.Statfs_t
	if err := syscall.Statfs(checkDir, &stat); err != nil {
		return false
	}
	freeBytes := uint64(stat.Bavail) * uint64(stat.Bsize)
	freeMB := int64(freeBytes / (1024 * 1024))
	return freeMB < thresholdMB
}

func compressFileGzip(srcPath string) error {
	src, err := os.Open(srcPath)
	if err != nil {
		return err
	}
	defer src.Close()

	destPath := srcPath + ".gz"
	dest, err := os.OpenFile(destPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	defer dest.Close()

	gw := gzip.NewWriter(dest)
	defer gw.Close()

	_, err = io.Copy(gw, src)
	return err
}

func sortStrings(slice []string) {
	for i := 0; i < len(slice); i++ {
		for j := i + 1; j < len(slice); j++ {
			if slice[i] > slice[j] {
				slice[i], slice[j] = slice[j], slice[i]
			}
		}
	}
}

func (d *ForensicDumper) rotateDumpFiles(oldPath string, logger *slog.Logger) {
	opts := d.opts
	if oldPath == "" {
		return
	}

	if opts.DumpCompress {
		go func(path string) {
			if err := compressFileGzip(path); err != nil {
				if logger != nil {
					logger.Error("dump file compression failed", slog.String("path", path), slog.Any("error", err))
				}
			} else {
				_ = os.Remove(path)
			}
		}(oldPath)
	}

	if opts.DumpMaxBackups > 0 {
		files, err := os.ReadDir(opts.DumpDir)
		if err != nil {
			return
		}
		var dumpFiles []string
		for _, f := range files {
			if f.IsDir() {
				continue
			}
			name := f.Name()
			if strings.HasPrefix(name, "dump_") && (strings.HasSuffix(name, ".jsonl") || strings.HasSuffix(name, ".jsonl.gz")) {
				dumpFiles = append(dumpFiles, filepath.Join(opts.DumpDir, name))
			}
		}

		sortStrings(dumpFiles)

		if len(dumpFiles) > opts.DumpMaxBackups {
			excess := len(dumpFiles) - opts.DumpMaxBackups
			for i := 0; i < excess; i++ {
				_ = os.Remove(dumpFiles[i])
			}
		}
	}
}

func (d *ForensicDumper) asyncDumpLoop() {
	defer d.wg.Done()

	var dumpFile *os.File
	var currentPath string
	var bw *bufio.Writer
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	var lastWarnedTime time.Time

	defer func() {
		if bw != nil {
			_ = bw.Flush()
		}
		if dumpFile != nil {
			_ = dumpFile.Close()
		}
	}()

	for {
		select {
		case <-d.ctx.Done():
			// Drenar de forma no bloqueante todas las tareas pendientes del canal
			for {
				select {
				case task := <-d.dumpChan:
					d.processTask(&dumpFile, &currentPath, &bw, task, &lastWarnedTime)
				default:
					return
				}
			}

		case task := <-d.dumpChan:
			d.processTask(&dumpFile, &currentPath, &bw, task, &lastWarnedTime)

		case <-ticker.C:
			if bw != nil {
				_ = bw.Flush()
			}
		}
	}
}

func (d *ForensicDumper) processTask(
	dumpFile **os.File,
	currentPath *string,
	bw **bufio.Writer,
	task dumpTask,
	lastWarnedTime *time.Time,
) {
	opts := d.opts

	// Check disk space threshold
	if isDiskSpaceLow(opts.DumpDir, opts.DumpMinFreeSpaceMB) {
		if time.Since(*lastWarnedTime) > 5*time.Second {
			if task.logger != nil {
				task.logger.Warn("forensic log dump skipped: low disk space on target partition",
					slog.String("dir", opts.DumpDir),
					slog.Int64("min_free_mb", opts.DumpMinFreeSpaceMB))
			}
			*lastWarnedTime = time.Now()
		}
		return
	}

	// Lazy initialization of active dump file
	if *dumpFile == nil {
		if err := os.MkdirAll(opts.DumpDir, 0o700); err != nil {
			if task.logger != nil {
				task.logger.Error("failed to create dump directory", slog.Any("error", err))
			}
			return
		}
		path := filepath.Join(opts.DumpDir, fmt.Sprintf("dump_%d.jsonl", time.Now().UnixNano()))
		f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
		if err != nil {
			if task.logger != nil {
				task.logger.Error("failed to lazily open dump file", slog.Any("error", err))
			}
			return
		}
		*dumpFile = f
		*currentPath = path
		*bw = bufio.NewWriterSize(*dumpFile, 64*1024)
	} else {
		// Check file size rotation
		fi, err := (*dumpFile).Stat()
		if err == nil && fi.Size() >= int64(opts.DumpMaxSizeMB)*1024*1024 {
			if *bw != nil {
				_ = (*bw).Flush()
			}
			_ = (*dumpFile).Close()

			d.rotateDumpFiles(*currentPath, task.logger)

			newPath := filepath.Join(opts.DumpDir, fmt.Sprintf("dump_%d.jsonl", time.Now().UnixNano()))
			f, err := os.OpenFile(newPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
			if err == nil {
				*dumpFile = f
				*currentPath = newPath
				*bw = bufio.NewWriterSize(*dumpFile, 64*1024)
			} else {
				*dumpFile = nil
				*currentPath = ""
				*bw = nil
				if task.logger != nil {
					task.logger.Error("failed to create new dump file after rotation", slog.Any("error", err))
				}
			}
		}
	}

	if *dumpFile != nil && *bw != nil {
		_, _ = (*bw).Write(task.line)
		if (*bw).Available() < 4096 {
			_ = (*bw).Flush()
		}
	}
}

func flattenHeaders(h http.Header) map[string]string {
	out := make(map[string]string, len(h))
	for k, v := range h {
		out[k] = strings.Join(v, ", ")
	}
	return out
}

// isTextualContentType decides if a payload should be dumped as cleartext.
// Empty Content-Type is treated as textual: many gRPC-Web/JSON RPCs omit it
// or use uncommon variants and we'd rather err on the side of capturing.
//
// Heuristic: anything text/*, anything whose media type contains "json" or
// "xml" (catches application/json+protobuf used by Google AI Studio,
// application/vnd.api+json, application/json, application/xml, …), plus an
// explicit allowlist for known textual containers.
func isTextualContentType(ct string) bool {
	if ct == "" {
		return true
	}
	mt := strings.ToLower(strings.TrimSpace(strings.SplitN(ct, ";", 2)[0]))
	if strings.HasPrefix(mt, "text/") {
		return true
	}
	if strings.Contains(mt, "json") || strings.Contains(mt, "xml") {
		return true
	}
	switch mt {
	case "application/javascript",
		"application/x-javascript",
		"application/ecmascript",
		"application/x-www-form-urlencoded",
		"application/grpc-web-text",
		"application/x-ndjson":
		return true
	}
	return false
}

// decompressBody undoes the Content-Encoding wrapper (gzip / x-gzip / deflate /
// br). identity / "" pass through untouched.
func decompressBody(data []byte, encoding string) ([]byte, error) {
	encoding = strings.ToLower(strings.TrimSpace(encoding))
	switch encoding {
	case "", "identity":
		return data, nil
	case "gzip", "x-gzip":
		r, err := gzip.NewReader(bytes.NewReader(data))
		if err != nil {
			return nil, fmt.Errorf("gzip: %w", err)
		}
		defer r.Close()
		return copyDecodedBody(r, "gzip read")
	case "deflate":
		r := flate.NewReader(bytes.NewReader(data))
		defer r.Close()
		return copyDecodedBody(r, "deflate")
	case "br":
		r := newBrotliReader(bytes.NewReader(data))
		defer r.Close()
		return copyDecodedBody(r, "brotli")
	case "zstd":
		r, err := zstd.NewReader(bytes.NewReader(data))
		if err != nil {
			return nil, fmt.Errorf("zstd: %w", err)
		}
		defer r.Close()
		return copyDecodedBody(r, "zstd")
	}
	return nil, fmt.Errorf("unsupported encoding %q", encoding)
}

func copyDecodedBody(r io.Reader, label string) ([]byte, error) {
	var out bytes.Buffer
	if _, err := copyBufferPooled(&out, r); err != nil {
		return nil, fmt.Errorf("%s: %w", label, err)
	}
	return out.Bytes(), nil
}

type benignError struct {
	err error
}

func (e benignError) Error() string {
	if e.err != nil {
		return e.err.Error()
	}
	return "benign connection closed"
}

func (e benignError) Unwrap() error {
	return e.err
}

func (e benignError) Benign() bool {
	return true
}

func isBenignRelayError(err error, bytesWritten int64, contentLength int64, resp *http.Response) bool {
	if err == nil {
		return false
	}
	errStr := err.Error()
	isBrokenPipe := strings.Contains(errStr, "broken pipe") ||
		strings.Contains(errStr, "connection reset by peer") ||
		strings.Contains(errStr, "i/o timeout") ||
		errors.Is(err, syscall.EPIPE) ||
		errors.Is(err, syscall.ECONNRESET)

	if !isBrokenPipe {
		return false
	}

	if contentLength >= 0 && bytesWritten >= contentLength {
		return true
	}

	if contentLength == 0 || resp.StatusCode == http.StatusNoContent || resp.StatusCode == http.StatusNotModified {
		return true
	}

	return false
}

func isHostH2(h2Hosts *sync.Map, host string) bool {
	if h2Hosts == nil {
		return false
	}
	val, ok := h2Hosts.Load(host)
	if !ok {
		return false
	}
	return val.(bool)
}

func redirectResponse(targetURL string) string {
	return fmt.Sprintf("HTTP/1.1 302 Found\r\nLocation: %s\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", targetURL)
}
