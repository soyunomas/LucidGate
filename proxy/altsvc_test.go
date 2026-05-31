package proxy

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

func counterValue(t *testing.T, c prometheus.Counter) float64 {
	t.Helper()
	var m dto.Metric
	if err := c.Write(&m); err != nil {
		t.Fatalf("counter write: %v", err)
	}
	if m.Counter == nil {
		return 0
	}
	return m.Counter.GetValue()
}

func TestStripHTTP3AdvertisingRemovesAltSvc(t *testing.T) {
	h := http.Header{}
	h.Set("Content-Type", "text/html")
	h.Add("Alt-Svc", `h3=":443"; ma=2592000`)
	h.Add("Alt-Svc", `h3-29=":443"; ma=2592000`)

	if !stripHTTP3Advertising(h) {
		t.Fatalf("expected strip to report removal")
	}
	if got := h.Get("Alt-Svc"); got != "" {
		t.Fatalf("Alt-Svc still present: %q", got)
	}
	if values := h.Values("Alt-Svc"); len(values) != 0 {
		t.Fatalf("Alt-Svc values still present: %v", values)
	}
	if h.Get("Content-Type") != "text/html" {
		t.Fatalf("unrelated header was clobbered")
	}
}

func TestStripHTTP3AdvertisingRemovesAlternateProtocol(t *testing.T) {
	h := http.Header{}
	h.Set("Alternate-Protocol", "443:quic")
	if !stripHTTP3Advertising(h) {
		t.Fatalf("expected strip to report removal")
	}
	if h.Get("Alternate-Protocol") != "" {
		t.Fatalf("Alternate-Protocol still present")
	}
}

func TestStripHTTP3AdvertisingNoopWhenAbsent(t *testing.T) {
	h := http.Header{}
	h.Set("Content-Type", "text/html")
	if stripHTTP3Advertising(h) {
		t.Fatalf("strip reported removal but no Alt-Svc was present")
	}
	if h.Get("Content-Type") != "text/html" {
		t.Fatalf("unrelated header was clobbered")
	}
}

func TestStripHTTP3AdvertisingHandlesNilHeader(t *testing.T) {
	if stripHTTP3Advertising(nil) {
		t.Fatalf("expected nil header to report no removal")
	}
}

func TestStripHTTP3AdvertisingMatchesCanonicalFormFromReadResponse(t *testing.T) {
	// http.ReadResponse always normalizes header keys to canonical MIME form,
	// so the strip operates on canonical names. Verify the canonical paths
	// are covered for both supported headers.
	h := http.Header{}
	h.Add("alt-svc", `h3=":443"`)       // Add canonicalizes for us.
	h.Add("alternate-protocol", "quic") // Same here.

	if !stripHTTP3Advertising(h) {
		t.Fatalf("expected strip to remove both headers")
	}
	if h.Get("Alt-Svc") != "" || h.Get("Alternate-Protocol") != "" {
		t.Fatalf("headers still present after strip")
	}
}

// TestServeHTTPPlainStripsAltSvcFromUpstream demonstrates that LucidGate
// removes any HTTP/3 advertising header before forwarding the response to the
// client. Without this strip, browsers cache the Alt-Svc value and switch
// subsequent requests for the same origin to QUIC over UDP/443, bypassing the
// HTTP/1.1+HTTP/2 interception proxy entirely.
func TestServeHTTPPlainStripsAltSvcFromUpstream(t *testing.T) {
	upstreamErr := make(chan error, 1)
	server := NewServer("127.0.0.1:0", slog.New(slog.NewTextHandler(io.Discard, nil)))
	server.SetRelayOptions(RelayOptions{
		LogBodies:       true,
		MaxCaptureBytes: 1 << 20,
		IOTimeout:       time.Second,
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
			_, _ = io.Copy(io.Discard, req.Body)
			_ = req.Body.Close()
			// Send a realistic Cloudflare-style HTTP/3 advertisement plus a
			// legacy Alternate-Protocol header. Both must be stripped.
			_, err = io.WriteString(upstreamSide,
				"HTTP/1.1 200 OK\r\n"+
					"Connection: close\r\n"+
					"Content-Type: text/plain\r\n"+
					"Content-Length: 2\r\n"+
					`Alt-Svc: h3=":443"; ma=86400, h3-29=":443"; ma=86400`+"\r\n"+
					"Alternate-Protocol: 443:quic\r\n"+
					"\r\n"+
					"ok")
			upstreamErr <- err
		}()
		return proxySide, nil
	}))

	before := counterValue(t, AltSvcStripped)

	req := httptest.NewRequest(http.MethodGet, "http://example.test/", nil)
	req.RemoteAddr = "127.0.0.1:50000"
	rec := httptest.NewRecorder()
	server.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%q", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("Alt-Svc"); got != "" {
		t.Fatalf("Alt-Svc still present in client response: %q", got)
	}
	if got := rec.Header().Get("Alternate-Protocol"); got != "" {
		t.Fatalf("Alternate-Protocol still present in client response: %q", got)
	}

	after := counterValue(t, AltSvcStripped)
	if after-before != 1 {
		t.Fatalf("AltSvcStripped delta = %v, want 1", after-before)
	}

	select {
	case err := <-upstreamErr:
		if err != nil {
			t.Fatalf("upstream server error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("upstream server did not finish")
	}
}
