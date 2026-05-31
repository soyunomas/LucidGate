package proxy

import "net/http"

// stripHTTP3Advertising removes headers used by browsers to discover HTTP/3
// endpoints for the same origin. Without this strip, Chrome and Firefox cache
// the Alt-Svc value and switch subsequent requests to QUIC over UDP, which the
// LucidGate proxy (HTTP/1.1 + HTTP/2 only) cannot intercept. The strip is the
// proxy-level defense; operators should also block egress UDP/443 at the
// firewall for full coverage.
//
// Headers removed:
//   - Alt-Svc (RFC 7838)
//   - Alternate-Protocol (legacy Chromium)
//
// Returns true if any header was actually present and removed.
func stripHTTP3Advertising(h http.Header) bool {
	if h == nil {
		return false
	}
	removed := false
	for _, name := range []string{"Alt-Svc", "Alternate-Protocol"} {
		if _, ok := h[http.CanonicalHeaderKey(name)]; ok {
			h.Del(name)
			removed = true
		}
	}
	return removed
}
