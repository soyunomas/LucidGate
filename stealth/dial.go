package stealth

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"

	utls "github.com/refraction-networking/utls"
)

const defaultDialTimeout = 10 * time.Second

var upstreamHTTP1ALPN = []string{"http/1.1"}

// upstreamSessionCache is shared across all Dialer instances so that uTLS can
// resume TLS 1.3 sessions (PSK) and TLS 1.2 tickets across reconnects to the
// same upstream host. This cuts both CPU (no full handshake) and RTT (1-RTT
// or 0-RTT instead of 2-RTT). Carrier-class proxies depend on this to avoid
// hammering busy CDNs with full handshakes on every reconnect.
var upstreamSessionCache = utls.NewLRUClientSessionCache(8192)

// upstreamKeepAlive controls the TCP keep-alive probe interval for upstream
// connections. Without this, half-open connections accumulate as zombie FDs.
const upstreamKeepAlive = 30 * time.Second

type Dialer struct {
	Timeout                time.Duration
	Config                 *utls.Config
	InsecureSkipVerifyFunc func(address, serverName string) bool
}

func DialFirefox(ctx context.Context, address, serverName string) (*utls.UConn, error) {
	return Dialer{}.DialFirefox(ctx, address, serverName)
}

func (d Dialer) Dial(ctx context.Context, address, serverName string) (net.Conn, error) {
	return d.DialFirefox(ctx, address, serverName)
}

func (d Dialer) DialFirefox(ctx context.Context, address, serverName string) (*utls.UConn, error) {
	if address == "" {
		return nil, errors.New("empty upstream address")
	}
	if serverName == "" {
		return nil, errors.New("empty upstream server name")
	}
	timeout := d.Timeout
	if timeout <= 0 {
		timeout = defaultDialTimeout
	}

	dialer := net.Dialer{Timeout: timeout, KeepAlive: upstreamKeepAlive}
	tcpConn, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return nil, fmt.Errorf("dial upstream tcp: %w", err)
	}
	ok := false
	defer func() {
		if !ok {
			_ = tcpConn.Close()
		}
	}()

	if err := tcpConn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return nil, fmt.Errorf("set upstream deadline: %w", err)
	}

	config := &utls.Config{}
	if d.Config != nil {
		config = d.Config.Clone()
	}
	config.ServerName = serverName
	if d.InsecureSkipVerifyFunc != nil && d.InsecureSkipVerifyFunc(address, serverName) {
		config.InsecureSkipVerify = true
	}
	if len(config.NextProtos) == 0 {
		config.NextProtos = upstreamHTTP1ALPN
	}
	if config.ClientSessionCache == nil {
		config.ClientSessionCache = upstreamSessionCache
	}
	// First dials to a new ServerName have no cached session, so the
	// UtlsPreSharedKeyExtension we append to the spec must self-omit instead
	// of aborting the handshake with "empty psk detected".
	config.OmitEmptyPsk = true

	spec, err := firefoxSpecWithALPNAndPSK(config.NextProtos)
	if err != nil {
		return nil, fmt.Errorf("build firefox spec: %w", err)
	}

	tlsConn := utls.UClient(tcpConn, config, utls.HelloCustom)
	if err := tlsConn.ApplyPreset(&spec); err != nil {
		return nil, fmt.Errorf("apply firefox spec: %w", err)
	}
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		return nil, fmt.Errorf("upstream utls handshake: %w", err)
	}
	if err := tcpConn.SetDeadline(time.Time{}); err != nil {
		return nil, fmt.Errorf("clear upstream deadline: %w", err)
	}

	ok = true
	return tlsConn, nil
}

// firefoxHTTP1SpecWithPSK derives a fresh ClientHelloSpec from
// HelloFirefox_120 with two operational tweaks the upstream stack needs:
//
//  1. The ALPN list is reduced to {"http/1.1"} so the upstream never picks
//     HTTP/2 (the relay only speaks HTTP/1.1 today; negotiating h2 here
//     would silently break header/body framing).
//  2. A trailing UtlsPreSharedKeyExtension is appended. The vanilla
//     Firefox_120 parrot includes PSKKeyExchangeModes and SessionTicket but
//     omits the actual pre_shared_key extension, which means TLS 1.3
//     resumption never engages (RFC 8446 §4.2.11 mandates pre_shared_key
//     last). Without this, the shared upstreamSessionCache is dead weight on
//     TLS 1.3 only endpoints (Google, Cloudflare, Fastly) and every reconnect
//     pays a full 2-RTT handshake. The extension is inert when the cache has
//     no session for ServerName, so first dials are unaffected.
//
// The spec is rebuilt per dial because ClientHelloSpec is not safe for
// concurrent mutation by ApplyPreset.
func firefoxSpecWithALPNAndPSK(protocols []string) (utls.ClientHelloSpec, error) {
	spec, err := utls.UTLSIdToSpec(utls.HelloFirefox_120)
	if err != nil {
		return utls.ClientHelloSpec{}, err
	}
	hasPSK := false
	for _, ext := range spec.Extensions {
		switch e := ext.(type) {
		case *utls.ALPNExtension:
			e.AlpnProtocols = protocols
		case *utls.UtlsPreSharedKeyExtension, *utls.FakePreSharedKeyExtension:
			hasPSK = true
		}
	}
	if !hasPSK {
		spec.Extensions = append(spec.Extensions, &utls.UtlsPreSharedKeyExtension{})
	}
	return spec, nil
}
