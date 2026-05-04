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
	Timeout time.Duration
	Config  *utls.Config
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
	if len(config.NextProtos) == 0 {
		config.NextProtos = upstreamHTTP1ALPN
	}
	if config.ClientSessionCache == nil {
		config.ClientSessionCache = upstreamSessionCache
	}

	tlsConn := utls.UClient(tcpConn, config, utls.HelloFirefox_Auto)
	if err := forceHTTP1ALPN(tlsConn); err != nil {
		return nil, fmt.Errorf("force upstream alpn: %w", err)
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

func forceHTTP1ALPN(conn *utls.UConn) error {
	if err := conn.BuildHandshakeState(); err != nil {
		return err
	}
	for _, ext := range conn.Extensions {
		if alpn, ok := ext.(*utls.ALPNExtension); ok {
			alpn.AlpnProtocols = upstreamHTTP1ALPN
			conn.HandshakeState.Hello.AlpnProtocols = upstreamHTTP1ALPN
			return nil
		}
	}
	conn.Extensions = append(conn.Extensions, &utls.ALPNExtension{AlpnProtocols: upstreamHTTP1ALPN})
	conn.HandshakeState.Hello.AlpnProtocols = upstreamHTTP1ALPN
	return nil
}
