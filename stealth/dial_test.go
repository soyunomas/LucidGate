package stealth

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"testing"
	"time"

	"lucidgate/pki"

	utls "github.com/refraction-networking/utls"
)

func TestDialFirefoxHandshakesWithLocalTLSServer(t *testing.T) {
	ca, err := pki.GenerateRootCA(time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("GenerateRootCA() error = %v", err)
	}
	leaf, err := pki.GenerateLeafCert("localhost", ca.Certificate, ca.PrivateKey)
	if err != nil {
		t.Fatalf("GenerateLeafCert() error = %v", err)
	}

	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{*leaf},
		MinVersion:   tls.VersionTLS12,
	})
	if err != nil {
		t.Fatalf("tls.Listen() error = %v", err)
	}
	defer ln.Close()

	serverErr := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			serverErr <- err
			return
		}
		defer conn.Close()
		serverErr <- conn.(*tls.Conn).Handshake()
	}()

	roots := x509.NewCertPool()
	roots.AddCert(ca.Certificate)
	conn, err := Dialer{
		Timeout: 2 * time.Second,
		Config:  &utls.Config{RootCAs: roots},
	}.DialFirefox(context.Background(), ln.Addr().String(), "localhost")
	if err != nil {
		t.Fatalf("DialFirefox() error = %v", err)
	}
	defer conn.Close()

	select {
	case err := <-serverErr:
		if err != nil {
			t.Fatalf("server handshake error = %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("server did not complete TLS handshake")
	}
}

func TestDialFirefoxDefaultsToHTTP1ALPN(t *testing.T) {
	ca, err := pki.GenerateRootCA(time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("GenerateRootCA() error = %v", err)
	}
	leaf, err := pki.GenerateLeafCert("localhost", ca.Certificate, ca.PrivateKey)
	if err != nil {
		t.Fatalf("GenerateLeafCert() error = %v", err)
	}

	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{*leaf},
		NextProtos:   []string{"h2", "http/1.1"},
		MinVersion:   tls.VersionTLS12,
	})
	if err != nil {
		t.Fatalf("tls.Listen() error = %v", err)
	}
	defer ln.Close()

	negotiated := make(chan string, 1)
	serverErr := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			serverErr <- err
			return
		}
		defer conn.Close()
		tlsConn := conn.(*tls.Conn)
		if err := tlsConn.Handshake(); err != nil {
			serverErr <- err
			return
		}
		negotiated <- tlsConn.ConnectionState().NegotiatedProtocol
		serverErr <- nil
	}()

	roots := x509.NewCertPool()
	roots.AddCert(ca.Certificate)
	conn, err := Dialer{
		Timeout: 2 * time.Second,
		Config:  &utls.Config{RootCAs: roots},
	}.DialFirefox(context.Background(), ln.Addr().String(), "localhost")
	if err != nil {
		t.Fatalf("DialFirefox() error = %v", err)
	}
	defer conn.Close()

	select {
	case proto := <-negotiated:
		if proto != "http/1.1" {
			t.Fatalf("NegotiatedProtocol = %q, want http/1.1", proto)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("server did not report negotiated protocol")
	}
	if err := <-serverErr; err != nil {
		t.Fatalf("server handshake error = %v", err)
	}
}

func TestDialFirefoxResumesSessionAcrossDials(t *testing.T) {
	ca, err := pki.GenerateRootCA(time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("GenerateRootCA() error = %v", err)
	}
	leaf, err := pki.GenerateLeafCert("localhost", ca.Certificate, ca.PrivateKey)
	if err != nil {
		t.Fatalf("GenerateLeafCert() error = %v", err)
	}

	// Server pinned to TLS 1.3 so resumption uses PSK (the very codepath the
	// uTLS spec patch enables); session tickets must be enabled.
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates:           []tls.Certificate{*leaf},
		MinVersion:             tls.VersionTLS13,
		MaxVersion:             tls.VersionTLS13,
		SessionTicketsDisabled: false,
	})
	if err != nil {
		t.Fatalf("tls.Listen() error = %v", err)
	}
	defer ln.Close()

	serverDone := make(chan error, 2)
	go func() {
		for i := 0; i < 2; i++ {
			conn, err := ln.Accept()
			if err != nil {
				serverDone <- err
				return
			}
			tlsConn := conn.(*tls.Conn)
			if err := tlsConn.Handshake(); err != nil {
				_ = conn.Close()
				serverDone <- err
				return
			}
			// Drive a token byte both directions so the TLS 1.3
			// NewSessionTicket post-handshake message is actually
			// delivered before either side closes.
			if _, err := tlsConn.Write([]byte{0xAA}); err != nil {
				_ = conn.Close()
				serverDone <- err
				return
			}
			buf := make([]byte, 1)
			_, _ = tlsConn.Read(buf)
			_ = conn.Close()
			serverDone <- nil
		}
	}()

	roots := x509.NewCertPool()
	roots.AddCert(ca.Certificate)
	// Caller-owned cache so the test is hermetic and does not interact with
	// the package-level upstreamSessionCache used in production.
	cache := utls.NewLRUClientSessionCache(8)
	cfg := &utls.Config{
		RootCAs:            roots,
		ClientSessionCache: cache,
	}

	dial := func() *utls.UConn {
		conn, err := Dialer{Timeout: 2 * time.Second, Config: cfg}.
			DialFirefox(context.Background(), ln.Addr().String(), "localhost")
		if err != nil {
			t.Fatalf("DialFirefox() error = %v", err)
		}
		buf := make([]byte, 1)
		if _, err := conn.Read(buf); err != nil {
			t.Fatalf("read server token = %v", err)
		}
		if _, err := conn.Write([]byte{0x55}); err != nil {
			t.Fatalf("write client token = %v", err)
		}
		return conn
	}

	first := dial()
	if first.ConnectionState().DidResume {
		t.Fatalf("first dial unexpectedly resumed")
	}
	_ = first.Close()
	if err := <-serverDone; err != nil {
		t.Fatalf("first server handshake error = %v", err)
	}

	second := dial()
	defer second.Close()
	if !second.ConnectionState().DidResume {
		t.Fatalf("second dial did not resume; UtlsPreSharedKeyExtension regression")
	}
	if err := <-serverDone; err != nil {
		t.Fatalf("second server handshake error = %v", err)
	}
}

func TestDialFirefoxClosesTCPOnHandshakeError(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen() error = %v", err)
	}
	defer ln.Close()

	accepted := make(chan net.Conn, 1)
	go func() {
		conn, err := ln.Accept()
		if err == nil {
			accepted <- conn
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	_, err = Dialer{Timeout: time.Second}.DialFirefox(ctx, ln.Addr().String(), "localhost")
	if err == nil {
		t.Fatal("DialFirefox() error = nil, want handshake failure")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("DialFirefox() error = %v, want context deadline", err)
	}

	select {
	case conn := <-accepted:
		defer conn.Close()
	case <-time.After(time.Second):
		t.Fatal("server did not accept tcp connection")
	}
}
