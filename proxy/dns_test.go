package proxy

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"
)

type mockLookupResolver struct {
	calls int
	ips   []net.IP
	err   error
}

func (m *mockLookupResolver) LookupIP(ctx context.Context, network, host string) ([]net.IP, error) {
	m.calls++
	if m.err != nil {
		return nil, m.err
	}
	return m.ips, nil
}

func TestDNSResolverBypassRawIP(t *testing.T) {
	mock := &mockLookupResolver{ips: []net.IP{net.ParseIP("1.1.1.1")}}
	r := NewDNSResolver(true, 10*time.Second)
	r.resolver = mock

	ctx := context.Background()

	// 1. Raw IPv4 should bypass
	res, err := r.Resolve(ctx, "127.0.0.1")
	if err != nil {
		t.Fatalf("unexpected error resolving raw IP: %v", err)
	}
	if res != "127.0.0.1" {
		t.Fatalf("expected 127.0.0.1, got %s", res)
	}
	if mock.calls != 0 {
		t.Fatalf("mock resolver should not have been called for raw IP")
	}

	// 2. Raw IPv6 should bypass
	res, err = r.Resolve(ctx, "::1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res != "::1" {
		t.Fatalf("expected ::1, got %s", res)
	}
	if mock.calls != 0 {
		t.Fatalf("mock resolver should not have been called")
	}
}

func TestDNSResolverCachingAndTTL(t *testing.T) {
	mock := &mockLookupResolver{ips: []net.IP{net.ParseIP("192.168.1.100")}}
	r := NewDNSResolver(true, 50*time.Millisecond) // Short TTL for testing
	r.resolver = mock

	ctx := context.Background()
	host := "my-local-server.lan"

	// 1. First resolve should trigger actual DNS lookup
	res, err := r.Resolve(ctx, host)
	if err != nil {
		t.Fatalf("resolve failed: %v", err)
	}
	if res != "192.168.1.100" {
		t.Fatalf("unexpected IP: %s", res)
	}
	if mock.calls != 1 {
		t.Fatalf("expected 1 call, got %d", mock.calls)
	}

	// 2. Second resolve within TTL should return cached IP immediately
	res, err = r.Resolve(ctx, host)
	if err != nil {
		t.Fatalf("resolve failed: %v", err)
	}
	if res != "192.168.1.100" {
		t.Fatalf("unexpected IP: %s", res)
	}
	if mock.calls != 1 {
		t.Fatalf("expected cached call to bypass lookup, calls: %d", mock.calls)
	}

	// 3. Wait for TTL to expire (50ms)
	time.Sleep(60 * time.Millisecond)

	// 4. Third resolve after TTL should trigger a new DNS lookup
	mock.ips = []net.IP{net.ParseIP("192.168.1.200")}
	res, err = r.Resolve(ctx, host)
	if err != nil {
		t.Fatalf("resolve failed: %v", err)
	}
	if res != "192.168.1.200" {
		t.Fatalf("unexpected IP: %s", res)
	}
	if mock.calls != 2 {
		t.Fatalf("expected 2 calls after TTL expiration, got %d", mock.calls)
	}
}

func TestDNSResolverResolveAddr(t *testing.T) {
	mock := &mockLookupResolver{ips: []net.IP{net.ParseIP("10.0.0.5")}}
	r := NewDNSResolver(true, 10*time.Second)
	r.resolver = mock

	ctx := context.Background()

	// 1. Resolve host:port
	res, err := r.ResolveAddr(ctx, "internal-service.local:8080")
	if err != nil {
		t.Fatalf("ResolveAddr failed: %v", err)
	}
	if res != "10.0.0.5:8080" {
		t.Fatalf("expected 10.0.0.5:8080, got %s", res)
	}

	// 2. Resolve raw IP:port (should bypass dial calls)
	mock.calls = 0
	res, err = r.ResolveAddr(ctx, "8.8.8.8:53")
	if err != nil {
		t.Fatalf("ResolveAddr failed: %v", err)
	}
	if res != "8.8.8.8:53" {
		t.Fatalf("expected 8.8.8.8:53, got %s", res)
	}
	if mock.calls != 0 {
		t.Fatalf("expected zero calls for raw IP:port")
	}
}

func TestDNSResolverDisabled(t *testing.T) {
	mock := &mockLookupResolver{ips: []net.IP{net.ParseIP("1.1.1.1")}}
	r := NewDNSResolver(false, 10*time.Second) // Disabled
	r.resolver = mock

	ctx := context.Background()
	host := "dns-disabled.com"

	// All resolves should bypass and return the original host without calling the lookup resolver
	for i := 0; i < 3; i++ {
		res, err := r.Resolve(ctx, host)
		if err != nil {
			t.Fatalf("resolve failed: %v", err)
		}
		if res != host {
			t.Fatalf("expected original host %s, got %s", host, res)
		}
		if mock.calls != 0 {
			t.Fatalf("expected zero calls since resolver is disabled")
		}
	}
}

func TestDNSResolverResolveAddrForPolicyCanForceLookup(t *testing.T) {
	mock := &mockLookupResolver{ips: []net.IP{net.ParseIP("203.0.113.10")}}
	r := NewDNSResolver(false, 0)
	r.resolver = mock

	resolvedAddr, resolvedHost, err := r.ResolveAddrForPolicy(context.Background(), "policy.example:443", true)
	if err != nil {
		t.Fatalf("ResolveAddrForPolicy() error = %v", err)
	}
	if resolvedAddr != "203.0.113.10:443" || resolvedHost != "203.0.113.10" {
		t.Fatalf("resolved = %q host=%q, want 203.0.113.10:443 host 203.0.113.10", resolvedAddr, resolvedHost)
	}
	if mock.calls != 1 {
		t.Fatalf("DNS lookups = %d, want 1", mock.calls)
	}
}

func TestDNSResolverError(t *testing.T) {
	mock := &mockLookupResolver{err: errors.New("dns lookup timeout")}
	r := NewDNSResolver(true, 10*time.Second)
	r.resolver = mock

	ctx := context.Background()
	_, err := r.Resolve(ctx, "error-host.com")
	if err == nil {
		t.Fatalf("expected error, got nil")
	}
}
