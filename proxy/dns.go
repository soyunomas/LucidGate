package proxy

import (
	"context"
	"net"
	"sync"
	"time"
)

type dnsEntry struct {
	ips       []net.IP
	expiresAt time.Time
}

type ipLookupResolver interface {
	LookupIP(ctx context.Context, network, host string) ([]net.IP, error)
}

type DNSResolver struct {
	cache    sync.Map
	enabled  bool
	ttl      time.Duration
	resolver ipLookupResolver
}

func NewDNSResolver(enabled bool, ttl time.Duration) *DNSResolver {
	return &DNSResolver{
		enabled:  enabled,
		ttl:      ttl,
		resolver: net.DefaultResolver,
	}
}

func (r *DNSResolver) Resolve(ctx context.Context, host string) (string, error) {
	if !r.enabled || r.ttl <= 0 {
		return host, nil
	}

	// If host is already a raw IP (IPv4 or IPv6), bypass resolution
	if ip := net.ParseIP(host); ip != nil {
		return host, nil
	}

	now := time.Now()
	if val, ok := r.cache.Load(host); ok {
		entry := val.(*dnsEntry)
		if now.Before(entry.expiresAt) {
			return entry.ips[0].String(), nil
		}
	}

	ips, err := r.resolver.LookupIP(ctx, "ip", host)
	if err != nil {
		return "", err
	}
	if len(ips) == 0 {
		return "", &net.DNSError{Err: "no IP addresses found", Name: host}
	}

	r.cache.Store(host, &dnsEntry{
		ips:       ips,
		expiresAt: now.Add(r.ttl),
	})

	return ips[0].String(), nil
}

func (r *DNSResolver) ResolveAddr(ctx context.Context, address string) (string, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		// Just a hostname
		return r.Resolve(ctx, address)
	}
	resolvedHost, err := r.Resolve(ctx, host)
	if err != nil {
		return "", err
	}
	return net.JoinHostPort(resolvedHost, port), nil
}
