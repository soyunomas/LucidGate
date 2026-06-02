package proxy

import (
	"net/netip"
	"testing"
)

func TestDomainMatcher(t *testing.T) {
	sites := []string{
		"example.com",
		"google.com",
		"*.github.com",
	}
	m := NewDomainMatcher(sites)

	tests := []struct {
		host  string
		match bool
	}{
		{"example.com", true},
		{"sub.example.com", true},
		{"google.com", true},
		{"mail.google.com", true},
		{"github.com", true},
		{"api.github.com", true},
		{"other.com", false},
	}

	for _, tc := range tests {
		got := m.Match(tc.host)
		if got != tc.match {
			t.Errorf("Match(%q) = %t, want %t", tc.host, got, tc.match)
		}
	}
}

func TestIPMatcher(t *testing.T) {
	prefixes := []string{
		"192.0.2.0/24",
		"203.0.113.42",
	}
	m, err := NewIPMatcher(prefixes)
	if err != nil {
		t.Fatalf("NewIPMatcher() error = %v", err)
	}

	tests := []struct {
		ip    string
		match bool
	}{
		{"192.0.2.1", true},
		{"192.0.2.254", true},
		{"192.0.3.1", false},
		{"203.0.113.42", true},
		{"203.0.113.43", false},
	}

	for _, tc := range tests {
		addr, err := netip.ParseAddr(tc.ip)
		if err != nil {
			t.Fatalf("ParseAddr(%q) error = %v", tc.ip, err)
		}
		got := m.Match(addr)
		if got != tc.match {
			t.Errorf("Match(%q) = %t, want %t", tc.ip, got, tc.match)
		}
	}
}

func TestMITMBypassRespectsGreySSL(t *testing.T) {
	server := NewServer("127.0.0.1:0", nil)

	// Set MITM Bypass for some hosts (they should normally bypass MITM)
	server.SetMITMBypass([]string{"bypass.com", "192.0.2.100"})

	// Verify standard bypass
	if !server.shouldBypassMITM("bypass.com") {
		t.Error("expected bypass.com to bypass MITM")
	}

	// 1. Domain Grey SSL overrides bypass:
	greySites := NewDomainMatcher([]string{"bypass.com"})
	server.SetGreySSLRules(greySites, nil)

	// Since bypass.com is in Grey SSL rules, it should NOT bypass MITM!
	if server.shouldBypassMITM("bypass.com") {
		t.Error("expected bypass.com in Grey SSL to be MITM intercepted (not bypassed)")
	}

	// 2. IP Grey SSL overrides bypass:
	server.SetGreySSLRules(nil, nil) // reset sites
	greyIPs, err := NewIPMatcher([]string{"192.0.2.100"})
	if err != nil {
		t.Fatalf("NewIPMatcher error = %v", err)
	}
	server.SetGreySSLRules(nil, greyIPs)

	if server.shouldBypassMITM("192.0.2.100") {
		t.Error("expected 192.0.2.100 in Grey SSL to be MITM intercepted (not bypassed)")
	}
}
