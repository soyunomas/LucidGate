package proxy

import "testing"

func TestAccessRulesMatchCIDRsAndDefault(t *testing.T) {
	rules, err := NewAccessRules([]AccessProfile{
		{Name: "students", Clients: []string{"192.0.2.0/24"}},
		{Name: "loopback", Clients: []string{"127.0.0.1"}},
		{Name: "default", Default: true},
	})
	if err != nil {
		t.Fatalf("NewAccessRules() error = %v", err)
	}
	tests := []struct {
		remoteAddr string
		profile    string
		allowed    bool
	}{
		{"192.0.2.55:50000", "students", true},
		{"127.0.0.1:50000", "loopback", true},
		{"198.51.100.10:50000", "default", true},
	}
	for _, tt := range tests {
		profile, allowed := rules.ProfileForRemoteAddr(tt.remoteAddr)
		if allowed != tt.allowed || profile != tt.profile {
			t.Fatalf("ProfileForRemoteAddr(%q) = %q/%t, want %q/%t", tt.remoteAddr, profile, allowed, tt.profile, tt.allowed)
		}
	}
}

func TestAccessRulesDenyWhenNoDefaultMatches(t *testing.T) {
	rules, err := NewAccessRules([]AccessProfile{
		{Name: "students", Clients: []string{"192.0.2.0/24"}},
	})
	if err != nil {
		t.Fatalf("NewAccessRules() error = %v", err)
	}
	if profile, allowed := rules.ProfileForRemoteAddr("198.51.100.10:50000"); allowed || profile != "" {
		t.Fatalf("ProfileForRemoteAddr() = %q/%t, want denied", profile, allowed)
	}
}

func TestAccessRulesRejectInvalidClientCIDR(t *testing.T) {
	_, err := NewAccessRules([]AccessProfile{
		{Name: "bad", Clients: []string{"not a cidr"}},
	})
	if err == nil {
		t.Fatal("NewAccessRules() error = nil, want error")
	}
}
