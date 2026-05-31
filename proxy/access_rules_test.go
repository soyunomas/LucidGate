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

func TestAccessRulesBannedAndExceptions(t *testing.T) {
	rules, err := NewAccessRules([]AccessProfile{
		{Name: "students", Clients: []string{"192.0.2.0/24"}},
		{Name: "default", Default: true},
	})
	if err != nil {
		t.Fatalf("NewAccessRules() error = %v", err)
	}

	// Ban 192.0.2.55 and 10.0.0.0/8
	err = rules.SetBanned([]string{"192.0.2.55", "10.0.0.0/8"})
	if err != nil {
		t.Fatalf("SetBanned() error = %v", err)
	}

	// Except 10.0.0.5
	err = rules.SetExceptions([]string{"10.0.0.5"})
	if err != nil {
		t.Fatalf("SetExceptions() error = %v", err)
	}

	tests := []struct {
		remoteAddr string
		profile    string
		allowed    bool
	}{
		{"192.0.2.1:50000", "students", true},    // Normal allowed
		{"192.0.2.55:50000", "", false},          // Banned IP
		{"10.0.0.1:50000", "", false},            // Banned subnet
		{"10.0.0.5:50000", "default", true},      // Excepted IP (passes through to default)
		{"198.51.100.10:50000", "default", true}, // Normal default fallback
	}

	for _, tt := range tests {
		profile, allowed := rules.ProfileForRemoteAddr(tt.remoteAddr)
		if allowed != tt.allowed || profile != tt.profile {
			t.Errorf("ProfileForRemoteAddr(%q) = %q/%t, want %q/%t", tt.remoteAddr, profile, allowed, tt.profile, tt.allowed)
		}
	}

	// Check invalid formatting errors
	if err = rules.SetBanned([]string{"invalid"}); err == nil {
		t.Error("SetBanned(invalid) want error, got nil")
	}
	if err = rules.SetExceptions([]string{"invalid"}); err == nil {
		t.Error("SetExceptions(invalid) want error, got nil")
	}
}
