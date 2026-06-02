package proxy

import "testing"

func TestDomainRulesBlockRootAndSubdomains(t *testing.T) {
	rules := NewDomainRules([]string{"example.com", ".school.test."})
	for _, host := range []string{
		"example.com",
		"www.example.com",
		"a.b.example.com",
		"school.test.",
		"cdn.school.test",
	} {
		if !rules.Blocked(host) {
			t.Fatalf("Blocked(%q) = false, want true", host)
		}
	}
}

func TestDomainRulesDoNotBlockSuffixLookalikes(t *testing.T) {
	rules := NewDomainRules([]string{"example.com"})
	for _, host := range []string{
		"badexample.com",
		"example.com.evil",
		"com",
		"",
	} {
		if rules.Blocked(host) {
			t.Fatalf("Blocked(%q) = true, want false", host)
		}
	}
}

func TestDomainRulesExceptionsOverrideBans(t *testing.T) {
	rules, err := NewDomainRulesConfig(DomainRulesConfig{
		Blocked:    []string{"example.com"},
		Exceptions: []string{"allowed.example.com"},
		BlockRegex: []RegexRule{{Pattern: `(^|\.)blocked-by-regex\.test$`}},
		AllowRegex: []RegexRule{{Pattern: `^allowed-regex\.blocked-by-regex\.test$`}},
	})
	if err != nil {
		t.Fatalf("NewDomainRulesConfig() error = %v", err)
	}
	for _, host := range []string{"example.com", "www.example.com", "blocked-by-regex.test", "www.blocked-by-regex.test"} {
		if !rules.Blocked(host) {
			t.Fatalf("Blocked(%q) = false, want true", host)
		}
	}
	for _, host := range []string{"allowed.example.com", "child.allowed.example.com", "allowed-regex.blocked-by-regex.test"} {
		if rules.Blocked(host) {
			t.Fatalf("Blocked(%q) = true, want false", host)
		}
	}
}

func TestDomainRulesTLDBlanket(t *testing.T) {
	// Test 1: Blanket block TLDs
	rules, err := NewDomainRulesConfig(DomainRulesConfig{
		BlanketBlockTLDs: []string{"xyz", "ru"},
		Exceptions:       []string{"allowed.example.ru"},
	})
	if err != nil {
		t.Fatalf("NewDomainRulesConfig() error = %v", err)
	}

	// Should block xyz and ru domains
	for _, host := range []string{"example.xyz", "sub.domain.ru", "malicious.ru"} {
		if !rules.Blocked(host) {
			t.Errorf("expected %q to be blocked by TLD blanket", host)
		}
	}

	// Should NOT block allowed domains or exceptions in blocked TLDs
	for _, host := range []string{"google.com", "allowed.example.ru", "127.0.0.1", "[::1]"} {
		if rules.Blocked(host) {
			t.Errorf("expected %q NOT to be blocked (IP/Exception/Allowed TLD)", host)
		}
	}

	// Test 2: Whitelist allowed TLDs
	rules2, err := NewDomainRulesConfig(DomainRulesConfig{
		AllowedTLDs: []string{"com", "org"},
		Exceptions:  []string{"exception.xyz"},
	})
	if err != nil {
		t.Fatalf("NewDomainRulesConfig() error = %v", err)
	}

	// Allowed TLDs should be permitted
	for _, host := range []string{"google.com", "wikipedia.org", "sub.com"} {
		if rules2.Blocked(host) {
			t.Errorf("expected allowed TLD %q NOT to be blocked", host)
		}
	}

	// Non-allowed TLDs should be blocked, except exceptions and IPs
	for _, host := range []string{"example.ru", "malicious.xyz", "domain.info"} {
		if !rules2.Blocked(host) {
			t.Errorf("expected non-allowed TLD %q to be blocked", host)
		}
	}

	for _, host := range []string{"exception.xyz", "192.168.1.1"} {
		if rules2.Blocked(host) {
			t.Errorf("expected %q NOT to be blocked (IP/Exception)", host)
		}
	}
}

func BenchmarkDomainTrieMatch(b *testing.B) {
	domains := []string{
		"google.com",
		"facebook.com",
		"twitter.com",
		"github.com",
		"microsoft.com",
		"amazon.com",
		"netflix.com",
		"apple.com",
		"youtube.com",
		"wikipedia.org",
	}
	rules := NewDomainRules(domains)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rules.Blocked("sub.google.com")
		rules.Blocked("unknown-domain.com")
	}
}
