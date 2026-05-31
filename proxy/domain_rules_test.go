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
