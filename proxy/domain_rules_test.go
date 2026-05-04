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
