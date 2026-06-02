package proxy

import (
	"net/netip"
	"strings"

	"github.com/gaissmai/bart"
)

// DomainMatcher wraps domainTrie for public, high-performance domain matching.
type DomainMatcher struct {
	trie domainTrie
}

func NewDomainMatcher(domains []string) *DomainMatcher {
	m := &DomainMatcher{}
	for _, d := range domains {
		d = strings.TrimPrefix(d, "*.")
		m.trie.Add(d)
	}
	m.trie.Compile()
	return m
}

func (m *DomainMatcher) Match(host string) bool {
	if m == nil {
		return false
	}
	return m.trie.Match(host)
}

// IPMatcher wraps bart.Table for public, high-performance IP prefix matching.
type IPMatcher struct {
	table bart.Table[bool]
}

func NewIPMatcher(prefixes []string) (*IPMatcher, error) {
	m := &IPMatcher{}
	if err := insertIPPrefixes(&m.table, prefixes); err != nil {
		return nil, err
	}
	return m, nil
}

func (m *IPMatcher) Match(ip netip.Addr) bool {
	if m == nil {
		return false
	}
	_, ok := m.table.Lookup(ip)
	return ok
}
