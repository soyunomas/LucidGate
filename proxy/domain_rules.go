package proxy

import (
	"strings"
)

type DomainRules struct {
	root domainNode
}

type domainNode struct {
	blocked  bool
	children map[string]*domainNode
}

func NewDomainRules(domains []string) *DomainRules {
	rules := &DomainRules{}
	for _, domain := range domains {
		rules.Add(domain)
	}
	return rules
}

func (r *DomainRules) Add(domain string) {
	labels := normalizedDomainLabels(domain)
	if len(labels) == 0 {
		return
	}
	node := &r.root
	for i := len(labels) - 1; i >= 0; i-- {
		label := labels[i]
		if node.children == nil {
			node.children = make(map[string]*domainNode)
		}
		next := node.children[label]
		if next == nil {
			next = &domainNode{}
			node.children[label] = next
		}
		node = next
	}
	node.blocked = true
}

func (r *DomainRules) Blocked(host string) bool {
	if r == nil {
		return false
	}
	labels := normalizedDomainLabels(host)
	if len(labels) == 0 {
		return false
	}
	node := &r.root
	for i := len(labels) - 1; i >= 0; i-- {
		next := node.children[labels[i]]
		if next == nil {
			return false
		}
		node = next
		if node.blocked {
			return true
		}
	}
	return node.blocked
}

func normalizedDomainLabels(host string) []string {
	host = strings.TrimSpace(strings.ToLower(host))
	host = strings.TrimPrefix(host, ".")
	host = strings.TrimSuffix(host, ".")
	if host == "" || strings.Contains(host, "/") {
		return nil
	}
	return strings.FieldsFunc(host, func(r rune) bool { return r == '.' })
}
