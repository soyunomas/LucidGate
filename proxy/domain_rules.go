package proxy

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

type DomainRules struct {
	blocked    domainTrie
	exceptions domainTrie
	blockRegex []*regexp.Regexp
	allowRegex []*regexp.Regexp
}

type flatNode struct {
	blocked    bool
	firstChild uint32
	childCount uint32
}

type flatTransition struct {
	label string
	node  uint32
}

type builderNode struct {
	blocked  bool
	children map[string]*builderNode
}

type domainTrie struct {
	builderRoot     *builderNode
	flatNodes       []flatNode
	flatTransitions []flatTransition
	flatRootBlocked bool
	compiled        bool
}

func NewDomainRules(domains []string) *DomainRules {
	rules, _ := NewDomainRulesConfig(DomainRulesConfig{Blocked: domains})
	return rules
}

type RegexRule struct {
	Pattern string
	Source  string
}

type DomainRulesConfig struct {
	Blocked    []string
	Exceptions []string
	BlockRegex []RegexRule
	AllowRegex []RegexRule
}

func NewDomainRulesConfig(cfg DomainRulesConfig) (*DomainRules, error) {
	rules := &DomainRules{}
	for _, domain := range cfg.Blocked {
		rules.blocked.Add(domain)
	}
	for _, domain := range cfg.Exceptions {
		rules.exceptions.Add(domain)
	}

	// Compilar los Tries al finalizar la fase de parsing
	rules.blocked.Compile()
	rules.exceptions.Compile()

	for _, rule := range cfg.BlockRegex {
		compiled, err := compilePolicyRegex(rule)
		if err != nil {
			return nil, err
		}
		rules.blockRegex = append(rules.blockRegex, compiled)
	}
	for _, rule := range cfg.AllowRegex {
		compiled, err := compilePolicyRegex(rule)
		if err != nil {
			return nil, err
		}
		rules.allowRegex = append(rules.allowRegex, compiled)
	}
	return rules, nil
}

func (r *DomainRules) Add(domain string) {
	r.blocked.Add(domain)
}

func (r *DomainRules) Compile() {
	if r == nil {
		return
	}
	r.blocked.Compile()
	r.exceptions.Compile()
}

func (t *domainTrie) Add(domain string) {
	labels := normalizedDomainLabels(domain)
	if len(labels) == 0 {
		return
	}
	if t.builderRoot == nil {
		t.builderRoot = &builderNode{}
	}
	node := t.builderRoot
	for i := len(labels) - 1; i >= 0; i-- {
		label := labels[i]
		if node.children == nil {
			node.children = make(map[string]*builderNode)
		}
		next := node.children[label]
		if next == nil {
			next = &builderNode{}
			node.children[label] = next
		}
		node = next
	}
	node.blocked = true
	t.compiled = false
}

func (t *domainTrie) Compile() {
	if t.compiled {
		return
	}
	if t.builderRoot == nil {
		t.compiled = true
		return
	}

	t.flatNodes = make([]flatNode, 0, 128)
	t.flatTransitions = make([]flatTransition, 0, 128)
	t.flatRootBlocked = t.builderRoot.blocked

	var buildFlat func(n *builderNode) uint32
	buildFlat = func(n *builderNode) uint32 {
		nodeIdx := uint32(len(t.flatNodes))
		t.flatNodes = append(t.flatNodes, flatNode{blocked: n.blocked})

		if len(n.children) == 0 {
			return nodeIdx
		}

		labels := make([]string, 0, len(n.children))
		for label := range n.children {
			labels = append(labels, label)
		}
		sort.Strings(labels)

		firstChild := uint32(len(t.flatTransitions))
		childCount := uint32(len(labels))

		transStart := len(t.flatTransitions)
		for _, label := range labels {
			t.flatTransitions = append(t.flatTransitions, flatTransition{label: label})
		}

		for i, label := range labels {
			childNode := n.children[label]
			childIdx := buildFlat(childNode)
			t.flatTransitions[transStart+i].node = childIdx
		}

		t.flatNodes[nodeIdx].firstChild = firstChild
		t.flatNodes[nodeIdx].childCount = childCount

		return nodeIdx
	}

	buildFlat(t.builderRoot)

	t.builderRoot = nil
	t.compiled = true
}

func (r *DomainRules) Blocked(host string) bool {
	if r == nil {
		return false
	}
	return r.Decision(host).Blocked
}

func (r *DomainRules) Decision(host string) PolicyDecision {
	if r == nil {
		return PolicyDecision{}
	}
	host = normalizedDomain(host)
	if host == "" {
		return PolicyDecision{}
	}
	if r.exceptions.Match(host) {
		return PolicyDecision{}
	}
	for _, rx := range r.allowRegex {
		if rx.MatchString(host) {
			return PolicyDecision{}
		}
	}
	if r.blocked.Match(host) {
		return PolicyDecision{Blocked: true, MatchType: "domain", Value: host}
	}
	for _, rx := range r.blockRegex {
		if rx.MatchString(host) {
			return PolicyDecision{Blocked: true, MatchType: "domain_regex", Value: rx.String()}
		}
	}
	return PolicyDecision{}
}

func (t *domainTrie) Match(host string) bool {
	if !t.compiled {
		t.Compile()
	}

	host = normalizedDomain(host)
	if host == "" {
		return false
	}

	if t.flatRootBlocked {
		return true
	}

	if len(t.flatNodes) == 0 {
		return false
	}

	nodeIdx := uint32(0)

	end := len(host)
	for end > 0 {
		start := strings.LastIndexByte(host[:end], '.')
		var label string
		if start == -1 {
			label = host[:end]
			end = 0
		} else {
			label = host[start+1 : end]
			end = start
		}

		if label == "" {
			continue
		}

		node := t.flatNodes[nodeIdx]
		if node.childCount == 0 {
			return false
		}

		foundIdx, found := t.binarySearchTransition(node.firstChild, node.firstChild+node.childCount, label)
		if !found {
			return false
		}

		nodeIdx = t.flatTransitions[foundIdx].node
		if t.flatNodes[nodeIdx].blocked {
			return true
		}
	}

	return t.flatNodes[nodeIdx].blocked
}

func (t *domainTrie) binarySearchTransition(start, end uint32, label string) (uint32, bool) {
	low := start
	high := end

	for low < high {
		mid := low + (high-low)/2
		midLabel := t.flatTransitions[mid].label
		if midLabel == label {
			return mid, true
		}
		if midLabel < label {
			low = mid + 1
		} else {
			high = mid
		}
	}
	return 0, false
}

func compilePolicyRegex(rule RegexRule) (*regexp.Regexp, error) {
	if strings.TrimSpace(rule.Pattern) == "" {
		if rule.Source != "" {
			return nil, fmt.Errorf("%s: empty regex", rule.Source)
		}
		return nil, fmt.Errorf("empty regex")
	}
	rx, err := regexp.Compile(rule.Pattern)
	if err != nil {
		if rule.Source != "" {
			return nil, fmt.Errorf("%s: compile regex %q: %w", rule.Source, rule.Pattern, err)
		}
		return nil, fmt.Errorf("compile regex %q: %w", rule.Pattern, err)
	}
	return rx, nil
}

func normalizedDomainLabels(host string) []string {
	host = normalizedDomain(host)
	if host == "" || strings.Contains(host, "/") {
		return nil
	}
	return strings.FieldsFunc(host, func(r rune) bool { return r == '.' })
}

func normalizedDomain(host string) string {
	host = strings.TrimSpace(strings.ToLower(host))
	host = strings.TrimPrefix(host, ".")
	host = strings.TrimSuffix(host, ".")
	if host == "" || strings.Contains(host, "/") {
		return ""
	}
	return host
}
