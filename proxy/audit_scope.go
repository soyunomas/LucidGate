package proxy

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type AuditClass string

const (
	AuditClassRoot       AuditClass = "root"
	AuditClassDependency AuditClass = "dependency"
	AuditClassNone       AuditClass = "none"
)

const (
	AuditDependencyMutationsNone       = "none"
	AuditDependencyMutationsRestricted = "restricted"
	AuditDependencyMutationsFull       = "full"
	AuditNoneModeTunnel                = "tunnel"
	AuditNoneModeNoInspect             = "noinspect"
)

type AuditScopeConfig struct {
	Enabled             bool
	Roots               []string
	DependencyTTL       time.Duration
	MaxDependencies     int
	NoneMode            string
	DependencyMutations string
	DiscoverHTML        bool
	DiscoverCSS         bool
	DiscoverJS          bool
	Now                 func() time.Time
}

type AuditScopeDecision struct {
	Class           AuditClass
	Root            string
	Reason          string
	MutationAllowed bool
	InspectAllowed  bool
	DumpAllowed     bool
}

type auditScopeContextKey struct{}

func WithAuditScopeDecision(ctx context.Context, dec AuditScopeDecision) context.Context {
	return context.WithValue(ctx, auditScopeContextKey{}, dec)
}

func AuditScopeDecisionFromContext(ctx context.Context) (AuditScopeDecision, bool) {
	if ctx == nil {
		return AuditScopeDecision{}, false
	}
	dec, ok := ctx.Value(auditScopeContextKey{}).(AuditScopeDecision)
	return dec, ok
}

type auditDependencyEntry struct {
	root     string
	reason   string
	lastSeen time.Time
}

type AuditScope struct {
	enabled             bool
	roots               *DomainMatcher
	dependencyTTL       time.Duration
	maxDependencies     int
	noneMode            string
	dependencyMutations string
	now                 func() time.Time
	mu                  sync.Mutex
	dependencies        atomic.Value // map[string]auditDependencyEntry
}

func NewAuditScope(cfg AuditScopeConfig) *AuditScope {
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	ttl := cfg.DependencyTTL
	if ttl <= 0 {
		ttl = 30 * time.Minute
	}
	maxDeps := cfg.MaxDependencies
	if maxDeps <= 0 {
		maxDeps = 8192
	}
	noneMode := strings.ToLower(strings.TrimSpace(cfg.NoneMode))
	if noneMode == "" {
		noneMode = AuditNoneModeTunnel
	}
	depMutations := strings.ToLower(strings.TrimSpace(cfg.DependencyMutations))
	if depMutations == "" {
		depMutations = AuditDependencyMutationsRestricted
	}
	scope := &AuditScope{
		enabled:             cfg.Enabled && len(cfg.Roots) > 0,
		roots:               NewDomainMatcher(cfg.Roots),
		dependencyTTL:       ttl,
		maxDependencies:     maxDeps,
		noneMode:            noneMode,
		dependencyMutations: depMutations,
		now:                 now,
	}
	scope.dependencies.Store(map[string]auditDependencyEntry{})
	return scope
}

func (s *AuditScope) Enabled() bool {
	return s != nil && s.enabled
}

func (s *AuditScope) NoneMode() string {
	if s == nil || s.noneMode == "" {
		return AuditNoneModeTunnel
	}
	return s.noneMode
}

func (s *AuditScope) Decide(req *http.Request, host string) AuditScopeDecision {
	if s == nil || !s.enabled {
		return AuditScopeDecision{
			Class:           AuditClassRoot,
			Reason:          "disabled",
			MutationAllowed: true,
			InspectAllowed:  true,
			DumpAllowed:     true,
		}
	}
	host = normalizeAuditHost(host)
	if host == "" {
		return s.noneDecision("empty_host")
	}
	if s.roots.Match(host) {
		return AuditScopeDecision{
			Class:           AuditClassRoot,
			Root:            host,
			Reason:          "root_host",
			MutationAllowed: true,
			InspectAllowed:  true,
			DumpAllowed:     true,
		}
	}
	if entry, ok := s.lookupDependency(host); ok {
		return s.dependencyDecision(entry.root, "known_dependency:"+entry.reason)
	}
	if req != nil {
		if root, reason := s.rootFromPropagationHeaders(req); root != "" {
			s.RegisterDependency(root, host, reason)
			return s.dependencyDecision(root, reason)
		}
	}
	return s.noneDecision("out_of_scope")
}

func (s *AuditScope) RegisterDependency(root, dependency, reason string) {
	if s == nil || !s.enabled {
		return
	}
	root = normalizeAuditHost(root)
	dependency = normalizeAuditHost(dependency)
	if root == "" || dependency == "" || root == dependency || s.roots.Match(dependency) {
		return
	}
	if !s.roots.Match(root) {
		if entry, ok := s.lookupDependency(root); ok {
			root = entry.root
		} else {
			return
		}
	}
	if reason == "" {
		reason = "manual"
	}

	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()

	current := s.dependencies.Load().(map[string]auditDependencyEntry)
	next := make(map[string]auditDependencyEntry, len(current)+1)
	for host, entry := range current {
		if now.Sub(entry.lastSeen) <= s.dependencyTTL {
			next[host] = entry
		}
	}
	next[dependency] = auditDependencyEntry{root: root, reason: reason, lastSeen: now}
	for len(next) > s.maxDependencies {
		var oldestHost string
		var oldest time.Time
		for host, entry := range next {
			if oldestHost == "" || entry.lastSeen.Before(oldest) {
				oldestHost = host
				oldest = entry.lastSeen
			}
		}
		delete(next, oldestHost)
	}
	s.dependencies.Store(next)
}

func (s *AuditScope) dependencyDecision(root, reason string) AuditScopeDecision {
	mutationAllowed := s.dependencyMutations == AuditDependencyMutationsFull
	return AuditScopeDecision{
		Class:           AuditClassDependency,
		Root:            root,
		Reason:          reason,
		MutationAllowed: mutationAllowed,
		InspectAllowed:  true,
		DumpAllowed:     true,
	}
}

func (s *AuditScope) noneDecision(reason string) AuditScopeDecision {
	return AuditScopeDecision{
		Class:           AuditClassNone,
		Reason:          reason,
		MutationAllowed: false,
		InspectAllowed:  false,
		DumpAllowed:     false,
	}
}

func (s *AuditScope) lookupDependency(host string) (auditDependencyEntry, bool) {
	host = normalizeAuditHost(host)
	if host == "" {
		return auditDependencyEntry{}, false
	}
	current := s.dependencies.Load().(map[string]auditDependencyEntry)
	entry, ok := current[host]
	if !ok || s.now().Sub(entry.lastSeen) > s.dependencyTTL {
		return auditDependencyEntry{}, false
	}
	return entry, true
}

func (s *AuditScope) rootFromPropagationHeaders(req *http.Request) (string, string) {
	if root := s.rootFromHeaderURL(req.Header.Get("Origin")); root != "" {
		return root, "origin"
	}
	if root := s.rootFromHeaderURL(req.Header.Get("Referer")); root != "" {
		return root, "referer"
	}
	return "", ""
}

func (s *AuditScope) rootFromHeaderURL(raw string) string {
	host := hostFromAbsoluteURL(raw)
	if host == "" {
		return ""
	}
	if s.roots.Match(host) {
		return host
	}
	if entry, ok := s.lookupDependency(host); ok {
		return entry.root
	}
	return ""
}

func hostFromAbsoluteURL(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Host == "" {
		return ""
	}
	return normalizeAuditHost(parsed.Host)
}

func normalizeAuditHost(host string) string {
	host = strings.TrimSpace(host)
	host = strings.TrimPrefix(host, "http://")
	host = strings.TrimPrefix(host, "https://")
	if i := strings.IndexByte(host, '/'); i >= 0 {
		host = host[:i]
	}
	host = strings.TrimPrefix(host, "*.")
	host = normalizedPolicyHost(host)
	return strings.Trim(host, ".")
}

func (o RelayOptions) ForAuditScope(dec AuditScopeDecision) RelayOptions {
	if dec.Class == "" || dec.Class == AuditClassRoot {
		return o
	}
	if dec.Class == AuditClassNone {
		o.LogBodies = false
		o.DumpDir = ""
		o.Filter = passThroughFilter{}
		o.RequestFilter = nil
		o.RequestSubstitutionFilter = nil
		return o
	}
	if dec.Class == AuditClassDependency && !dec.MutationAllowed {
		o.RequestSubstitutionFilter = nil
		o.Filter = nonMutatingFilter(o.Filter)
	}
	return o
}

func nonMutatingFilter(engine FilterEngine) FilterEngine {
	content, ok := engine.(*ContentFilter)
	if !ok || content == nil {
		return engine
	}
	return NewContentFilter(content.Semantic, nil, nil, content.Magic, nil, content.Antivirus).WithLogSemantic(content.LogSemantic)
}
