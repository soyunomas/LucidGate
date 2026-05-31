package proxy

import (
	"bytes"
	"fmt"
	"regexp"
)

const (
	defaultRegexSubstitutionWindow = 64 * 1024
	maxRegexSubstitutionWindow     = 1024 * 1024
)

type SubstitutionFilter struct {
	rules      []subRule
	regexRules []regexSubRule
}

type subRule struct {
	search  []byte
	replace []byte
}

type RegexSubstitutionRule struct {
	Pattern        string
	Replace        string
	MaxWindowBytes int
	Source         string
}

type regexSubRule struct {
	re        *regexp.Regexp
	replace   []byte
	maxWindow int
}

// Recibe un mapa de reemplazos y compila las reglas
func NewSubstitutionFilter(rules map[string]string) *SubstitutionFilter {
	f, _ := NewSubstitutionFilterWithRegex(rules, nil)
	return f
}

func NewSubstitutionFilterWithRegex(rules map[string]string, regexRules []RegexSubstitutionRule) (*SubstitutionFilter, error) {
	f := &SubstitutionFilter{}
	for s, r := range rules {
		if s != "" {
			f.rules = append(f.rules, subRule{[]byte(s), []byte(r)})
		}
	}
	for _, rule := range regexRules {
		if rule.Pattern == "" {
			continue
		}
		re, err := regexp.Compile(rule.Pattern)
		if err != nil {
			if rule.Source != "" {
				return nil, fmt.Errorf("%s: compile substitution regex %q: %w", rule.Source, rule.Pattern, err)
			}
			return nil, fmt.Errorf("compile substitution regex %q: %w", rule.Pattern, err)
		}
		maxWindow := rule.MaxWindowBytes
		if maxWindow <= 0 {
			maxWindow = defaultRegexSubstitutionWindow
		}
		if maxWindow > maxRegexSubstitutionWindow {
			return nil, fmt.Errorf("substitution regex %q max_window_bytes %d exceeds limit %d", rule.Pattern, maxWindow, maxRegexSubstitutionWindow)
		}
		f.regexRules = append(f.regexRules, regexSubRule{
			re:        re,
			replace:   []byte(rule.Replace),
			maxWindow: maxWindow,
		})
	}
	return f, nil
}

func (f *SubstitutionFilter) HasRules() bool {
	return f != nil && (len(f.rules) > 0 || len(f.regexRules) > 0)
}

func (f *SubstitutionFilter) NewFilter() FilterEngine {
	if !f.HasRules() {
		return passThroughFilter{}
	}
	// Si hay varias reglas, las encadenamos usando tu chainFilter parcheado
	var filters []FilterEngine
	for _, r := range f.rules {
		filters = append(filters, &substitutionStreamFilter{rule: r})
	}
	for _, r := range f.regexRules {
		filters = append(filters, &regexSubstitutionStreamFilter{rule: r})
	}
	if len(filters) == 1 {
		return filters[0]
	}
	return &chainFilter{filters: filters}
}

func (f *SubstitutionFilter) ProcessChunk(in []byte) ([]byte, bool, error) {
	return f.NewFilter().ProcessChunk(in)
}

type substitutionStreamFilter struct {
	rule    subRule
	pending []byte
}

func (f *substitutionStreamFilter) ProcessChunk(in []byte) ([]byte, bool, error) {
	if len(in) == 0 {
		return nil, false, nil
	}
	f.pending = append(f.pending, in...)

	var out []byte
	for {
		idx := bytes.Index(f.pending, f.rule.search)
		if idx == -1 {
			break
		}
		out = append(out, f.pending[:idx]...)
		out = append(out, f.rule.replace...)
		f.pending = f.pending[idx+len(f.rule.search):]
	}

	emit := len(f.pending) - (len(f.rule.search) - 1)
	if emit > 0 {
		out = append(out, f.pending[:emit]...)
		f.pending = f.pending[emit:]
	}

	return out, false, nil
}

func (f *substitutionStreamFilter) Flush() ([]byte, error) {
	if len(f.pending) == 0 {
		return nil, nil
	}
	out := make([]byte, len(f.pending))
	copy(out, f.pending)
	f.pending = f.pending[:0]
	return out, nil
}

type regexSubstitutionStreamFilter struct {
	rule    regexSubRule
	pending []byte
}

func (f *regexSubstitutionStreamFilter) ProcessChunk(in []byte) ([]byte, bool, error) {
	if len(in) == 0 {
		return nil, false, nil
	}
	f.pending = append(f.pending, in...)
	if len(f.pending) <= f.rule.maxWindow {
		return nil, false, nil
	}
	emit := len(f.pending) - f.rule.maxWindow
	replaced := f.rule.re.ReplaceAll(f.pending[:emit], f.rule.replace)
	out := append([]byte(nil), replaced...)
	copy(f.pending, f.pending[emit:])
	f.pending = f.pending[:len(f.pending)-emit]
	return out, false, nil
}

func (f *regexSubstitutionStreamFilter) Flush() ([]byte, error) {
	if len(f.pending) == 0 {
		return nil, nil
	}
	replaced := f.rule.re.ReplaceAll(f.pending, f.rule.replace)
	out := append([]byte(nil), replaced...)
	f.pending = f.pending[:0]
	return out, nil
}
