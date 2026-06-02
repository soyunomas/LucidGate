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
	rules           []subRule
	regexRules      []regexSubRule
	OnMatch         func(kind string, pattern string)
	LengthPreserved bool
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

	maxWindow := 0
	for _, r := range f.regexRules {
		if r.maxWindow > maxWindow {
			maxWindow = r.maxWindow
		}
	}
	for _, r := range f.rules {
		if len(r.search) > maxWindow {
			maxWindow = len(r.search)
		}
	}
	if maxWindow <= 0 {
		maxWindow = defaultRegexSubstitutionWindow
	}

	return &multiSubstitutionStreamFilter{
		rules:           f.rules,
		regexRules:      f.regexRules,
		maxWindow:       maxWindow,
		onMatch:         f.OnMatch,
		lengthPreserved: f.LengthPreserved,
	}
}

func (f *SubstitutionFilter) ProcessChunk(in []byte) ([]byte, bool, error) {
	return f.NewFilter().ProcessChunk(in)
}

type multiSubstitutionStreamFilter struct {
	rules           []subRule
	regexRules      []regexSubRule
	pending         []byte
	maxWindow       int
	onMatch         func(kind string, pattern string)
	lengthPreserved bool
	BlockOnMatch    bool
	matchedError    error
}

func (f *multiSubstitutionStreamFilter) ProcessChunk(in []byte) ([]byte, bool, error) {
	if f.matchedError != nil {
		return nil, false, f.matchedError
	}
	if len(in) == 0 {
		return nil, false, nil
	}
	f.pending = append(f.pending, in...)
	if len(f.pending) <= f.maxWindow {
		return nil, false, nil
	}
	emit := len(f.pending) - f.maxWindow
	chunk := make([]byte, emit)
	copy(chunk, f.pending[:emit])

	chunk = f.applyRules(chunk)
	if f.matchedError != nil {
		return nil, false, f.matchedError
	}

	out := append([]byte(nil), chunk...)
	copy(f.pending, f.pending[emit:])
	f.pending = f.pending[:len(f.pending)-emit]
	return out, false, nil
}

func (f *multiSubstitutionStreamFilter) Flush() ([]byte, error) {
	if f.matchedError != nil {
		return nil, f.matchedError
	}
	if len(f.pending) == 0 {
		return nil, nil
	}
	chunk := f.applyRules(f.pending)
	if f.matchedError != nil {
		return nil, f.matchedError
	}
	f.pending = f.pending[:0]
	return chunk, nil
}

func (f *multiSubstitutionStreamFilter) applyRules(in []byte) []byte {
	out := in
	// 1. Apply literal substitutions
	for _, r := range f.rules {
		var matched bool
		var outParts [][]byte
		pending := out
		targetReplace := r.replace
		if f.lengthPreserved {
			targetReplace = padOrTruncate(r.replace, len(r.search))
		}
		for {
			idx := bytes.Index(pending, r.search)
			if idx == -1 {
				outParts = append(outParts, pending)
				break
			}
			matched = true
			outParts = append(outParts, pending[:idx])
			outParts = append(outParts, targetReplace)
			pending = pending[idx+len(r.search):]
		}
		if matched {
			if f.BlockOnMatch {
				f.matchedError = ErrSecretExfiltrationBlocked
				return in
			}
			out = bytes.Join(outParts, nil)
			if f.onMatch != nil {
				f.onMatch("literal", string(r.search))
			}
		}
	}
	// 2. Apply regex substitutions
	for _, r := range f.regexRules {
		if r.re.Match(out) {
			if f.BlockOnMatch {
				f.matchedError = ErrSecretExfiltrationBlocked
				return in
			}
			if f.lengthPreserved {
				matches := r.re.FindAllSubmatchIndex(out, -1)
				for i := len(matches) - 1; i >= 0; i-- {
					loc := matches[i]
					matchStart, matchEnd := loc[0], loc[1]
					match := out[matchStart:matchEnd]
					expanded := r.re.Expand(nil, r.replace, out, loc)
					targetReplace := padOrTruncate(expanded, len(match))
					out = bytes.Join([][]byte{out[:matchStart], targetReplace, out[matchEnd:]}, nil)
				}
			} else {
				out = r.re.ReplaceAll(out, r.replace)
			}
			if f.onMatch != nil {
				f.onMatch("regex", r.re.String())
			}
		}
	}
	return out
}

func padOrTruncate(replace []byte, targetLen int) []byte {
	if len(replace) == targetLen {
		return replace
	}
	if len(replace) > targetLen {
		return replace[:targetLen]
	}
	res := make([]byte, targetLen)
	copy(res, replace)
	for i := len(replace); i < targetLen; i++ {
		res[i] = '*'
	}
	return res
}

