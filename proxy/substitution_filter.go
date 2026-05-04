package proxy

import "bytes"

type SubstitutionFilter struct {
	rules []subRule
}

type subRule struct {
	search  []byte
	replace []byte
}

// Recibe un mapa de reemplazos y compila las reglas
func NewSubstitutionFilter(rules map[string]string) *SubstitutionFilter {
	f := &SubstitutionFilter{}
	for s, r := range rules {
		if s != "" {
			f.rules = append(f.rules, subRule{[]byte(s), []byte(r)})
		}
	}
	return f
}

func (f *SubstitutionFilter) HasRules() bool {
	return f != nil && len(f.rules) > 0
}

func (f *SubstitutionFilter) NewFilter() FilterEngine {
	if f == nil || len(f.rules) == 0 {
		return passThroughFilter{}
	}
	// Si hay varias reglas, las encadenamos usando tu chainFilter parcheado
	var filters []FilterEngine
	for _, r := range f.rules {
		filters = append(filters, &substitutionStreamFilter{rule: r})
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
