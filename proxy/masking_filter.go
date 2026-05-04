package proxy

import "fmt"

type MaskingFilter struct {
	phrases [][]byte
	maxLen  int
}

func NewMaskingFilter(phrases []string) (*MaskingFilter, error) {
	f := &MaskingFilter{}
	for _, phrase := range phrases {
		normalized := normalizePhrase(phrase)
		if normalized == "" {
			continue
		}
		p := []byte(normalized)
		f.phrases = append(f.phrases, p)
		if len(p) > f.maxLen {
			f.maxLen = len(p)
		}
	}
	return f, nil
}

func (f *MaskingFilter) NewFilter() FilterEngine {
	if f == nil || f.maxLen == 0 {
		return passThroughFilter{}
	}
	return &maskingStreamFilter{compiled: f}
}

func (f *MaskingFilter) ProcessChunk(in []byte) ([]byte, bool, error) {
	return f.NewFilter().ProcessChunk(in)
}

type maskingStreamFilter struct {
	compiled *MaskingFilter
	pending  []byte
}

func (f *maskingStreamFilter) ProcessChunk(in []byte) ([]byte, bool, error) {
	if f.compiled == nil || f.compiled.maxLen == 0 || len(in) == 0 {
		return in, false, nil
	}
	f.pending = append(f.pending, in...)
	f.maskPending()
	emit := len(f.pending) - (f.compiled.maxLen - 1)
	if emit <= 0 {
		return nil, false, nil
	}
	out := make([]byte, emit)
	copy(out, f.pending[:emit])
	copy(f.pending, f.pending[emit:])
	f.pending = f.pending[:len(f.pending)-emit]
	return out, false, nil
}

func (f *maskingStreamFilter) maskPending() {
	for i := 0; i < len(f.pending); i++ {
		for _, phrase := range f.compiled.phrases {
			if i+len(phrase) > len(f.pending) {
				continue
			}
			if asciiEqualFoldBytes(f.pending[i:i+len(phrase)], phrase) {
				for j := 0; j < len(phrase); j++ {
					f.pending[i+j] = '*'
				}
			}
		}
	}
}

func asciiEqualFoldBytes(src []byte, normalized []byte) bool {
	if len(src) != len(normalized) {
		return false
	}
	for i := range src {
		if lowerASCII(src[i]) != normalized[i] {
			return false
		}
	}
	return true
}

type flushingFilter interface {
	Flush() ([]byte, error)
}

func (f *maskingStreamFilter) Flush() ([]byte, error) {
	if f.compiled == nil {
		return nil, fmt.Errorf("masking filter is not initialized")
	}
	if len(f.pending) == 0 {
		return nil, nil
	}
	f.maskPending()
	out := make([]byte, len(f.pending))
	copy(out, f.pending)
	f.pending = f.pending[:0]
	return out, nil
}

type ContentFilter struct {
	Semantic     *PhraseFilter
	Masking      *MaskingFilter
	HTML         *HTMLInjectionFilter
	Magic        *MagicFilter
	Substitution *SubstitutionFilter
	Antivirus    *Antivirus
}

func NewContentFilter(semantic *PhraseFilter, masking *MaskingFilter, html *HTMLInjectionFilter, magic *MagicFilter, substitution *SubstitutionFilter, antivirus ...*Antivirus) *ContentFilter {
	f := &ContentFilter{Semantic: semantic, Masking: masking, HTML: html, Magic: magic, Substitution: substitution}
	if len(antivirus) > 0 {
		f.Antivirus = antivirus[0]
	}
	return f
}

func (f *ContentFilter) NewFilter() FilterEngine {
	var filters []FilterEngine
	if f != nil && f.Magic != nil && len(f.Magic.blocked) > 0 {
		filters = append(filters, f.Magic.NewFilter())
	}
	if f != nil && f.Semantic != nil {
		filters = append(filters, f.Semantic.NewFilter())
	}
	if f != nil && f.Masking != nil && f.Masking.maxLen > 0 {
		filters = append(filters, f.Masking.NewFilter())
	}
	if f != nil && f.Substitution != nil && f.Substitution.HasRules() {
		filters = append(filters, f.Substitution.NewFilter())
	}
	if len(filters) == 0 {
		return passThroughFilter{}
	}
	if len(filters) == 1 {
		return filters[0]
	}
	return &chainFilter{filters: filters}
}

func (f *ContentFilter) ProcessChunk(in []byte) ([]byte, bool, error) {
	return f.NewFilter().ProcessChunk(in)
}

type chainFilter struct {
	filters []FilterEngine
}

func (f *chainFilter) ProcessChunk(in []byte) ([]byte, bool, error) {
	out := in
	for i, filter := range f.filters {
		next, blocked, err := filter.ProcessChunk(out)
		if err != nil {
			return nil, false, err
		}
		out = next
		if blocked {
			out, err = f.runDownstream(out, f.filters[i+1:])
			if err != nil {
				return nil, false, err
			}
			return out, true, nil
		}
		if len(out) == 0 {
			return nil, false, nil
		}
	}
	return out, false, nil
}

func (f *chainFilter) runDownstream(in []byte, filters []FilterEngine) ([]byte, error) {
	out := in
	var err error
	for _, filter := range filters {
		var blocked bool
		out, blocked, err = filter.ProcessChunk(out)
		if err != nil {
			return nil, err
		}
		if blocked {
			break
		}
	}
	for _, filter := range filters {
		flush, ok := filter.(flushingFilter)
		if !ok {
			continue
		}
		tail, err := flush.Flush()
		if err != nil {
			return nil, err
		}
		out = append(out, tail...)
	}
	return out, nil
}

func (f *chainFilter) Flush() ([]byte, error) {
	var finalOut []byte

	for i, filter := range f.filters {
		flush, ok := filter.(flushingFilter)
		if !ok {
			continue
		}

		chunk, err := flush.Flush()
		if err != nil {
			return nil, err
		}
		if len(chunk) == 0 {
			continue
		}

		// Pasamos los bytes retenidos por todos los filtros que están aguas abajo
		var blocked bool
		for _, downstream := range f.filters[i+1:] {
			chunk, blocked, err = downstream.ProcessChunk(chunk)
			if err != nil {
				return nil, err
			}
			if blocked {
				// Precepto #10: Fail Fast. Si bloquea, añadimos lo procesado y abortamos.
				finalOut = append(finalOut, chunk...)
				return finalOut, nil
			}
		}

		// Acumulamos el resultado final sin sobrescribir (append)
		finalOut = append(finalOut, chunk...)
	}

	return finalOut, nil
}

func (f *chainFilter) filtersAfter(target FilterEngine) []FilterEngine {
	for i, filter := range f.filters {
		if filter == target {
			return f.filters[i+1:]
		}
	}
	return nil
}
