package proxy

type HTMLInjectionFilter struct {
	banner []byte
}

func NewHTMLInjectionFilter(banner string) *HTMLInjectionFilter {
	return &HTMLInjectionFilter{banner: []byte(banner)}
}

func (f *HTMLInjectionFilter) NewFilter() FilterEngine {
	if f == nil || len(f.banner) == 0 {
		return passThroughFilter{}
	}
	return &htmlInjectionStreamFilter{banner: f.banner}
}

func (f *HTMLInjectionFilter) ProcessChunk(in []byte) ([]byte, bool, error) {
	return f.NewFilter().ProcessChunk(in)
}

type htmlInjectionStreamFilter struct {
	banner   []byte
	pending  []byte
	injected bool
}

func (f *htmlInjectionStreamFilter) ProcessChunk(in []byte) ([]byte, bool, error) {
	if len(f.banner) == 0 || len(in) == 0 {
		return in, false, nil
	}
	if f.injected {
		return in, false, nil
	}
	f.pending = append(f.pending, in...)
	if out, ok := f.injectPending(); ok {
		return out, false, nil
	}
	emit := len(f.pending) - (len("</body>") - 1)
	if emit <= 0 {
		return nil, false, nil
	}
	out := make([]byte, emit)
	copy(out, f.pending[:emit])
	copy(f.pending, f.pending[emit:])
	f.pending = f.pending[:len(f.pending)-emit]
	return out, false, nil
}

func (f *htmlInjectionStreamFilter) injectPending() ([]byte, bool) {
	const needle = "</body>"
	for i := 0; i+len(needle) <= len(f.pending); i++ {
		if asciiEqualFoldBytes(f.pending[i:i+len(needle)], []byte(needle)) {
			out := make([]byte, 0, len(f.pending)+len(f.banner))
			out = append(out, f.pending[:i]...)
			out = append(out, f.banner...)
			out = append(out, f.pending[i:]...)
			f.pending = f.pending[:0]
			f.injected = true
			return out, true
		}
	}
	return nil, false
}

func (f *htmlInjectionStreamFilter) Flush() ([]byte, error) {
	if len(f.pending) == 0 {
		return nil, nil
	}
	out := make([]byte, len(f.pending))
	copy(out, f.pending)
	f.pending = f.pending[:0]
	return out, nil
}
