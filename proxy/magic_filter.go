package proxy

import (
	"net/http"
	"strings"
)

// magicSniffLen is the maximum number of bytes inspected before deciding the
// real MIME type of a stream. Matches net/http.DetectContentType which only
// looks at the first 512 bytes.
const magicSniffLen = 512

// MagicFilter blocks responses whose real MIME type matches a configured
// blocklist. It buffers up to magicSniffLen bytes from the start of the
// stream, runs a small set of executable signatures plus
// http.DetectContentType, and re-injects the prefix into the stream when no
// match is found. Memory is bounded; the rest of the body flows through as
// pass-through once the decision is taken.
type MagicFilter struct {
	blocked map[string]struct{}
}

// NewMagicFilter builds an immutable filter from a list of MIME types. The
// types are normalized to lower-case without parameters. Returns nil when the
// list is empty so callers can short-circuit cheaply.
func NewMagicFilter(blockedTypes []string) *MagicFilter {
	if len(blockedTypes) == 0 {
		return nil
	}
	set := make(map[string]struct{}, len(blockedTypes))
	for _, raw := range blockedTypes {
		mt := strings.ToLower(strings.TrimSpace(raw))
		if i := strings.Index(mt, ";"); i >= 0 {
			mt = strings.TrimSpace(mt[:i])
		}
		if mt == "" {
			continue
		}
		set[mt] = struct{}{}
	}
	if len(set) == 0 {
		return nil
	}
	return &MagicFilter{blocked: set}
}

// NewFilter creates a per-stream instance to be safely used inside the relay
// hot path without locks.
func (f *MagicFilter) NewFilter() FilterEngine {
	if f == nil || len(f.blocked) == 0 {
		return passThroughFilter{}
	}
	return &magicStreamFilter{compiled: f}
}

// ProcessChunk on the compiled filter is only used in tests / one-shot
// callers. Production uses NewFilter for per-stream state.
func (f *MagicFilter) ProcessChunk(in []byte) ([]byte, bool, error) {
	return f.NewFilter().ProcessChunk(in)
}

type magicStreamFilter struct {
	compiled    *MagicFilter
	pending     []byte
	decided     bool
	blocked     bool
	blockedMime string
}

func (f *magicStreamFilter) Decision() (bool, string, string) {
	if f.blocked {
		return true, "magic", f.blockedMime
	}
	return false, "", ""
}

func (f *magicStreamFilter) ProcessChunk(in []byte) ([]byte, bool, error) {
	if f.blocked {
		return nil, true, nil
	}
	if f.decided {
		return in, false, nil
	}
	if len(in) == 0 {
		return nil, false, nil
	}
	need := magicSniffLen - len(f.pending)
	var tail []byte
	if len(in) <= need {
		f.pending = append(f.pending, in...)
	} else {
		f.pending = append(f.pending, in[:need]...)
		tail = in[need:]
	}
	if len(f.pending) < magicSniffLen {
		// Need more data; nothing to emit yet.
		return nil, false, nil
	}
	return f.commitDecision(tail)
}

func (f *magicStreamFilter) Flush() ([]byte, error) {
	if f.blocked || f.decided {
		return nil, nil
	}
	out, _, err := f.commitDecision(nil)
	return out, err
}

func (f *magicStreamFilter) commitDecision(tail []byte) ([]byte, bool, error) {
	f.decided = true
	mime := detectMagicType(f.pending)
	if _, hit := f.compiled.blocked[mime]; hit {
		f.blocked = true
		f.blockedMime = mime
		f.pending = nil
		return nil, true, nil
	}
	if len(tail) == 0 {
		out := f.pending
		f.pending = nil
		return out, false, nil
	}
	out := append(f.pending, tail...)
	f.pending = nil
	return out, false, nil
}

// detectMagicType inspects the prefix and returns the canonical MIME used to
// match against the blocklist. Custom signatures take precedence because
// http.DetectContentType funnels most executables to application/octet-stream
// which would be too coarse to ban without breaking legitimate downloads.
func detectMagicType(data []byte) string {
	switch {
	case len(data) >= 4 && data[0] == 0x7F && data[1] == 'E' && data[2] == 'L' && data[3] == 'F':
		return "executable/elf"
	case len(data) >= 2 && data[0] == 'M' && data[1] == 'Z':
		return "executable/pe"
	case len(data) >= 4 && data[0] == 0xFE && data[1] == 0xED && data[2] == 0xFA && (data[3] == 0xCE || data[3] == 0xCF):
		return "executable/mach"
	case len(data) >= 4 && (data[0] == 0xCE || data[0] == 0xCF) && data[1] == 0xFA && data[2] == 0xED && data[3] == 0xFE:
		return "executable/mach"
	case len(data) >= 4 && data[0] == 0xCA && data[1] == 0xFE && data[2] == 0xBA && data[3] == 0xBE:
		return "executable/mach"
	case len(data) >= 2 && data[0] == '#' && data[1] == '!':
		return "executable/script"
	}
	mt := http.DetectContentType(data)
	if i := strings.Index(mt, ";"); i >= 0 {
		mt = mt[:i]
	}
	return strings.ToLower(strings.TrimSpace(mt))
}
