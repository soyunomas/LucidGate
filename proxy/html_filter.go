package proxy

import "strings"

type htmlTextFilter struct {
	inner       FilterEngine
	inTag       bool
	tagClosing  bool
	tagName     []byte
	tagNameDone bool
	quote       byte
	comment     int
	skip        string
	closeMatch  int
}

func newHTMLTextFilter(inner FilterEngine) FilterEngine {
	if inner == nil {
		inner = passThroughFilter{}
	}
	return &htmlTextFilter{inner: inner}
}

func (f *htmlTextFilter) ProcessChunk(in []byte) ([]byte, bool, error) {
	for i, b := range in {
		visible, emit := f.consumeByte(b)
		if !emit {
			continue
		}
		_, blocked, err := f.inner.ProcessChunk([]byte{visible})
		if err != nil {
			return nil, false, err
		}
		if blocked {
			return in[:i+1], true, nil
		}
	}
	return in, false, nil
}

func (f *htmlTextFilter) consumeByte(b byte) (byte, bool) {
	if f.skip != "" {
		f.consumeSkippedContent(b)
		return 0, false
	}
	if f.comment > 0 {
		f.consumeComment(b)
		return 0, false
	}
	if f.inTag {
		f.consumeTag(b)
		return 0, false
	}
	if b == '<' {
		f.startTag()
		return 0, false
	}
	return b, true
}

func (f *htmlTextFilter) startTag() {
	f.inTag = true
	f.tagClosing = false
	f.tagNameDone = false
	f.quote = 0
	f.tagName = f.tagName[:0]
}

func (f *htmlTextFilter) consumeTag(b byte) {
	if f.quote != 0 {
		if b == f.quote {
			f.quote = 0
		}
		return
	}
	if b == '"' || b == '\'' {
		f.quote = b
		return
	}
	if len(f.tagName) == 0 && !f.tagClosing && b == '!' {
		f.comment = 1
		f.inTag = false
		return
	}
	if len(f.tagName) == 0 && b == '/' {
		f.tagClosing = true
		return
	}
	if b == '>' {
		f.finishTag()
		return
	}
	if isHTMLSpace(b) || b == '/' {
		f.tagNameDone = true
		return
	}
	if !f.tagNameDone {
		f.tagName = append(f.tagName, lowerASCII(b))
	}
}

func (f *htmlTextFilter) finishTag() {
	name := string(f.tagName)
	if !f.tagClosing && (name == "script" || name == "style") {
		f.skip = name
		f.closeMatch = 0
	}
	f.inTag = false
	f.tagClosing = false
	f.tagNameDone = false
	f.quote = 0
	f.tagName = f.tagName[:0]
}

func (f *htmlTextFilter) consumeComment(b byte) {
	switch f.comment {
	case 1:
		if b == '-' {
			f.comment = 2
			return
		}
	case 2:
		if b == '-' {
			f.comment = 3
			return
		}
	case 3:
		if b == '>' {
			f.comment = 0
			return
		}
		if b == '-' {
			return
		}
	}
	if b == '>' {
		f.comment = 0
		return
	}
	f.comment = 1
}

func (f *htmlTextFilter) consumeSkippedContent(b byte) {
	needle := "</" + f.skip + ">"
	if lowerASCII(b) == needle[f.closeMatch] {
		f.closeMatch++
		if f.closeMatch == len(needle) {
			f.skip = ""
			f.closeMatch = 0
		}
		return
	}
	if lowerASCII(b) == needle[0] {
		f.closeMatch = 1
		return
	}
	f.closeMatch = 0
}

func isHTMLSpace(b byte) bool {
	return strings.IndexByte(" \t\r\n\f", b) >= 0
}
