package proxy

import (
	"fmt"
	"strings"
)

// ahoNode is one state of the Aho-Corasick automaton. Transitions are stored
// as a dense [256]int32 array instead of a map[byte]int because the inner
// nextState() loop runs once per byte of inspected traffic. Replacing the map
// lookup (~30-60 ns/byte) with a single array index (~2-5 ns/byte) is the
// dominant CPU win for the semantic filter at carrier-class throughput.
//
// Memory cost per node: 256 * 4 B (transitions) + 12 B (fail/score/hard) =
// ~1 KiB. With <10 k phrases the trie stays under ~10 MiB, well within budget.
//
// next[b] == 0 means "no explicit transition". The empty trie keeps state 0 as
// the root so a 0 transition from a non-root state is never ambiguous because
// nextState() walks the fail chain instead of trusting next[b] directly.
type ahoNode struct {
	next   [256]int32
	fail   int32
	hard   bool
	excpt  bool
	score  int32
	phrase string
}

type PhraseFilter struct {
	nodes     []ahoNode
	threshold int
}

type WeightedPhrase struct {
	Phrase string
	Weight int
}

func NewPhraseFilter(phrases []string) (*PhraseFilter, error) {
	return NewScoredPhraseFilter(phrases, nil, 0)
}

func NewScoredPhraseFilter(blocked []string, weighted []WeightedPhrase, threshold int) (*PhraseFilter, error) {
	return NewPhraseFilterWithExceptions(blocked, weighted, nil, threshold)
}

// NewPhraseFilterWithExceptions builds an Aho-Corasick filter with optional
// exception phrases. When any exception phrase matches the inspected stream,
// subsequent hard blocks and score accumulations are suppressed for that
// stream. The exception is detected at the byte its terminal node fires;
// matches earlier in the same stream still trigger blocks (streaming model
// cannot rewind bytes already sent to the client).
func NewPhraseFilterWithExceptions(blocked []string, weighted []WeightedPhrase, exceptions []string, threshold int) (*PhraseFilter, error) {
	if threshold < 0 {
		return nil, fmt.Errorf("semantic score threshold cannot be negative")
	}
	filter := &PhraseFilter{
		nodes:     []ahoNode{{}},
		threshold: threshold,
	}
	for _, phrase := range blocked {
		filter.addPhrase(phrase, 0, true, false)
	}
	for _, phrase := range weighted {
		if phrase.Weight <= 0 {
			return nil, fmt.Errorf("semantic phrase %q weight must be positive", phrase.Phrase)
		}
		if threshold == 0 {
			return nil, fmt.Errorf("semantic score threshold must be positive when weighted phrases are configured")
		}
		filter.addPhrase(phrase.Phrase, phrase.Weight, false, false)
	}
	for _, phrase := range exceptions {
		filter.addPhrase(phrase, 0, false, true)
	}
	filter.buildFailures()
	return filter, nil
}

func (f *PhraseFilter) addPhrase(phrase string, score int, hard, exception bool) {
	normalized := normalizePhrase(phrase)
	if normalized == "" {
		return
	}
	node := int32(0)
	for i := 0; i < len(normalized); i++ {
		b := normalized[i]
		next := f.nodes[node].next[b]
		if next == 0 {
			next = int32(len(f.nodes))
			f.nodes = append(f.nodes, ahoNode{})
			f.nodes[node].next[b] = next
		}
		node = next
	}
	f.nodes[node].hard = f.nodes[node].hard || hard
	f.nodes[node].excpt = f.nodes[node].excpt || exception
	f.nodes[node].score += int32(score)
	if hard || score > 0 || exception {
		f.nodes[node].phrase = phrase
	}
}

func normalizePhrase(phrase string) string {
	return strings.ToLower(strings.TrimSpace(phrase))
}

// buildFailures runs the standard Aho-Corasick BFS to compute fail links, then
// "compiles" the goto function into the next[] table by overwriting empty
// transitions with the fail-chain target. The result is a fully deterministic
// transition table where nextState() degenerates to one array load per byte,
// no fail-chain walk needed at runtime.
func (f *PhraseFilter) buildFailures() {
	queue := make([]int32, 0, len(f.nodes))
	for b := 0; b < 256; b++ {
		child := f.nodes[0].next[b]
		if child != 0 {
			f.nodes[child].fail = 0
			queue = append(queue, child)
		}
	}
	for head := 0; head < len(queue); head++ {
		node := queue[head]
		for b := 0; b < 256; b++ {
			child := f.nodes[node].next[b]
			if child == 0 {
				// Empty transition: inherit goto from the fail target. This
				// converts the partial NFA into a complete DFA so nextState()
				// no longer needs to walk fail links at runtime.
				f.nodes[node].next[b] = f.nodes[f.nodes[node].fail].next[b]
				continue
			}
			fail := f.nodes[node].fail
			f.nodes[child].fail = f.nodes[fail].next[b]
			f.nodes[child].hard = f.nodes[child].hard || f.nodes[f.nodes[child].fail].hard
			f.nodes[child].excpt = f.nodes[child].excpt || f.nodes[f.nodes[child].fail].excpt
			f.nodes[child].score += f.nodes[f.nodes[child].fail].score
			if f.nodes[child].phrase == "" {
				f.nodes[child].phrase = f.nodes[f.nodes[child].fail].phrase
			}
			queue = append(queue, child)
		}
	}
}

func (f *PhraseFilter) NewFilter() FilterEngine {
	return &phraseStreamFilter{compiled: f}
}

func (f *PhraseFilter) ProcessChunk(in []byte) ([]byte, bool, error) {
	return f.NewFilter().ProcessChunk(in)
}

type Decisioner interface {
	Decision() (blocked bool, matchType string, value string)
}

type LogDecisioner interface {
	LogDecision() (matched bool, suppressed bool, matchType string, value string)
}

type LogPhraseCtxKey struct{}

type LogPhraseMatch struct {
	Matched    bool
	Suppressed bool
	MatchType  string
	Value      string
}

type phraseStreamFilter struct {
	compiled      *PhraseFilter
	node          int32
	score         int32
	excepted      bool
	blockedPhrase string
	blockedType   string
	observeOnly   bool
}

func (f *phraseStreamFilter) Decision() (bool, string, string) {
	if f.blockedPhrase != "" && !f.observeOnly {
		return true, f.blockedType, f.blockedPhrase
	}
	return false, "", ""
}

func (f *phraseStreamFilter) LogDecision() (bool, bool, string, string) {
	if f.observeOnly {
		if f.excepted {
			return false, true, "", ""
		}
		if f.blockedPhrase != "" {
			return true, false, f.blockedType, f.blockedPhrase
		}
	}
	return false, false, "", ""
}

func (f *phraseStreamFilter) ProcessChunk(in []byte) ([]byte, bool, error) {
	if f.compiled == nil || len(f.compiled.nodes) <= 1 || len(in) == 0 {
		return in, false, nil
	}
	blocked, outLen, err := f.matchChunk(in)
	if err != nil {
		return nil, false, err
	}
	if blocked {
		return in[:outLen], true, nil
	}
	return in, blocked, nil
}

func (f *phraseStreamFilter) matchChunk(in []byte) (bool, int, error) {
	if len(f.compiled.nodes) == 0 {
		return false, 0, fmt.Errorf("phrase filter is not initialized")
	}
	nodes := f.compiled.nodes
	node := f.node
	score := f.score
	excepted := f.excepted
	threshold := int32(f.compiled.threshold)
	for i, b := range in {
		node = nodes[node].next[lowerASCII(b)]
		current := &nodes[node]
		if current.excpt {
			excepted = true
		}
		if excepted {
			continue
		}
		if current.hard {
			f.blockedPhrase = current.phrase
			f.blockedType = "phrase"
			if !f.observeOnly {
				f.node = node
				f.score = score
				f.excepted = excepted
				return true, i + 1, nil
			}
		}
		if current.score > 0 {
			score += current.score
			if threshold > 0 && score >= threshold {
				f.blockedPhrase = current.phrase
				f.blockedType = "phrase_score"
				if !f.observeOnly {
					f.node = node
					f.score = score
					f.excepted = excepted
					return true, i + 1, nil
				}
			}
		}
	}
	f.node = node
	f.score = score
	f.excepted = excepted
	return false, len(in), nil
}

func lowerASCII(b byte) byte {
	if 'A' <= b && b <= 'Z' {
		return b + ('a' - 'A')
	}
	return b
}
