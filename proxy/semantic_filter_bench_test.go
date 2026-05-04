package proxy

import (
	"strings"
	"testing"
)

// BenchmarkPhraseFilterProcessChunk measures the per-byte cost of the
// Aho-Corasick scan over a 64 KiB chunk that contains no match. This is the
// hot path for every textual response inspected by LucidGate, so the benchmark
// gates regressions on the array-backed transition table introduced by Fase
// 7.5.1. Target: < 5 ns/byte on commodity x86 (was ~30-60 ns/byte with the
// previous map[byte]int implementation).
func BenchmarkPhraseFilterProcessChunk(b *testing.B) {
	phrases := []string{
		"credential dump",
		"malware kit",
		"exfiltration channel",
		"ransom note",
		"command and control",
		"reverse shell",
	}
	filter, err := NewPhraseFilter(phrases)
	if err != nil {
		b.Fatalf("NewPhraseFilter: %v", err)
	}
	stream := filter.NewFilter()
	chunk := []byte(strings.Repeat("the quick brown fox jumps over the lazy dog. ", 1500)[:64*1024])
	b.SetBytes(int64(len(chunk)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, err := stream.ProcessChunk(chunk)
		if err != nil {
			b.Fatalf("ProcessChunk: %v", err)
		}
	}
}
