package proxy

import "testing"

func TestRegexSubstitutionReplacesAcrossChunks(t *testing.T) {
	filter, err := NewSubstitutionFilterWithRegex(nil, []RegexSubstitutionRule{
		{
			Pattern:        `ca.*sa\.png`,
			Replace:        "carcasa.png",
			MaxWindowBytes: 64,
		},
	})
	if err != nil {
		t.Fatalf("NewSubstitutionFilterWithRegex() error = %v", err)
	}
	stream := filter.NewFilter()

	first, blocked, err := stream.ProcessChunk([]byte("before /img/ca"))
	if err != nil {
		t.Fatalf("ProcessChunk(first) error = %v", err)
	}
	if blocked {
		t.Fatal("blocked = true, want substitution only")
	}
	second, blocked, err := stream.ProcessChunk([]byte("rpeta/sa.png after"))
	if err != nil {
		t.Fatalf("ProcessChunk(second) error = %v", err)
	}
	if blocked {
		t.Fatal("blocked = true, want substitution only")
	}
	tail, err := stream.(flushingFilter).Flush()
	if err != nil {
		t.Fatalf("Flush() error = %v", err)
	}
	got := string(first) + string(second) + string(tail)
	want := "before /img/carcasa.png after"
	if got != want {
		t.Fatalf("stream = %q, want %q", got, want)
	}
}

func TestRegexSubstitutionSupportsCaptureExpansion(t *testing.T) {
	filter, err := NewSubstitutionFilterWithRegex(nil, []RegexSubstitutionRule{
		{Pattern: `image-([0-9]+)\.png`, Replace: `asset-$1.webp`, MaxWindowBytes: 64},
	})
	if err != nil {
		t.Fatalf("NewSubstitutionFilterWithRegex() error = %v", err)
	}
	stream := filter.NewFilter()

	out, blocked, err := stream.ProcessChunk([]byte("image-42.png"))
	if err != nil {
		t.Fatalf("ProcessChunk() error = %v", err)
	}
	if blocked {
		t.Fatal("blocked = true, want substitution only")
	}
	tail, err := stream.(flushingFilter).Flush()
	if err != nil {
		t.Fatalf("Flush() error = %v", err)
	}
	if got := string(out) + string(tail); got != "asset-42.webp" {
		t.Fatalf("stream = %q, want capture replacement", got)
	}
}

func TestRegexSubstitutionRejectsInvalidPattern(t *testing.T) {
	_, err := NewSubstitutionFilterWithRegex(nil, []RegexSubstitutionRule{
		{Pattern: `[`, Replace: "x", Source: "rules.list:2"},
	})
	if err == nil {
		t.Fatal("NewSubstitutionFilterWithRegex() error = nil, want invalid regex")
	}
}
