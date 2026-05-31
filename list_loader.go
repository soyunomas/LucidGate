package main

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// listLine represents a single textual entry sourced from a list file, kept
// together with the file/line it came from so parsing errors stay actionable.
type listLine struct {
	Path string
	Line int
	Text string
}

// loadTextListFiles reads each path in the declared order. If an entry is a
// directory, the files inside are read in alphabetical order. Each file is
// parsed line by line: comments (`#`) and blank lines are dropped, and
// `.Include<path>` directives are followed (with cycle detection). Returned
// entries preserve the order of first appearance.
func loadTextListFiles(configDir string, paths []string) ([]string, error) {
	files, err := expandListPaths(configDir, paths)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, file := range files {
		stack := map[string]bool{}
		lines, err := loadPlainListFile(file, stack)
		if err != nil {
			return nil, err
		}
		for _, ln := range lines {
			out = append(out, ln.Text)
		}
	}
	return out, nil
}

// loadWeightedPhraseFiles parses the e2guardian-style `<phrase><weight>` syntax
// from every file referenced by paths. Errors include the source file and line
// number.
func loadWeightedPhraseFiles(configDir string, paths []string) ([]SemanticPhraseConfig, error) {
	files, err := expandListPaths(configDir, paths)
	if err != nil {
		return nil, err
	}
	var out []SemanticPhraseConfig
	for _, file := range files {
		stack := map[string]bool{}
		lines, err := loadPlainListFile(file, stack)
		if err != nil {
			return nil, err
		}
		for _, ln := range lines {
			phrase, weight, err := parseWeightedLine(ln.Text)
			if err != nil {
				return nil, fmt.Errorf("%s:%d: %w", ln.Path, ln.Line, err)
			}
			out = append(out, SemanticPhraseConfig{Phrase: phrase, Weight: weight})
		}
	}
	return out, nil
}

// loadSubstitutionFiles parses `search => replace` rules from external files.
func loadSubstitutionFiles(configDir string, paths []string) ([]SubstitutionConfig, error) {
	files, err := expandListPaths(configDir, paths)
	if err != nil {
		return nil, err
	}
	var out []SubstitutionConfig
	for _, file := range files {
		stack := map[string]bool{}
		lines, err := loadPlainListFile(file, stack)
		if err != nil {
			return nil, err
		}
		for _, ln := range lines {
			search, replace, err := parseSubstitutionLine(ln.Text)
			if err != nil {
				return nil, fmt.Errorf("%s:%d: %w", ln.Path, ln.Line, err)
			}
			out = append(out, SubstitutionConfig{Search: search, Replace: replace})
		}
	}
	return out, nil
}

// loadRegexSubstitutionFiles parses `pattern => replace` regexp substitution
// rules from external files. Regexes are compiled later with their source
// location attached to the config so reload errors stay actionable.
func loadRegexSubstitutionFiles(configDir string, paths []string) ([]RegexSubstitutionConfig, error) {
	files, err := expandListPaths(configDir, paths)
	if err != nil {
		return nil, err
	}
	var out []RegexSubstitutionConfig
	for _, file := range files {
		stack := map[string]bool{}
		lines, err := loadPlainListFile(file, stack)
		if err != nil {
			return nil, err
		}
		for _, ln := range lines {
			pattern, replace, err := parseSubstitutionLine(ln.Text)
			if err != nil {
				return nil, fmt.Errorf("%s:%d: %w", ln.Path, ln.Line, err)
			}
			out = append(out, RegexSubstitutionConfig{
				Pattern: pattern,
				Replace: replace,
				Source:  fmt.Sprintf("%s:%d", ln.Path, ln.Line),
			})
		}
	}
	return out, nil
}

// expandListPaths walks each declared path and produces the ordered list of
// files to parse. Directories expand to their alphabetically sorted contents.
// Relative paths are anchored to configDir.
func expandListPaths(configDir string, paths []string) ([]string, error) {
	var out []string
	for _, p := range paths {
		resolved := p
		if !filepath.IsAbs(resolved) {
			resolved = filepath.Join(configDir, resolved)
		}
		info, err := os.Stat(resolved)
		if err != nil {
			return nil, fmt.Errorf("stat list path %s: %w", resolved, err)
		}
		if !info.IsDir() {
			out = append(out, resolved)
			continue
		}
		entries, err := os.ReadDir(resolved)
		if err != nil {
			return nil, fmt.Errorf("read list dir %s: %w", resolved, err)
		}
		sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			out = append(out, filepath.Join(resolved, entry.Name()))
		}
	}
	return out, nil
}

// loadPlainListFile reads one file, dropping comments/blank lines and
// recursively expanding `.Include<...>` directives. The stack map detects
// include cycles. Returned listLine entries preserve the original file/line
// for downstream error reporting.
func loadPlainListFile(path string, stack map[string]bool) ([]listLine, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("resolve list path %s: %w", path, err)
	}
	if stack[abs] {
		return nil, fmt.Errorf("include cycle detected at %s", abs)
	}
	stack[abs] = true
	defer delete(stack, abs)

	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open list file %s: %w", path, err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	var out []listLine
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		raw := scanner.Text()
		stripped := stripComment(raw)
		stripped = strings.TrimSpace(stripped)
		if stripped == "" {
			continue
		}
		if inc, ok := parseIncludeLine(stripped); ok {
			if inc == "" {
				return nil, fmt.Errorf("%s:%d: empty .Include path", path, lineNo)
			}
			incPath := inc
			if !filepath.IsAbs(incPath) {
				incPath = filepath.Join(filepath.Dir(path), incPath)
			}
			nested, err := loadPlainListFile(incPath, stack)
			if err != nil {
				return nil, err
			}
			out = append(out, nested...)
			continue
		}
		out = append(out, listLine{Path: path, Line: lineNo, Text: stripped})
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan list file %s: %w", path, err)
	}
	return out, nil
}

// parseIncludeLine recognises the e2guardian `.Include<path>` directive.
func parseIncludeLine(line string) (string, bool) {
	const prefix = ".Include<"
	if !strings.HasPrefix(line, prefix) {
		return "", false
	}
	if !strings.HasSuffix(line, ">") {
		return "", false
	}
	inner := line[len(prefix) : len(line)-1]
	return strings.TrimSpace(inner), true
}

// parseWeightedLine parses `<phrase><weight>` style entries. Both segments
// must be present; weight must be a positive integer.
func parseWeightedLine(line string) (string, int, error) {
	if !strings.HasPrefix(line, "<") {
		return "", 0, fmt.Errorf("invalid weighted phrase syntax %q (expected <phrase><weight>)", line)
	}
	end := strings.Index(line, ">")
	if end <= 1 {
		return "", 0, fmt.Errorf("invalid weighted phrase syntax %q (missing closing '>' for phrase)", line)
	}
	phrase := line[1:end]
	rest := strings.TrimSpace(line[end+1:])
	if !strings.HasPrefix(rest, "<") || !strings.HasSuffix(rest, ">") || len(rest) < 3 {
		return "", 0, fmt.Errorf("invalid weighted phrase syntax %q (missing <weight>)", line)
	}
	weightStr := rest[1 : len(rest)-1]
	weight, err := strconv.Atoi(strings.TrimSpace(weightStr))
	if err != nil {
		return "", 0, fmt.Errorf("invalid weight %q: %w", weightStr, err)
	}
	if weight <= 0 {
		return "", 0, fmt.Errorf("weight must be positive, got %d", weight)
	}
	if phrase == "" {
		return "", 0, fmt.Errorf("weighted phrase cannot be empty")
	}
	return phrase, weight, nil
}

// parseSubstitutionLine parses a `search => replace` rule. Replace may be
// empty (deletion); search must be present.
func parseSubstitutionLine(line string) (string, string, error) {
	idx := strings.Index(line, "=>")
	if idx < 0 {
		return "", "", fmt.Errorf("missing '=>' separator in substitution rule %q", line)
	}
	search := strings.TrimSpace(line[:idx])
	replace := strings.TrimSpace(line[idx+2:])
	if search == "" {
		return "", "", fmt.Errorf("substitution search cannot be empty")
	}
	return search, replace, nil
}

// stripComment removes `# ...` trailing comments while preserving any leading
// content before the marker.
func stripComment(line string) string {
	if i := strings.Index(line, "#"); i >= 0 {
		return line[:i]
	}
	return line
}

// appendUniqueStrings appends entries from extra that are not already in base,
// preserving the input order. The first occurrence wins.
func appendUniqueStrings(base, extra []string) []string {
	if len(extra) == 0 {
		return base
	}
	seen := make(map[string]struct{}, len(base)+len(extra))
	for _, v := range base {
		seen[v] = struct{}{}
	}
	for _, v := range extra {
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		base = append(base, v)
	}
	return base
}

// mergeWeightedPhrases combines embedded TOML weighted phrases with the ones
// loaded from external lists. Duplicates with conflicting weights produce a
// clear error; identical duplicates are silently deduplicated.
func mergeWeightedPhrases(base, extra []SemanticPhraseConfig) ([]SemanticPhraseConfig, error) {
	if len(extra) == 0 {
		return base, nil
	}
	seen := make(map[string]int, len(base)+len(extra))
	for _, p := range base {
		seen[p.Phrase] = p.Weight
	}
	for _, p := range extra {
		if existing, ok := seen[p.Phrase]; ok {
			if existing != p.Weight {
				return nil, fmt.Errorf("duplicate weighted phrase %q with conflicting weights %d and %d", p.Phrase, existing, p.Weight)
			}
			continue
		}
		seen[p.Phrase] = p.Weight
		base = append(base, p)
	}
	return base, nil
}

// mergeSubstitutions combines embedded TOML substitution rules with external
// ones. Any duplicate `search` key (regardless of replacement) is rejected.
func mergeSubstitutions(base, extra []SubstitutionConfig) ([]SubstitutionConfig, error) {
	if len(extra) == 0 {
		return base, nil
	}
	seen := make(map[string]struct{}, len(base)+len(extra))
	for _, r := range base {
		seen[r.Search] = struct{}{}
	}
	for _, r := range extra {
		if _, ok := seen[r.Search]; ok {
			return nil, fmt.Errorf("duplicate substitution search %q", r.Search)
		}
		seen[r.Search] = struct{}{}
		base = append(base, r)
	}
	return base, nil
}

// mergeRegexSubstitutions combines embedded TOML regexp substitutions with
// external ones. Duplicate patterns are rejected because replacement order is
// significant and ambiguity would make reloads surprising.
func mergeRegexSubstitutions(base, extra []RegexSubstitutionConfig) ([]RegexSubstitutionConfig, error) {
	if len(extra) == 0 {
		return base, nil
	}
	seen := make(map[string]struct{}, len(base)+len(extra))
	for _, r := range base {
		seen[r.Pattern] = struct{}{}
	}
	for _, r := range extra {
		if _, ok := seen[r.Pattern]; ok {
			return nil, fmt.Errorf("duplicate regex substitution pattern %q", r.Pattern)
		}
		seen[r.Pattern] = struct{}{}
		base = append(base, r)
	}
	return base, nil
}
