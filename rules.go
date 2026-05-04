package main

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

func loadRuleDomains(cfg *appConfig) ([]string, error) {
	if cfg == nil || len(cfg.IncludeDirs) == 0 {
		return nil, nil
	}
	baseDir := "."
	if cfg.ConfigPath != "" {
		baseDir = filepath.Dir(cfg.ConfigPath)
	}
	var domains []string
	for _, dir := range cfg.IncludeDirs {
		if !filepath.IsAbs(dir) {
			dir = filepath.Join(baseDir, dir)
		}
		entries, err := os.ReadDir(dir)
		if err != nil {
			return nil, fmt.Errorf("read include_dir %s: %w", dir, err)
		}
		sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			path := filepath.Join(dir, entry.Name())
			fileDomains, err := loadDomainFile(path)
			if err != nil {
				return nil, err
			}
			domains = append(domains, fileDomains...)
		}
	}
	return domains, nil
}

func loadDomainFile(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open rule file %s: %w", path, err)
	}
	defer f.Close()

	var domains []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if before, _, ok := strings.Cut(line, "#"); ok {
			line = before
		}
		line = strings.TrimSpace(line)
		line = strings.TrimPrefix(line, ".")
		line = strings.TrimSuffix(line, ".")
		if line == "" {
			continue
		}
		domains = append(domains, strings.ToLower(line))
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan rule file %s: %w", path, err)
	}
	return domains, nil
}
