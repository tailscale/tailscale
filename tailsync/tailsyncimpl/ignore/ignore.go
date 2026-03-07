// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// Package ignore provides gitignore-style pattern matching for tailsync.
package ignore

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
)

// DefaultPatterns are always excluded from sync.
var DefaultPatterns = []string{
	".git/",
	".svn/",
	".hg/",
	"node_modules/",
	"__pycache__/",
	"*.pyc",
	".DS_Store",
	"Thumbs.db",
	"*.swp",
	"*.swo",
	"*~",
	".tailsync-conflicts/",
}

// Matcher evaluates whether a given path should be ignored.
type Matcher struct {
	patterns []pattern
}

type pattern struct {
	glob   string
	isDir  bool // trailing slash means directory-only
	negate bool
}

// New creates a Matcher from the given patterns.
func New(patterns []string) *Matcher {
	m := &Matcher{}
	for _, p := range patterns {
		m.addPattern(p)
	}
	return m
}

// NewWithDefaults creates a Matcher with the default patterns plus additional ones.
func NewWithDefaults(additional []string) *Matcher {
	all := make([]string, 0, len(DefaultPatterns)+len(additional))
	all = append(all, DefaultPatterns...)
	all = append(all, additional...)
	return New(all)
}

// LoadFile loads patterns from a .tailsyncignore file and combines them
// with defaults and any additional patterns.
func LoadFile(path string, additional []string) *Matcher {
	filePatterns := readIgnoreFile(path)
	all := make([]string, 0, len(DefaultPatterns)+len(filePatterns)+len(additional))
	all = append(all, DefaultPatterns...)
	all = append(all, filePatterns...)
	all = append(all, additional...)
	return New(all)
}

func readIgnoreFile(path string) []string {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	var patterns []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		patterns = append(patterns, line)
	}
	return patterns
}

func (m *Matcher) addPattern(raw string) {
	if raw == "" {
		return
	}
	p := pattern{}
	if strings.HasPrefix(raw, "!") {
		p.negate = true
		raw = raw[1:]
	}
	if strings.HasSuffix(raw, "/") {
		p.isDir = true
		raw = strings.TrimSuffix(raw, "/")
	}
	p.glob = raw
	m.patterns = append(m.patterns, p)
}

// Match reports whether the given relative path should be ignored.
// isDir indicates whether the path is a directory.
func (m *Matcher) Match(relPath string, isDir bool) bool {
	if m == nil {
		return false
	}
	matched := false
	for _, p := range m.patterns {
		if p.isDir && !isDir {
			// Directory-only patterns still match files inside that directory.
			if !hasAncestor(p.glob, relPath) {
				continue
			}
			matched = !p.negate
			continue
		}
		if matchPattern(p.glob, relPath) {
			matched = !p.negate
		}
	}
	return matched
}

// hasAncestor reports whether any ancestor directory of relPath matches glob.
func hasAncestor(glob, relPath string) bool {
	dir := relPath
	for {
		dir = filepath.Dir(dir)
		if dir == "." || dir == "/" {
			break
		}
		if matchPattern(glob, dir) {
			return true
		}
	}
	return false
}

// matchPattern checks if relPath matches glob. It checks both the full path
// and the base name, matching gitignore behavior.
func matchPattern(glob, relPath string) bool {
	// If the pattern contains a separator, match against full path.
	if strings.Contains(glob, "/") || strings.Contains(glob, string(filepath.Separator)) {
		ok, _ := filepath.Match(glob, relPath)
		return ok
	}
	// Otherwise match against each path component.
	base := filepath.Base(relPath)
	ok, _ := filepath.Match(glob, base)
	if ok {
		return true
	}
	// Also try matching against each directory component.
	dir := relPath
	for {
		dir = filepath.Dir(dir)
		if dir == "." || dir == "/" {
			break
		}
		component := filepath.Base(dir)
		ok, _ = filepath.Match(glob, component)
		if ok {
			return true
		}
	}
	return false
}
