// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// Package symcost analyzes a Go binary's symbol table to find which
// generic ("parameterized") functions and types are most expensive in
// aggregate.
//
// Go generics are implemented with GC-shape stenciling: the compiler
// emits one copy of a generic function/method body per distinct GC
// shape of its type parameters, plus per-T thin wrappers (Close,
// itabs, type descriptors) for each concrete instantiation. Both the
// stencils and the per-T wrappers cost binary size, and the cost
// scales with the number of distinct type arguments used at call
// sites across the program.
//
// symcost reads `go tool nm -size` output, normalizes generic
// instantiation suffixes (the [...] payload, including the
// `go.shape.*` markers Go emits for stencils) into a single template
// per generic, and reports per-template totals. The top of the output
// tells you which generic body is costing you the most binary size in
// aggregate; high min/max variance within a template tells you that
// GC-shape sharing is uneven and might point to dedup opportunities.
//
// This package is a measurement aid. It does not modify binaries.
package symcost

import (
	"bufio"
	"fmt"
	"io"
	"os/exec"
	"sort"
	"strconv"
	"strings"
)

// Symbol is a single entry from `go tool nm -size`.
type Symbol struct {
	// Addr is the symbol's address as printed by nm. May be empty
	// for unmapped symbols.
	Addr string
	// Size is the symbol size in bytes.
	Size int64
	// Type is the nm symbol type letter (e.g. T for text, R for
	// read-only data, B for BSS, etc.).
	Type string
	// Name is the symbol's full demangled name as printed by nm.
	Name string
}

// Group is a set of symbols that share a normalized name. For
// generic functions/methods, this collapses all instantiations of a
// single generic template into one Group; for non-generic symbols,
// the Group contains exactly one Symbol.
type Group struct {
	// Template is the normalized symbol name. Generic instantiation
	// suffixes (the bracketed type arguments) are replaced with
	// `[…]`. For example all of:
	//   foo.Bar[main.X].Baz
	//   foo.Bar[main.Y].Baz
	//   foo.Bar[go.shape.struct { F int }].Baz
	// share the template `foo.Bar[…].Baz`.
	Template string
	// Package is the import path the symbol belongs to, derived
	// from Template. Empty for symbols where a package can't be
	// inferred (e.g. linker-internal symbols).
	Package string
	// Members are the individual symbols in this group, sorted by
	// descending Size.
	Members []Symbol
	// Total is the sum of Size across Members.
	Total int64
	// Min, Max, and Avg are the size statistics across Members. Avg
	// is rounded down (integer division).
	Min, Max, Avg int64
}

// Analyze runs `go tool nm -size` against binaryPath and returns
// groups sorted by descending Total size.
//
// The provided context can be used to cancel the nm subprocess.
func Analyze(binaryPath string) ([]Group, error) {
	cmd := exec.Command("go", "tool", "nm", "-size", binaryPath)
	out, err := cmd.Output()
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			return nil, fmt.Errorf("`go tool nm -size %s`: %w: %s",
				binaryPath, err, string(ee.Stderr))
		}
		return nil, fmt.Errorf("`go tool nm -size %s`: %w", binaryPath, err)
	}
	return AnalyzeNMOutput(strings.NewReader(string(out)))
}

// AnalyzeNMOutput parses the textual output of `go tool nm -size`
// from r and returns the resulting groups, sorted by descending
// Total size. It is exposed separately so callers can feed in
// captured nm output (e.g. from a file) without re-invoking nm.
func AnalyzeNMOutput(r io.Reader) ([]Group, error) {
	syms, err := parseNM(r)
	if err != nil {
		return nil, err
	}
	return GroupSymbols(syms), nil
}

// GroupSymbols collapses syms into Groups keyed by the normalized
// template name. The result is sorted by descending Total size.
func GroupSymbols(syms []Symbol) []Group {
	byTemplate := make(map[string]*Group)
	for _, s := range syms {
		tpl := normalize(s.Name)
		g, ok := byTemplate[tpl]
		if !ok {
			g = &Group{Template: tpl, Package: packageOf(tpl)}
			byTemplate[tpl] = g
		}
		g.Members = append(g.Members, s)
		g.Total += s.Size
	}
	out := make([]Group, 0, len(byTemplate))
	for _, g := range byTemplate {
		sort.Slice(g.Members, func(i, j int) bool {
			return g.Members[i].Size > g.Members[j].Size
		})
		g.Min = g.Members[len(g.Members)-1].Size
		g.Max = g.Members[0].Size
		g.Avg = g.Total / int64(len(g.Members))
		out = append(out, *g)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Total != out[j].Total {
			return out[i].Total > out[j].Total
		}
		return out[i].Template < out[j].Template
	})
	return out
}

// IsGeneric reports whether the group's template represents a
// generic instantiation (i.e. its name contains the `[…]` placeholder
// that normalize() inserts).
func (g Group) IsGeneric() bool {
	return strings.Contains(g.Template, "[…]")
}

// Count returns the number of symbols in the group.
func (g Group) Count() int { return len(g.Members) }

// Filter is a set of optional restrictions applied to a slice of
// Groups. Zero values mean "no restriction".
type Filter struct {
	// PackageSubstr keeps only groups whose Package contains this
	// substring. Useful for narrowing to a single subsystem.
	PackageSubstr string
	// MinCount keeps only groups with at least this many member
	// symbols. Useful for finding heavily-instantiated generics
	// (set MinCount=2 to drop everything non-generic).
	MinCount int
	// MinTotal keeps only groups whose Total size is at least this
	// many bytes.
	MinTotal int64
	// GenericOnly, if true, keeps only groups representing generic
	// instantiations (Group.IsGeneric()).
	GenericOnly bool
}

// Apply returns groups filtered according to f, preserving order.
func (f Filter) Apply(groups []Group) []Group {
	out := groups[:0:0]
	for _, g := range groups {
		if f.PackageSubstr != "" && !strings.Contains(g.Package, f.PackageSubstr) {
			continue
		}
		if f.MinCount > 0 && g.Count() < f.MinCount {
			continue
		}
		if f.MinTotal > 0 && g.Total < f.MinTotal {
			continue
		}
		if f.GenericOnly && !g.IsGeneric() {
			continue
		}
		out = append(out, g)
	}
	return out
}

// parseNM parses `go tool nm -size` output. Each line has the form:
//
//	<addr-or-spaces> <size> <type> <name>
//
// where addr is hex (or blank), size is decimal, type is a single
// letter, and name is the rest of the line (and may contain spaces,
// e.g. inside `go.shape.struct { F int }`).
func parseNM(r io.Reader) ([]Symbol, error) {
	var syms []Symbol
	sc := bufio.NewScanner(r)
	// nm output can be wide for stencils with deep struct shapes.
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := sc.Text()
		if line == "" {
			continue
		}
		// nm prints addr right-justified in 16 columns; an unmapped
		// symbol leaves it blank.
		var addr string
		rest := line
		if len(line) >= 16 && strings.TrimSpace(line[:16]) != "" {
			addr = strings.TrimSpace(line[:16])
			rest = strings.TrimLeft(line[16:], " ")
		} else if len(line) >= 16 {
			rest = strings.TrimLeft(line[16:], " ")
		} else {
			rest = strings.TrimLeft(line, " ")
		}
		// Now rest is "<size> <type> <name>".
		sizeEnd := strings.IndexByte(rest, ' ')
		if sizeEnd < 0 {
			continue
		}
		size, err := strconv.ParseInt(rest[:sizeEnd], 10, 64)
		if err != nil {
			continue // not a parseable line; skip
		}
		rest = strings.TrimLeft(rest[sizeEnd:], " ")
		if len(rest) < 2 {
			continue
		}
		typ := rest[:1]
		name := strings.TrimLeft(rest[1:], " ")
		syms = append(syms, Symbol{
			Addr: addr,
			Size: size,
			Type: typ,
			Name: name,
		})
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("scanning nm output: %w", err)
	}
	return syms, nil
}

// normalize collapses every top-level bracketed segment in name into
// `[…]`. This turns all instantiations of a single generic template
// (whether by concrete types like `main.Event0` or by GC-shape names
// like `go.shape.struct { F0 int }`) into one template string.
//
// We deliberately collapse only top-level brackets — nested brackets
// inside the type argument list (rare in practice) are part of the
// payload and would be erased anyway. Bracket depth is tracked so we
// don't get confused by struct types whose own representation
// contains brackets.
func normalize(name string) string {
	var b strings.Builder
	b.Grow(len(name))
	depth := 0
	for i := 0; i < len(name); i++ {
		c := name[i]
		switch c {
		case '[':
			if depth == 0 {
				b.WriteString("[…]")
			}
			depth++
		case ']':
			if depth > 0 {
				depth--
			}
		default:
			if depth == 0 {
				b.WriteByte(c)
			}
		}
	}
	return b.String()
}

// packageOf returns the import path portion of a normalized symbol
// name, or empty string if one can't be determined.
//
// Go symbol names look like `import/path.Type.Method` or
// `import/path.func` or `import/path.(*Type).Method`. The package
// path ends at the last "/" segment's first ".".
func packageOf(name string) string {
	// Strip leading runtime/linker artifacts like "go:itab.".
	if rest, ok := strings.CutPrefix(name, "go:itab."); ok {
		// itabs are "go:itab.<concrete>,<interface>"; the interface
		// part's package is the most useful for grouping.
		if comma := strings.LastIndexByte(rest, ','); comma >= 0 {
			return packageOf(strings.TrimSpace(rest[comma+1:]))
		}
		name = rest
	}
	// Find the last "/" — everything before plus the next segment's
	// leading identifier is the package.
	slash := strings.LastIndexByte(name, '/')
	tail := name
	prefix := ""
	if slash >= 0 {
		prefix = name[:slash+1]
		tail = name[slash+1:]
	}
	// In tail, the package name is up to the first '.' that isn't
	// inside brackets/parens.
	depth := 0
	for i := 0; i < len(tail); i++ {
		switch tail[i] {
		case '[', '(':
			depth++
		case ']', ')':
			if depth > 0 {
				depth--
			}
		case '.':
			if depth == 0 {
				return prefix + tail[:i]
			}
		}
	}
	// No '.' found — give up.
	return ""
}
