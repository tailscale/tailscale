// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package symcost

import (
	"sort"
)

// Cost is a per-target attribution result. It carries a breakdown of
// bytes by section and a list of contributing items so callers can
// drill down from a headline number to the specific symbols/types/
// itabs/funcs that produced the cost.
type Cost struct {
	// Target is the user's query string (a receiver template like
	// "tailscale.com/util/eventbus.Publisher" or a function
	// template like "...(*Publisher[…]).Publish").
	Target string

	// Sections breaks the total cost down by section name.
	Sections map[string]int64
	// Total is the sum across Sections.
	Total int64

	// Funcs lists all functions that contributed (either by name or
	// by association with a receiver), sorted by descending body+
	// pclntab cost.
	Funcs []FuncCost
	// Types lists all type descriptors attributed, sorted by
	// descending size.
	Types []TypeCost
	// Itabs lists all itabs attributed, sorted by descending size.
	Itabs []ItabCost
	// NamedSyms lists named symbols (excluding those covered by
	// Funcs/Itabs) attributed, sorted by descending size.
	NamedSyms []SymCost
}

// FuncCost is one function's contribution.
type FuncCost struct {
	Name         string
	BodyBytes    int64
	PclntabBytes int64
}

// Total is body+pclntab cost.
func (fc FuncCost) Total() int64 { return fc.BodyBytes + fc.PclntabBytes }

// TypeCost is one type descriptor's contribution.
type TypeCost struct {
	Name      string
	Bytes     int64
	NameBytes int64
}

// Total is descriptor+name cost.
func (tc TypeCost) Total() int64 { return tc.Bytes + tc.NameBytes }

// ItabCost is one itab's contribution.
type ItabCost struct {
	SymName       string
	ConcreteName  string
	InterfaceName string
	Bytes         int64
}

// SymCost is one named symbol's contribution.
type SymCost struct {
	Name    string
	Section string
	Bytes   int64
}

// CostByReceiver returns the aggregate cost of all symbols, types,
// itabs, and named rodata associated with the given receiver type.
//
// receiver is a type name without the instantiation suffix, e.g.
// "tailscale.com/util/eventbus.Publisher" or just "Publisher" (the
// latter is matched as a substring against the package-qualified
// name). The returned Cost includes:
//
//   - all methods on the receiver, across instantiations (.text and
//     pclntab attribution)
//   - all generic dictionaries naming the receiver (.dict.Receiver[…])
//   - all type-equality and type-hash functions for the receiver
//   - all itabs whose concrete type is the receiver
//   - the runtime type descriptor for every instantiation of the
//     receiver
//
// If receiver names a non-generic type, the [...] suffix doesn't
// apply and the function still works correctly: it matches the type
// directly.
func (b *Binary) CostByReceiver(receiver string) Cost {
	c := Cost{
		Target:   receiver,
		Sections: map[string]int64{},
	}
	matchTpl := receiverMatcher(receiver)

	// 1. Functions: receiver methods, eq/hash funcs, dicts (which
	//    live in .rodata, not .text, but we look for them in the
	//    symbol table).
	for _, f := range b.Funcs {
		if !matchTpl(f.Name) {
			continue
		}
		fc := FuncCost{
			Name:         f.Name,
			BodyBytes:    f.BodyBytes(),
			PclntabBytes: f.PclntabBytes,
		}
		c.Funcs = append(c.Funcs, fc)
		c.Sections[".text"] += fc.BodyBytes
		c.Sections[".gopclntab"] += fc.PclntabBytes
	}

	// 2. Itabs by concrete-name match.
	for _, it := range b.Itabs {
		if matchTpl(it.ConcreteName) || matchTpl(it.SymName) {
			c.Itabs = append(c.Itabs, ItabCost{
				SymName:       it.SymName,
				ConcreteName:  it.ConcreteName,
				InterfaceName: it.InterfaceName,
				Bytes:         it.Bytes,
			})
			c.Sections[".rodata"] += it.Bytes
		}
	}

	// 3. Type descriptors: walk Types map for matching names.
	//    Names in the type-descriptor table can use the short or
	//    long form; matchTpl handles both.
	for name, ts := range b.Types {
		if !matchTpl(name) {
			continue
		}
		for _, t := range ts {
			c.Types = append(c.Types, TypeCost{
				Name:      t.Name,
				Bytes:     t.Bytes,
				NameBytes: t.NameBytes,
			})
			c.Sections[".rodata"] += t.TotalBytes()
		}
	}

	// 4. Named symbols not yet accounted for. These are typically
	//    dicts, eq/hash, and other rodata items the symbol table
	//    knows about. Skip anything that's a function (already
	//    counted via Funcs) or an itab (already counted).
	covered := make(map[string]bool, len(c.Funcs)+len(c.Itabs))
	for _, f := range c.Funcs {
		covered[f.Name] = true
	}
	for _, it := range c.Itabs {
		covered[it.SymName] = true
	}
	for _, s := range b.Syms {
		if !matchTpl(s.Name) || covered[s.Name] || s.Size == 0 {
			continue
		}
		c.NamedSyms = append(c.NamedSyms, SymCost{
			Name:    s.Name,
			Section: s.Section,
			Bytes:   int64(s.Size),
		})
		c.Sections[s.Section] += int64(s.Size)
	}

	c.finalize()
	return c
}

// CostByFunction returns the aggregate cost of one function (or one
// generic function template — pass the normalized name with the
// `[…]` placeholder, or any concrete instantiation, and we'll match
// all instantiations sharing the template).
//
// The returned Cost includes the function's body bytes and its
// share of pclntab. Disassembly-based attribution of referenced
// rodata is added in a separate code path; see
// CostByFunctionWithRefs.
func (b *Binary) CostByFunction(name string) Cost {
	c := Cost{
		Target:   name,
		Sections: map[string]int64{},
	}
	tpl := normalize(name)
	for _, f := range b.Funcs {
		if normalize(f.Name) != tpl && f.Name != name {
			continue
		}
		fc := FuncCost{
			Name:         f.Name,
			BodyBytes:    f.BodyBytes(),
			PclntabBytes: f.PclntabBytes,
		}
		c.Funcs = append(c.Funcs, fc)
		c.Sections[".text"] += fc.BodyBytes
		c.Sections[".gopclntab"] += fc.PclntabBytes
	}
	c.finalize()
	return c
}

// finalize sorts the per-category lists and computes Total.
func (c *Cost) finalize() {
	sort.Slice(c.Funcs, func(i, j int) bool {
		return c.Funcs[i].Total() > c.Funcs[j].Total()
	})
	sort.Slice(c.Types, func(i, j int) bool {
		return c.Types[i].Total() > c.Types[j].Total()
	})
	sort.Slice(c.Itabs, func(i, j int) bool {
		return c.Itabs[i].Bytes > c.Itabs[j].Bytes
	})
	sort.Slice(c.NamedSyms, func(i, j int) bool {
		return c.NamedSyms[i].Bytes > c.NamedSyms[j].Bytes
	})
	for _, v := range c.Sections {
		c.Total += v
	}
}

// receiverMatcher returns a function that reports whether a symbol
// or type name "belongs to" the given receiver.
//
// The query string can be a fully-qualified receiver
// ("tailscale.com/util/eventbus.Publisher") or a short name
// ("Publisher"). The matcher accepts a symbol if any of the
// following appears within it as a delimited identifier:
//
//   - the receiver name itself (matches type-descriptor names,
//     dict entries, eq/hash entries, value-receiver methods)
//   - the receiver written inside a Go method-receiver wrapper:
//     "<pkg>.(*<Type>" or "<pkg>.(<Type>" — Go encodes pointer
//     and value receivers using these forms when generating
//     method symbol names.
//
// For qualified inputs ("pkg.Type"), the package and type segments
// are checked separately so that the encoded form "pkg.(*Type[...])."
// is recognized.
//
// The matcher is delimiter-aware: it ensures that what comes after
// the matched substring is a syntactic break (`[`, `.`, `,`, `]`,
// `)`, end of string), so a query for "main.Foo" doesn't accidentally
// match "main.FooBar".
func receiverMatcher(receiver string) func(string) bool {
	if receiver == "" {
		return func(string) bool { return false }
	}
	// Build the list of forms we accept. For an input "pkg.Type",
	// also accept:
	//   - "pkg.(*Type" / "pkg.(Type": Go method-receiver name mangling
	//   - "shortpkg.Type": the type-descriptor short form (Go stores
	//     type names using only the final path segment of the
	//     package, e.g. "eventbus.Publisher" instead of
	//     "tailscale.com/util/eventbus.Publisher")
	forms := []string{receiver}
	if pkg, typ, ok := splitLastDot(receiver); ok {
		forms = append(forms,
			pkg+".(*"+typ,     // pointer-receiver method: pkg.(*Type[...])
			pkg+".("+typ,      // value-receiver method:   pkg.(Type[...])
			pkg+"..dict."+typ, // generic dictionary:  pkg..dict.Type[...]
		)
		// Short-package form: trim everything before the last "/"
		// in the package portion. The type name stays the same.
		// This handles type-descriptor names like "eventbus.Publisher"
		// instead of "tailscale.com/util/eventbus.Publisher".
		short := pkg
		if slash := lastByteOff(pkg, '/'); slash >= 0 {
			short = pkg[slash+1:]
		}
		if short != pkg {
			forms = append(forms,
				short+"."+typ,
				short+".(*"+typ,
				short+".("+typ,
			)
		}
	}

	return func(name string) bool {
		if name == "" {
			return false
		}
		for _, want := range forms {
			if matchDelimited(name, want) {
				return true
			}
		}
		return false
	}
}

// matchDelimited reports whether want appears in name as a
// delimited identifier — i.e. surrounded by start/end of string or
// by Go symbol-table punctuation characters (excluding identifier
// continuations).
func matchDelimited(name, want string) bool {
	for i := 0; i+len(want) <= len(name); i++ {
		if name[i:i+len(want)] != want {
			continue
		}
		// Left boundary: start of string or symbol punctuation.
		if i > 0 {
			c := name[i-1]
			switch c {
			case '*', '.', '(', '[', ',', ' ':
				// ok
			default:
				continue
			}
		}
		// Right boundary: end of string or punctuation. We accept
		// '*' and '(' here too, because the encoded receiver forms
		// like "pkg.(*Type" end before the next character which is
		// a type continuation like `[T]` or `).Method`.
		if j := i + len(want); j < len(name) {
			c := name[j]
			switch c {
			case '.', '[', ',', ']', ')', ' ':
				// ok
			default:
				continue
			}
		}
		return true
	}
	return false
}

// lastByteOff returns the index of the last occurrence of c in s,
// or -1.
func lastByteOff(s string, c byte) int {
	for i := len(s) - 1; i >= 0; i-- {
		if s[i] == c {
			return i
		}
	}
	return -1
}

// splitLastDot splits s at the last unbracketed '.' and returns the
// (prefix, suffix, ok) triple. Returns ok=false if there is no such
// dot. Used to split a qualified receiver name into its package path
// and type-name parts.
func splitLastDot(s string) (string, string, bool) {
	depth := 0
	last := -1
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '[', '(':
			depth++
		case ']', ')':
			if depth > 0 {
				depth--
			}
		case '.':
			if depth == 0 {
				last = i
			}
		}
	}
	if last < 0 {
		return "", "", false
	}
	return s[:last], s[last+1:], true
}
