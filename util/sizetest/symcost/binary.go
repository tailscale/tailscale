// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package symcost

import (
	"debug/elf"
	"debug/gosym"
	"encoding/binary"
	"errors"
	"fmt"
	"sort"
)

// Binary is an opened Go binary with parsed sections, symbol table,
// pclntab, type descriptor index, and itab index. It is the
// foundation on which per-receiver and per-function attribution is
// computed.
//
// Binary is currently ELF-only. Mach-O and PE support can be added
// without changing the user-facing API.
type Binary struct {
	// Path is the filesystem path to the binary.
	Path string

	// PtrSize is the target's pointer size in bytes (4 or 8).
	PtrSize int
	// ByteOrder is the target's byte order.
	ByteOrder binary.ByteOrder

	// Sections is the binary's section list keyed by name. Only
	// PROGBITS sections are populated.
	Sections map[string]*Section
	// Syms is the binary's static symbol table, sorted by address.
	// Each Sym carries its size as recorded in the ELF symtab (this
	// is the same source `go tool nm -size` reads).
	Syms []*Sym
	// SymsByName maps demangled symbol name to *Sym for quick lookup.
	// Names are unique in well-formed Go binaries.
	SymsByName map[string]*Sym

	// Funcs is the function range table from gopclntab, sorted by
	// Entry. End for the last function is the end of .text.
	Funcs []*Func
	// PclntabSize is the total size of the .gopclntab section in
	// bytes; sum of FuncMetaBytes across Funcs equals this minus
	// the table's fixed header.
	PclntabSize int64

	// Types is the runtime type descriptor index, keyed by Go type
	// name (after un-mangling, e.g. "*tailscale.com/util/eventbus.Publisher[main.Event0]").
	// Multiple raw type entries may share a name when GC-shape
	// stenciling produces aliases; in that case Types maps to a
	// list of *Type, all of which contribute to the type's cost.
	Types map[string][]*Type

	// Itabs is the list of all interface tables in the binary.
	Itabs []*Itab

	elf *elf.File
}

// Section is a slim view of one ELF PROGBITS section.
type Section struct {
	Name string
	// Addr is the virtual address where the section is loaded.
	Addr uint64
	// Size is the section's in-memory size in bytes.
	Size uint64
	// Data is the section's raw contents. For NOBITS sections
	// (e.g. .bss), Data is nil. We only populate PROGBITS.
	Data []byte
}

// AddrInRange reports whether addr lies within this section.
func (s *Section) AddrInRange(addr uint64) bool {
	return addr >= s.Addr && addr < s.Addr+s.Size
}

// Slice returns the section bytes covering [addr, addr+n). Returns
// nil if the range is partly out of bounds.
func (s *Section) Slice(addr uint64, n int) []byte {
	if !s.AddrInRange(addr) || addr+uint64(n) > s.Addr+s.Size {
		return nil
	}
	off := addr - s.Addr
	return s.Data[off : off+uint64(n)]
}

// Sym is a symbol from the binary's static symbol table.
type Sym struct {
	// Name is the demangled symbol name (Go symbol convention).
	Name string
	// Addr is the symbol's virtual address.
	Addr uint64
	// Size is the symbol's recorded size in bytes. Note that
	// .text symbols' Size matches the function body bytes; rodata
	// symbols may have Size 0 if the linker didn't record one,
	// in which case the size has to be derived from following the
	// symbol layout.
	Size uint64
	// Section is the name of the section the symbol lives in,
	// e.g. ".text" or ".rodata".
	Section string
}

// Func is one entry in the gopclntab function table.
type Func struct {
	// Name is the function name (demangled, Go symbol convention).
	Name string
	// Entry is the function's start address in .text.
	Entry uint64
	// End is the address one past the last byte of the function.
	End uint64
	// PclntabBytes is the per-function metadata size attributable
	// to this function in .gopclntab. Computed from the difference
	// between successive entries in the function-info offset table,
	// minus a small fixed header per function.
	PclntabBytes int64
}

// BodyBytes returns the size of the function's machine code (End - Entry).
func (f *Func) BodyBytes() int64 { return int64(f.End - f.Entry) }

// Open opens path as an ELF Go binary and parses its high-level
// structure. The returned *Binary owns an open file handle until
// Close is called.
func Open(path string) (*Binary, error) {
	ef, err := elf.Open(path)
	if err != nil {
		return nil, fmt.Errorf("opening %s as ELF: %w", path, err)
	}
	b := &Binary{
		Path:       path,
		Sections:   map[string]*Section{},
		SymsByName: map[string]*Sym{},
		Types:      map[string][]*Type{},
		elf:        ef,
	}
	switch ef.Class {
	case elf.ELFCLASS64:
		b.PtrSize = 8
	case elf.ELFCLASS32:
		b.PtrSize = 4
	default:
		ef.Close()
		return nil, fmt.Errorf("unsupported ELF class %v", ef.Class)
	}
	b.ByteOrder = ef.ByteOrder

	if err := b.loadSections(); err != nil {
		ef.Close()
		return nil, err
	}
	if err := b.loadSymbols(); err != nil {
		ef.Close()
		return nil, err
	}
	if err := b.loadFuncs(); err != nil {
		ef.Close()
		return nil, err
	}
	if err := b.loadTypes(); err != nil {
		ef.Close()
		return nil, err
	}
	if err := b.loadItabs(); err != nil {
		ef.Close()
		return nil, err
	}
	return b, nil
}

// Close releases the underlying file handle.
func (b *Binary) Close() error {
	if b.elf != nil {
		err := b.elf.Close()
		b.elf = nil
		return err
	}
	return nil
}

func (b *Binary) loadSections() error {
	for _, s := range b.elf.Sections {
		if s.Type != elf.SHT_PROGBITS {
			continue
		}
		sec := &Section{
			Name: s.Name,
			Addr: s.Addr,
			Size: s.Size,
		}
		if s.Size > 0 {
			data, err := s.Data()
			if err != nil {
				return fmt.Errorf("reading section %s: %w", s.Name, err)
			}
			sec.Data = data
		}
		b.Sections[s.Name] = sec
	}
	if _, ok := b.Sections[".text"]; !ok {
		return errors.New("no .text section: not a Go binary?")
	}
	return nil
}

func (b *Binary) loadSymbols() error {
	syms, err := b.elf.Symbols()
	if err != nil {
		// A stripped binary loses the static symbol table and we
		// can't recover named-symbol info. We still proceed (so
		// pclntab and type-side analysis still works), but the
		// caller will get empty Syms.
		if errors.Is(err, elf.ErrNoSymbols) {
			return nil
		}
		return fmt.Errorf("reading symbol table: %w", err)
	}
	for i := range syms {
		es := &syms[i]
		if es.Size == 0 && es.Value == 0 {
			continue
		}
		// Find which section it's in, by address.
		secName := ""
		for _, sec := range b.Sections {
			if sec.AddrInRange(es.Value) {
				secName = sec.Name
				break
			}
		}
		s := &Sym{
			Name:    es.Name,
			Addr:    es.Value,
			Size:    es.Size,
			Section: secName,
		}
		b.Syms = append(b.Syms, s)
		// In well-formed Go binaries names are unique. If we hit a
		// duplicate (e.g. weak/aliased), keep the first.
		if _, exists := b.SymsByName[es.Name]; !exists {
			b.SymsByName[es.Name] = s
		}
	}
	sort.Slice(b.Syms, func(i, j int) bool { return b.Syms[i].Addr < b.Syms[j].Addr })
	return nil
}

func (b *Binary) loadFuncs() error {
	pcln := b.Sections[".gopclntab"]
	text := b.Sections[".text"]
	if pcln == nil || text == nil {
		return nil // older or stripped layout
	}
	b.PclntabSize = int64(pcln.Size)

	// debug/gosym does the heavy lifting of decoding pclntab.
	lt := gosym.NewLineTable(pcln.Data, text.Addr)
	tab, err := gosym.NewTable(nil, lt)
	if err != nil {
		return fmt.Errorf("decoding pclntab: %w", err)
	}
	for i := range tab.Funcs {
		gf := &tab.Funcs[i]
		f := &Func{
			Name:  gf.Name,
			Entry: gf.Entry,
			End:   gf.End,
		}
		b.Funcs = append(b.Funcs, f)
	}
	sort.Slice(b.Funcs, func(i, j int) bool { return b.Funcs[i].Entry < b.Funcs[j].Entry })

	// Distribute the pclntab section size across functions
	// proportional to body size. This is an approximation: in
	// reality, each function has a fixed-size pclntab header plus
	// variable-size pcdata/funcdata that scales with body size and
	// inlining depth. The proportional distribution is accurate
	// enough to surface the *relative* pclntab cost of one function
	// vs another, which is what we need for attribution. A future
	// refinement would parse runtime._func directly from pclntab.
	var totalBody int64
	for _, f := range b.Funcs {
		totalBody += f.BodyBytes()
	}
	if totalBody > 0 {
		// Reserve some bytes for non-per-function pclntab data
		// (the file table, the function index table itself, etc.).
		// gosym doesn't expose this directly; we estimate by
		// reserving a fixed 64 bytes per function for headers,
		// distributing only the remainder by body proportion.
		fixedPerFunc := int64(64)
		fixedTotal := fixedPerFunc * int64(len(b.Funcs))
		variable := b.PclntabSize - fixedTotal
		if variable < 0 {
			variable = b.PclntabSize / 2
			fixedPerFunc = (b.PclntabSize - variable) / int64(len(b.Funcs))
		}
		for _, f := range b.Funcs {
			share := variable * f.BodyBytes() / totalBody
			f.PclntabBytes = fixedPerFunc + share
		}
	}
	return nil
}

// FuncByName returns the Func with the given exact name, or nil.
func (b *Binary) FuncByName(name string) *Func {
	for _, f := range b.Funcs {
		if f.Name == name {
			return f
		}
	}
	return nil
}

// FuncsByTemplate returns all Funcs whose name normalizes to the
// given template (i.e. all instantiations of one generic).
func (b *Binary) FuncsByTemplate(tpl string) []*Func {
	var out []*Func
	for _, f := range b.Funcs {
		if normalize(f.Name) == tpl {
			out = append(out, f)
		}
	}
	return out
}
