// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package symcost

import (
	"fmt"
)

// Itab is one interface table from .itablink, attributing the
// itab's storage cost to the (concrete type, interface type) pair.
type Itab struct {
	// Addr is the virtual address of the itab in rodata/itablink.
	Addr uint64
	// Bytes is the total size of the itab struct itself, including
	// the trailing fun pointer array.
	Bytes int64
	// SymName is the linker-emitted symbol name for the itab,
	// `go:itab.<concrete>,<interface>` if the binary still carries
	// it as a named symbol.
	SymName string
	// ConcreteName is the concrete type name (e.g.
	// "*tailscale.com/util/eventbus.Publisher[main.Event0]"). May
	// be empty if we couldn't resolve it (e.g. from index entries
	// that point at unnamed types).
	ConcreteName string
	// InterfaceName is the interface type name (e.g.
	// "tailscale.com/util/eventbus.publisher").
	InterfaceName string
}

// loadItabs walks .itablink (a sorted list of pointers to itab
// structs) and records each one. The names come from the binary's
// static symbol table when present, since itabs are emitted with
// canonical names like `go:itab.<concrete>,<interface>`.
func (b *Binary) loadItabs() error {
	il := b.Sections[".itablink"]
	if il == nil || il.Size == 0 {
		return nil
	}
	if b.PtrSize != 8 && b.PtrSize != 4 {
		return fmt.Errorf("unsupported pointer size %d", b.PtrSize)
	}
	count := int(il.Size) / b.PtrSize
	for i := 0; i < count; i++ {
		buf := il.Data[i*b.PtrSize : (i+1)*b.PtrSize]
		var addr uint64
		switch b.PtrSize {
		case 8:
			addr = b.ByteOrder.Uint64(buf)
		case 4:
			addr = uint64(b.ByteOrder.Uint32(buf))
		}
		if addr == 0 {
			continue
		}
		it := b.decodeItab(addr)
		if it != nil {
			b.Itabs = append(b.Itabs, it)
		}
	}
	return nil
}

// decodeItab reads the itab at addr. The runtime layout is:
//
//	Inter   *interfacetype  // ptrSize
//	Type    *_type          // ptrSize
//	Hash    uint32          // 4
//	_       [4]byte         // 4 padding (on 64-bit)
//	Fun     [1]uintptr      // ptrSize, plus per-method extension
//
// The total size is `2*ptrSize + 8 + ptrSize * nmethod`. We can find
// a named symbol covering this address (and its size) via SymsByName
// keyed by `go:itab.<concrete>,<interface>` — that is the most
// reliable way to size each itab without fully decoding the interface
// method count.
func (b *Binary) decodeItab(addr uint64) *Itab {
	rodata := b.Sections[".rodata"]
	if rodata == nil || !rodata.AddrInRange(addr) {
		return nil
	}
	// Try to find a named symbol at this address.
	var sym *Sym
	for _, s := range b.Syms {
		if s.Addr == addr {
			sym = s
			break
		}
		if s.Addr > addr {
			break
		}
	}
	it := &Itab{Addr: addr}
	if sym != nil {
		it.SymName = sym.Name
		it.Bytes = int64(sym.Size)
		// Parse `go:itab.<concrete>,<interface>` (or `go:itab.<x>` for
		// some emit paths).
		if rest, ok := stripPrefix(sym.Name, "go:itab."); ok {
			if comma := lastByte(rest, ','); comma >= 0 {
				it.ConcreteName = rest[:comma]
				it.InterfaceName = rest[comma+1:]
			} else {
				it.ConcreteName = rest
			}
		}
	} else {
		// Fall back to a conservative minimum size; we lose
		// the per-method tail (which is usually small for the
		// 1-2 method interfaces we care about).
		it.Bytes = int64(2*b.PtrSize + 8 + b.PtrSize)
	}
	return it
}

// stripPrefix is strings.CutPrefix in older-Go-friendly form.
func stripPrefix(s, prefix string) (string, bool) {
	if len(s) >= len(prefix) && s[:len(prefix)] == prefix {
		return s[len(prefix):], true
	}
	return "", false
}

// lastByte returns the index of the last occurrence of c in s, or -1.
func lastByte(s string, c byte) int {
	for i := len(s) - 1; i >= 0; i-- {
		if s[i] == c {
			return i
		}
	}
	return -1
}
