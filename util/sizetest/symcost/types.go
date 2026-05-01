// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package symcost

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// Type is the runtime type descriptor for one Go type as it appears
// in a compiled binary. It carries enough information to attribute
// the descriptor's bytes to a specific Go type name.
//
// Type mirrors the layout described in internal/abi.Type as of Go
// 1.21+. We do not import internal/abi (it isn't accessible to
// regular packages); the constants we depend on are vendored in
// abiconst.go.
type Type struct {
	// Addr is the virtual address of the type descriptor in
	// .rodata.
	Addr uint64
	// Bytes is the size of the type descriptor proper, in bytes.
	// This includes the common Type header, the kind-specific
	// extension (StructType, FuncType, ChanType, etc. and any
	// trailing field arrays), and the optional UncommonType
	// (method list) when present.
	Bytes int64
	// NameBytes is the size of the type's name string in
	// .rodata, computed from the (length-prefixed, optional-tag-prefixed)
	// reflect.name encoding. This is part of the per-type cost
	// even though it lives outside the Type struct itself.
	NameBytes int64
	// Name is the demangled type name (e.g.
	// "*tailscale.com/util/eventbus.Publisher[main.Event0]").
	Name string
	// Kind is the type's reflect-style kind (Struct, Pointer,
	// Interface, etc.).
	Kind Kind
	// HasUncommon is true when the type carries a UncommonType
	// (method list) extension.
	HasUncommon bool
}

// TotalBytes returns Bytes + NameBytes, the full per-type cost as
// charged by symcost's attribution.
func (t *Type) TotalBytes() int64 { return t.Bytes + t.NameBytes }

// loadTypes walks .typelink to find every type descriptor and
// records each one in b.Types. The .typelink section is a sorted
// list of int32 offsets into the read-only data segment that point
// at runtime._type structs. We follow each offset and decode the
// type's name and size.
func (b *Binary) loadTypes() error {
	tl := b.Sections[".typelink"]
	if tl == nil || tl.Size == 0 {
		// No .typelink section: nothing to attribute.
		return nil
	}
	// .typelink entries are int32 offsets relative to the start of
	// the type table, which the runtime keeps in moduledata.types.
	// In the linked binary, the resolved address is the moduledata
	// "types" base plus the offset. The base is the start of the
	// rodata range that contains type descriptors. Empirically,
	// it is the address of the .rodata section's typelink-adjacent
	// range; in practice, we can find it as the lowest address
	// among all referenced type pointers.
	//
	// For decoding purposes, we can just iterate offsets and look
	// up the corresponding rodata bytes via the section table.
	// However, the offsets are relative to a base we need to know.
	// Strategy: treat the offsets as additions to the lowest
	// .rodata address; the linker emits typelink offsets relative
	// to that. If the resulting address falls in .rodata and the
	// decoded type looks valid, we accept it.
	//
	// In Go's actual encoding the offsets are relative to
	// firstmoduledata.types, which equals the start of the
	// rodata block reserved for types. We don't have direct
	// access to moduledata, but we can probe: try each .rodata
	// section's start as the base and pick whichever produces
	// valid, in-range type pointers.
	rodata := b.Sections[".rodata"]
	if rodata == nil {
		return nil
	}
	base, err := b.findTypelinkBase(tl, rodata)
	if err != nil {
		return fmt.Errorf("locating typelink base: %w", err)
	}

	count := int(tl.Size) / 4
	for i := 0; i < count; i++ {
		off := int32(b.ByteOrder.Uint32(tl.Data[i*4:]))
		typeAddr := base + uint64(int64(off))
		t, err := b.decodeType(typeAddr)
		if err != nil {
			// A bad entry means our base is wrong or the
			// binary uses a layout we don't understand.
			// Continue trying others; the loop is best-effort.
			continue
		}
		if t == nil {
			continue
		}
		b.Types[t.Name] = append(b.Types[t.Name], t)
	}
	return nil
}

// findTypelinkBase determines the address that .typelink offsets
// are relative to. The Go linker emits these offsets relative to
// the start of the rodata "types" range (firstmoduledata.types).
// We probe by trying the .rodata start as the base, decoding the
// first entry, and checking that the decoded type's name is a
// plausible string. If that fails, we step the base forward in
// page-sized increments until we find a base that works.
func (b *Binary) findTypelinkBase(tl, rodata *Section) (uint64, error) {
	// Heuristic: try .rodata.Addr + offset for each candidate base,
	// where candidate base is .rodata.Addr (modern layout). If the
	// first three entries all decode cleanly and produce names
	// from the rodata section, we accept the base.
	candidates := []uint64{rodata.Addr}
	// In some builds the type pool starts after a header within
	// rodata; allow probing in PtrSize steps for a few iterations.
	for delta := uint64(b.PtrSize); delta < 4096; delta += uint64(b.PtrSize) {
		candidates = append(candidates, rodata.Addr+delta)
	}
	for _, base := range candidates {
		ok := 0
		for i := 0; i < 5 && i*4 < len(tl.Data); i++ {
			off := int32(b.ByteOrder.Uint32(tl.Data[i*4:]))
			addr := base + uint64(int64(off))
			t, err := b.decodeType(addr)
			if err == nil && t != nil && plausibleTypeName(t.Name) {
				ok++
			}
		}
		if ok >= 3 {
			return base, nil
		}
	}
	return 0, errors.New("no typelink base produced plausible types")
}

// plausibleTypeName reports whether s looks like a Go type name as
// emitted by the compiler. We use it to validate guesses at the
// typelink base address.
func plausibleTypeName(s string) bool {
	if s == "" || len(s) > 4096 {
		return false
	}
	// Type names contain at least one letter; many start with '*',
	// '[', a package path, etc. Reject names that have NUL bytes or
	// non-printable characters.
	hasLetter := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < 0x20 || c == 0x7f {
			return false
		}
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') {
			hasLetter = true
		}
	}
	return hasLetter
}

// decodeType reads a runtime._type descriptor at addr and returns
// a *Type with its name and total byte size. Returns nil and a
// non-nil error if the address is out of range or the data doesn't
// look like a type descriptor.
func (b *Binary) decodeType(addr uint64) (*Type, error) {
	rodata := b.Sections[".rodata"]
	if rodata == nil || !rodata.AddrInRange(addr) {
		return nil, fmt.Errorf("addr 0x%x not in .rodata", addr)
	}
	common := commonTypeSize(b.PtrSize)
	hdr := rodata.Slice(addr, common)
	if hdr == nil {
		return nil, fmt.Errorf("type header at 0x%x out of range", addr)
	}
	// Parse what we need: tflag, kind, str (NameOff), ptrToThis (TypeOff).
	tflag := hdr[tflagOffset(b.PtrSize)]
	kindByte := hdr[kindOffset(b.PtrSize)]
	kind := Kind(kindByte & kindMask)
	strOff := int32(b.ByteOrder.Uint32(hdr[nameOffOffset(b.PtrSize):]))
	hasUncommon := tflag&tflagUncommon != 0

	// Extension size depends on kind. We compute the kind-specific
	// extension size, then add UncommonType if present, then add
	// any trailing variable-length arrays for kinds with method
	// lists / fields / parameter lists.
	extSize, extVar := kindExtraSize(b.PtrSize, kind, addr, rodata, common, b.ByteOrder)

	totalSize := int64(common + extSize + extVar)
	if hasUncommon {
		// UncommonType is appended after the kind-specific extension
		// and contains its own variable-length method list.
		uOff := common + extSize + extVar
		uMethods, uMethodsBytes := decodeUncommon(b.PtrSize, addr, rodata, uOff, b.ByteOrder)
		_ = uMethods
		totalSize += int64(uncommonSize() + uMethodsBytes)
	}

	// Decode the name. The name lives in rodata; its offset is
	// relative to the same base used in typelink. For simplicity
	// we treat it as relative to .rodata.Addr — the same convention
	// the compiler uses.
	name, nameBytes := decodeName(rodata, addr, strOff, tflag)

	return &Type{
		Addr:        addr,
		Bytes:       totalSize,
		NameBytes:   nameBytes,
		Name:        name,
		Kind:        kind,
		HasUncommon: hasUncommon,
	}, nil
}

// decodeName reads a length-prefixed name string starting at the
// rodata-relative offset off (relative to the .rodata base, matching
// what the linker emits). Returns the decoded name and the size in
// bytes the name occupies in rodata.
func decodeName(rodata *Section, typeAddr uint64, off int32, tflag uint8) (string, int64) {
	nameAddr := rodata.Addr + uint64(int64(off))
	if !rodata.AddrInRange(nameAddr) {
		return "", 0
	}
	off64 := nameAddr - rodata.Addr
	data := rodata.Data[off64:]
	if len(data) < 2 {
		return "", 0
	}
	// reflect.name layout: 1 byte flags, then varint length, then
	// `length` bytes of name, then optional tag and pkgpath which
	// we don't account for here (they're separate offsets and the
	// linker shares them across types).
	nameLen, lenLen := binaryUvarint(data[1:])
	if nameLen == 0 || nameLen > 4096 {
		return "", 0
	}
	headerSize := 1 + lenLen
	totalSize := int64(headerSize) + int64(nameLen)
	if int64(len(data)) < totalSize {
		return "", 0
	}
	name := string(data[headerSize : headerSize+int(nameLen)])
	if tflag&tflagExtraStar != 0 && len(name) > 0 && name[0] == '*' {
		// The compiler stores the name with a leading '*' for
		// pointer-to-named types so the same name string can be
		// reused for both T and *T. The TFlagExtraStar bit signals
		// this. The canonical (callable) name for the type is
		// without the star, but the storage cost still includes
		// the star byte; we keep totalSize unchanged.
		name = name[1:]
	}
	return name, totalSize
}

// binaryUvarint is a slimmed copy of encoding/binary.Uvarint that
// avoids the import cycle for callers that don't already use it.
// It returns (value, byteCount). On error returns (0, 0).
func binaryUvarint(buf []byte) (uint64, int) {
	var x uint64
	var s uint
	for i, b := range buf {
		if i == 10 {
			return 0, 0
		}
		if b < 0x80 {
			return x | uint64(b)<<s, i + 1
		}
		x |= uint64(b&0x7f) << s
		s += 7
	}
	return 0, 0
}

// kindExtraSize returns the size of the kind-specific extension
// that follows the common Type header. extVar accounts for trailing
// variable-length arrays (e.g. method lists, struct fields).
func kindExtraSize(ptrSize int, kind Kind, addr uint64, rodata *Section, common int, bo binary.ByteOrder) (extSize, extVar int) {
	switch kind {
	case KindStruct:
		// StructType layout:
		//   type StructType struct {
		//       Type
		//       PkgPath Name           // size = ptrSize (struct{Bytes *byte})
		//       Fields  []StructField  // slice header = 3 * ptrSize
		//   }
		// Trailing fields array: each StructField is 3 * ptrSize.
		// We read the slice length from rodata.
		extSize = ptrSize + 3*ptrSize
		fieldsLenOff := common + ptrSize + ptrSize // skip Type + PkgPath + Fields.Data
		if buf := rodata.Slice(addr+uint64(fieldsLenOff), ptrSize); buf != nil {
			n := int(decodeUint(buf, ptrSize, bo))
			extVar = n * 3 * ptrSize
		}
	case KindInterface:
		// InterfaceType: pkgPath (Name) + methods slice header.
		extSize = ptrSize + 3*ptrSize
		methodsLenOff := common + ptrSize + ptrSize
		if buf := rodata.Slice(addr+uint64(methodsLenOff), ptrSize); buf != nil {
			n := int(decodeUint(buf, ptrSize, bo))
			// Imethod is 2 * uint32 = 8 bytes.
			extVar = n * 8
		}
	case KindFunc:
		// FuncType: InCount uint16, OutCount uint16, then trailing
		// in/out type pointer arrays.
		extSize = 4 // 2 * uint16
		// Pad to ptr alignment.
		if ptrSize == 8 {
			extSize = 8
		}
		// Read in/out counts (relative to common).
		if buf := rodata.Slice(addr+uint64(common), 4); buf != nil {
			in := int(bo.Uint16(buf[0:2]))
			out := int(bo.Uint16(buf[2:4])) & 0x7fff
			extVar = (in + out) * ptrSize
		}
	case KindMap:
		// MapType has key, elem, bucket, hasher, keysize/valuesize,
		// flags. All but the function pointer are small; total ~4
		// pointers + 4 bytes.
		extSize = 4*ptrSize + 8
	case KindArray:
		// ArrayType: Elem *Type, Slice *Type, Len uintptr.
		extSize = 3 * ptrSize
	case KindSlice:
		// SliceType: Elem *Type.
		extSize = ptrSize
	case KindPointer:
		// PtrType: Elem *Type.
		extSize = ptrSize
	case KindChan:
		// ChanType: Elem *Type, Dir uintptr.
		extSize = 2 * ptrSize
	default:
		// Other kinds (Bool, Int*, Float*, String, etc.) have no
		// extension beyond the common header.
		extSize = 0
	}
	return extSize, extVar
}

// decodeUncommon decodes an UncommonType at the given offset into
// the rodata block for this type. Returns the number of methods
// and the bytes occupied by the trailing method array.
func decodeUncommon(ptrSize int, addr uint64, rodata *Section, off int, bo binary.ByteOrder) (int, int) {
	// UncommonType layout:
	//   PkgPath  NameOff  // uint32
	//   Mcount   uint16
	//   Xcount   uint16
	//   Moff     uint32
	//   _        uint32  // unused
	buf := rodata.Slice(addr+uint64(off), uncommonSize())
	if buf == nil {
		return 0, 0
	}
	mcount := int(bo.Uint16(buf[4:6]))
	// Method layout:
	//   Name NameOff
	//   Mtyp TypeOff
	//   Ifn  TextOff
	//   Tfn  TextOff
	// = 4 * uint32 = 16 bytes.
	return mcount, mcount * 16
}

// decodeUint reads an unsigned integer of size sz (4 or 8) from buf.
func decodeUint(buf []byte, sz int, bo binary.ByteOrder) uint64 {
	switch sz {
	case 4:
		return uint64(bo.Uint32(buf))
	case 8:
		return bo.Uint64(buf)
	}
	return 0
}
