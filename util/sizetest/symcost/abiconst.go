// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package symcost

// This file vendors the layout constants and offsets we need to
// decode runtime type descriptors and itabs. They mirror the
// definitions in Go's internal/abi (which we cannot import) and in
// cmd/link/internal/ld/decodesym.go (which is the linker's
// reverse-direction decoder).
//
// Refs:
//   - Type layout: src/internal/abi/type.go
//   - Layout helper functions: src/internal/abi/compiletype.go
//   - Linker decoder: src/cmd/link/internal/ld/decodesym.go
//
// These constants are stable enough that Go has shipped them across
// 1.21..1.26 without changes meaningful to size accounting. If a
// future Go release changes the layout we'll need to update them
// here; the integration tests detect such regressions by sanity-
// checking that decoded type names match the binary's own symbol
// table.

// Kind values from internal/abi.
type Kind uint8

const (
	KindInvalid Kind = iota
	KindBool
	KindInt
	KindInt8
	KindInt16
	KindInt32
	KindInt64
	KindUint
	KindUint8
	KindUint16
	KindUint32
	KindUint64
	KindUintptr
	KindFloat32
	KindFloat64
	KindComplex64
	KindComplex128
	KindArray
	KindChan
	KindFunc
	KindInterface
	KindMap
	KindPointer
	KindSlice
	KindString
	KindStruct
	KindUnsafePointer
)

const kindMask = (1 << 5) - 1

// TFlag bits.
const (
	tflagUncommon       uint8 = 1 << 0
	tflagExtraStar      uint8 = 1 << 1
	tflagNamed          uint8 = 1 << 2
	tflagRegularMemory  uint8 = 1 << 3
	tflagGCMaskOnDemand uint8 = 1 << 4
)

// commonTypeSize returns the size in bytes of internal/abi.Type's
// common header for the given pointer size. From
// internal/abi.CommonSize: 4*ptrSize + 8 + 8.
func commonTypeSize(ptrSize int) int { return 4*ptrSize + 8 + 8 }

// uncommonSize returns the size of internal/abi.UncommonType:
// pkgPath NameOff (4) + Mcount (2) + Xcount (2) + Moff (4) + _ (4).
func uncommonSize() int { return 4 + 2 + 2 + 4 + 4 }

// tflagOffset is the byte offset of the TFlag field within the
// common Type header. From internal/abi.TFlagOff: 2*ptrSize + 4.
func tflagOffset(ptrSize int) int { return 2*ptrSize + 4 }

// kindOffset is the byte offset of the Kind field within the common
// Type header. From src/cmd/link/internal/ld/decodesym.go: 2*ptrSize+7.
func kindOffset(ptrSize int) int { return 2*ptrSize + 7 }

// nameOffOffset is the byte offset of the Str (NameOff) field within
// the common Type header. After the header: Size, PtrBytes, Hash,
// TFlag, Align, FieldAlign, Kind, _padding to ptr align, Equal,
// GCData, Str, PtrToThis. Equal is one ptr; GCData is one ptr; then
// Str is the next 4 bytes. CommonSize counts everything through
// PtrToThis. Layout:
//
//	ptrSize  Size_
//	ptrSize  PtrBytes
//	uint32   Hash
//	uint8    TFlag
//	uint8    Align_
//	uint8    FieldAlign_
//	uint8    Kind_
//	ptrSize  Equal (function pointer)
//	ptrSize  GCData (*byte)
//	uint32   Str (NameOff)
//	uint32   PtrToThis (TypeOff)
//
// So Str starts at 2*ptrSize + 8 + 2*ptrSize = 4*ptrSize + 8.
func nameOffOffset(ptrSize int) int { return 4*ptrSize + 8 }
