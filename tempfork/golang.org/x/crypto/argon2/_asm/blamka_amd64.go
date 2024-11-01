// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	. "github.com/mmcloughlin/avo/build"
	. "github.com/mmcloughlin/avo/operand"
	. "github.com/mmcloughlin/avo/reg"
	_ "golang.org/x/crypto/argon2"
)

//go:generate go run . -out ../blamka_amd64.s -pkg argon2

func main() {
	Package("golang.org/x/crypto/argon2")
	ConstraintExpr("amd64,gc,!purego")

	blamkaSSE4()
	mixBlocksSSE2()
	xorBlocksSSE2()
	Generate()
}

func blamkaSSE4() {
	Implement("blamkaSSE4")
	Attributes(NOSPLIT)
	AllocLocal(0)

	Load(Param("b"), RAX)

	c40 := c40_DATA()
	c48 := c48_DATA()

	MOVOU(c40, X10)
	MOVOU(c48, X11)

	BLAMKA_ROUND_0(AX, 0, X8, X9, X10, X11)
	BLAMKA_ROUND_0(AX, 16, X8, X9, X10, X11)
	BLAMKA_ROUND_0(AX, 32, X8, X9, X10, X11)
	BLAMKA_ROUND_0(AX, 48, X8, X9, X10, X11)
	BLAMKA_ROUND_0(AX, 64, X8, X9, X10, X11)
	BLAMKA_ROUND_0(AX, 80, X8, X9, X10, X11)
	BLAMKA_ROUND_0(AX, 96, X8, X9, X10, X11)
	BLAMKA_ROUND_0(AX, 112, X8, X9, X10, X11)

	BLAMKA_ROUND_1(AX, 0, X8, X9, X10, X11)
	BLAMKA_ROUND_1(AX, 2, X8, X9, X10, X11)
	BLAMKA_ROUND_1(AX, 4, X8, X9, X10, X11)
	BLAMKA_ROUND_1(AX, 6, X8, X9, X10, X11)
	BLAMKA_ROUND_1(AX, 8, X8, X9, X10, X11)
	BLAMKA_ROUND_1(AX, 10, X8, X9, X10, X11)
	BLAMKA_ROUND_1(AX, 12, X8, X9, X10, X11)
	BLAMKA_ROUND_1(AX, 14, X8, X9, X10, X11)
	RET()
}

func mixBlocksSSE2() {
	Implement("mixBlocksSSE2")
	Attributes(NOSPLIT)
	AllocLocal(0)

	Load(Param("out"), RDX)
	Load(Param("a"), RAX)
	Load(Param("b"), RBX)
	Load(Param("c"), RCX)
	MOVQ(U32(128), RDI)

	Label("loop")
	MOVOU(Mem{Base: AX}.Offset(0), X0)
	MOVOU(Mem{Base: BX}.Offset(0), X1)
	MOVOU(Mem{Base: CX}.Offset(0), X2)
	PXOR(X1, X0)
	PXOR(X2, X0)
	MOVOU(X0, Mem{Base: DX}.Offset(0))
	ADDQ(Imm(16), RAX)
	ADDQ(Imm(16), RBX)
	ADDQ(Imm(16), RCX)
	ADDQ(Imm(16), RDX)
	SUBQ(Imm(2), RDI)
	JA(LabelRef("loop"))
	RET()
}

func xorBlocksSSE2() {
	Implement("xorBlocksSSE2")
	Attributes(NOSPLIT)
	AllocLocal(0)

	Load(Param("out"), RDX)
	Load(Param("a"), RAX)
	Load(Param("b"), RBX)
	Load(Param("c"), RCX)
	MOVQ(U32(128), RDI)

	Label("loop")
	MOVOU(Mem{Base: AX}.Offset(0), X0)
	MOVOU(Mem{Base: BX}.Offset(0), X1)
	MOVOU(Mem{Base: CX}.Offset(0), X2)
	MOVOU(Mem{Base: DX}.Offset(0), X3)
	PXOR(X1, X0)
	PXOR(X2, X0)
	PXOR(X3, X0)
	MOVOU(X0, Mem{Base: DX}.Offset(0))
	ADDQ(Imm(16), RAX)
	ADDQ(Imm(16), RBX)
	ADDQ(Imm(16), RCX)
	ADDQ(Imm(16), RDX)
	SUBQ(Imm(2), RDI)
	JA(LabelRef("loop"))
	RET()
}

func SHUFFLE(v2, v3, v4, v5, v6, v7, t1, t2 VecPhysical) {
	MOVO(v4, t1)
	MOVO(v5, v4)
	MOVO(t1, v5)
	MOVO(v6, t1)
	PUNPCKLQDQ(v6, t2)
	PUNPCKHQDQ(v7, v6)
	PUNPCKHQDQ(t2, v6)
	PUNPCKLQDQ(v7, t2)
	MOVO(t1, v7)
	MOVO(v2, t1)
	PUNPCKHQDQ(t2, v7)
	PUNPCKLQDQ(v3, t2)
	PUNPCKHQDQ(t2, v2)
	PUNPCKLQDQ(t1, t2)
	PUNPCKHQDQ(t2, v3)
}

func SHUFFLE_INV(v2, v3, v4, v5, v6, v7, t1, t2 VecPhysical) {
	MOVO(v4, t1)
	MOVO(v5, v4)
	MOVO(t1, v5)
	MOVO(v2, t1)
	PUNPCKLQDQ(v2, t2)
	PUNPCKHQDQ(v3, v2)
	PUNPCKHQDQ(t2, v2)
	PUNPCKLQDQ(v3, t2)
	MOVO(t1, v3)
	MOVO(v6, t1)
	PUNPCKHQDQ(t2, v3)
	PUNPCKLQDQ(v7, t2)
	PUNPCKHQDQ(t2, v6)
	PUNPCKLQDQ(t1, t2)
	PUNPCKHQDQ(t2, v7)
}

func HALF_ROUND(v0, v1, v2, v3, v4, v5, v6, v7, t0, c40, c48 VecPhysical) {
	MOVO(v0, t0)
	PMULULQ(v2, t0)
	PADDQ(v2, v0)
	PADDQ(t0, v0)
	PADDQ(t0, v0)
	PXOR(v0, v6)
	PSHUFD(Imm(0xB1), v6, v6)
	MOVO(v4, t0)
	PMULULQ(v6, t0)
	PADDQ(v6, v4)
	PADDQ(t0, v4)
	PADDQ(t0, v4)
	PXOR(v4, v2)
	PSHUFB(c40, v2)
	MOVO(v0, t0)
	PMULULQ(v2, t0)
	PADDQ(v2, v0)
	PADDQ(t0, v0)
	PADDQ(t0, v0)
	PXOR(v0, v6)
	PSHUFB(c48, v6)
	MOVO(v4, t0)
	PMULULQ(v6, t0)
	PADDQ(v6, v4)
	PADDQ(t0, v4)
	PADDQ(t0, v4)
	PXOR(v4, v2)
	MOVO(v2, t0)
	PADDQ(v2, t0)
	PSRLQ(Imm(63), v2)
	PXOR(t0, v2)
	MOVO(v1, t0)
	PMULULQ(v3, t0)
	PADDQ(v3, v1)
	PADDQ(t0, v1)
	PADDQ(t0, v1)
	PXOR(v1, v7)
	PSHUFD(Imm(0xB1), v7, v7)
	MOVO(v5, t0)
	PMULULQ(v7, t0)
	PADDQ(v7, v5)
	PADDQ(t0, v5)
	PADDQ(t0, v5)
	PXOR(v5, v3)
	PSHUFB(c40, v3)
	MOVO(v1, t0)
	PMULULQ(v3, t0)
	PADDQ(v3, v1)
	PADDQ(t0, v1)
	PADDQ(t0, v1)
	PXOR(v1, v7)
	PSHUFB(c48, v7)
	MOVO(v5, t0)
	PMULULQ(v7, t0)
	PADDQ(v7, v5)
	PADDQ(t0, v5)
	PADDQ(t0, v5)
	PXOR(v5, v3)
	MOVO(v3, t0)
	PADDQ(v3, t0)
	PSRLQ(Imm(63), v3)
	PXOR(t0, v3)
}

func LOAD_MSG_0(block GPPhysical, off int) {
	var registers = []VecPhysical{X0, X1, X2, X3, X4, X5, X6, X7}
	for i, r := range registers {
		MOVOU(Mem{Base: block}.Offset(8*(off+(i*2))), r)
	}
}

func STORE_MSG_0(block GPPhysical, off int) {
	var registers = []VecPhysical{X0, X1, X2, X3, X4, X5, X6, X7}
	for i, r := range registers {
		MOVOU(r, Mem{Base: block}.Offset(8*(off+(i*2))))
	}
}

func LOAD_MSG_1(block GPPhysical, off int) {
	var registers = []VecPhysical{X0, X1, X2, X3, X4, X5, X6, X7}
	for i, r := range registers {
		MOVOU(Mem{Base: block}.Offset(8*off+i*16*8), r)
	}
}

func STORE_MSG_1(block GPPhysical, off int) {
	var registers = []VecPhysical{X0, X1, X2, X3, X4, X5, X6, X7}
	for i, r := range registers {
		MOVOU(r, Mem{Base: block}.Offset(8*off+i*16*8))
	}
}

func BLAMKA_ROUND_0(block GPPhysical, off int, t0, t1, c40, c48 VecPhysical) {
	LOAD_MSG_0(block, off)
	HALF_ROUND(X0, X1, X2, X3, X4, X5, X6, X7, t0, c40, c48)
	SHUFFLE(X2, X3, X4, X5, X6, X7, t0, t1)
	HALF_ROUND(X0, X1, X2, X3, X4, X5, X6, X7, t0, c40, c48)
	SHUFFLE_INV(X2, X3, X4, X5, X6, X7, t0, t1)
	STORE_MSG_0(block, off)
}

func BLAMKA_ROUND_1(block GPPhysical, off int, t0, t1, c40, c48 VecPhysical) {
	LOAD_MSG_1(block, off)
	HALF_ROUND(X0, X1, X2, X3, X4, X5, X6, X7, t0, c40, c48)
	SHUFFLE(X2, X3, X4, X5, X6, X7, t0, t1)
	HALF_ROUND(X0, X1, X2, X3, X4, X5, X6, X7, t0, c40, c48)
	SHUFFLE_INV(X2, X3, X4, X5, X6, X7, t0, t1)
	STORE_MSG_1(block, off)
}

// ##------------------DATA SECTION-------------------##

var c40_DATA_ptr, c48_DATA_ptr *Mem

func c40_DATA() Mem {
	if c40_DATA_ptr != nil {
		return *c40_DATA_ptr
	}

	c40_DATA := GLOBL("·c40", NOPTR|RODATA)
	c40_DATA_ptr = &c40_DATA
	DATA(0x00, U64(0x0201000706050403))
	DATA(0x08, U64(0x0a09080f0e0d0c0b))
	return c40_DATA
}
func c48_DATA() Mem {
	if c48_DATA_ptr != nil {
		return *c48_DATA_ptr
	}

	c48_DATA := GLOBL("·c48", NOPTR|RODATA)
	c48_DATA_ptr = &c48_DATA
	DATA(0x00, U64(0x0100070605040302))
	DATA(0x08, U64(0x09080f0e0d0c0b0a))
	return c48_DATA
}
