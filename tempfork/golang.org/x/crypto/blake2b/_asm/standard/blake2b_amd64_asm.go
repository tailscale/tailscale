// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	. "github.com/mmcloughlin/avo/build"
	. "github.com/mmcloughlin/avo/operand"
	. "github.com/mmcloughlin/avo/reg"
	_ "golang.org/x/crypto/blake2b"
)

//go:generate go run . -out ../../blake2b_amd64.s -pkg blake2b

const ThatPeskyUnicodeDot = "\u00b7"

var iv0_DATA_ptr, iv1_DATA_ptr, iv2_DATA_ptr, iv3_DATA_ptr, c40_DATA_ptr, c48_DATA_ptr *Mem

func main() {
	Package("golang.org/x/crypto/blake2b")
	ConstraintExpr("amd64,gc,!purego")
	hashBlocksSSE4()
	Generate()
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

func HALF_ROUND(v0, v1, v2, v3, v4, v5, v6, v7 VecPhysical, m0, m1, m2, m3 Op, t0, c40, c48 VecPhysical) {
	PADDQ(m0, v0)
	PADDQ(m1, v1)
	PADDQ(v2, v0)
	PADDQ(v3, v1)
	PXOR(v0, v6)
	PXOR(v1, v7)
	PSHUFD(Imm(0xB1), v6, v6)
	PSHUFD(Imm(0xB1), v7, v7)
	PADDQ(v6, v4)
	PADDQ(v7, v5)
	PXOR(v4, v2)
	PXOR(v5, v3)
	PSHUFB(c40, v2)
	PSHUFB(c40, v3)
	PADDQ(m2, v0)
	PADDQ(m3, v1)
	PADDQ(v2, v0)
	PADDQ(v3, v1)
	PXOR(v0, v6)
	PXOR(v1, v7)
	PSHUFB(c48, v6)
	PSHUFB(c48, v7)
	PADDQ(v6, v4)
	PADDQ(v7, v5)
	PXOR(v4, v2)
	PXOR(v5, v3)
	MOVOU(v2, t0)
	PADDQ(v2, t0)
	PSRLQ(Imm(63), v2)
	PXOR(t0, v2)
	MOVOU(v3, t0)
	PADDQ(v3, t0)
	PSRLQ(Imm(63), v3)
	PXOR(t0, v3)
}

func LOAD_MSG(m0, m1, m2, m3 VecPhysical, src GPPhysical, i0, i1, i2, i3, i4, i5, i6, i7 int) {
	MOVQ(Mem{Base: src}.Offset(i0*8), m0)
	PINSRQ(Imm(1), Mem{Base: src}.Offset(i1*8), m0)
	MOVQ(Mem{Base: src}.Offset(i2*8), m1)
	PINSRQ(Imm(1), Mem{Base: src}.Offset(i3*8), m1)
	MOVQ(Mem{Base: src}.Offset(i4*8), m2)
	PINSRQ(Imm(1), Mem{Base: src}.Offset(i5*8), m2)
	MOVQ(Mem{Base: src}.Offset(i6*8), m3)
	PINSRQ(Imm(1), Mem{Base: src}.Offset(i7*8), m3)
}

func hashBlocksSSE4() {
	Implement("hashBlocksSSE4")
	Attributes(4)
	AllocLocal(288) // frame size = 272 + 16 byte alignment

	Load(Param("h"), RAX)
	Load(Param("c"), RBX)
	Load(Param("flag"), RCX)
	Load(Param("blocks").Base(), RSI)
	Load(Param("blocks").Len(), RDI)

	MOVQ(RSP, R10)
	ADDQ(Imm(15), R10)
	ANDQ(I32(-16), R10)

	iv3 := iv3_DATA()
	MOVOU(iv3, X0)
	MOVO(X0, Mem{Base: R10}.Offset(0))
	XORQ(RCX, Mem{Base: R10}.Offset(0)) // 0(R10) = ·iv3 ^ (CX || 0)

	c40 := c40_DATA()
	c48 := c48_DATA()
	MOVOU(c40, X13)
	MOVOU(c48, X14)

	MOVOU(Mem{Base: AX}.Offset(0), X12)
	MOVOU(Mem{Base: AX}.Offset(16), X15)

	MOVQ(Mem{Base: BX}.Offset(0), R8)
	MOVQ(Mem{Base: BX}.Offset(8), R9)

	Label("loop")
	ADDQ(Imm(128), R8)
	CMPQ(R8, Imm(128))
	JGE(LabelRef("noinc"))
	INCQ(R9)

	Label("noinc")
	MOVQ(R8, X8)
	PINSRQ(Imm(1), R9, X8)

	iv0 := iv0_DATA()
	iv1 := iv1_DATA()
	iv2 := iv2_DATA()

	MOVO(X12, X0)
	MOVO(X15, X1)
	MOVOU(Mem{Base: AX}.Offset(32), X2)
	MOVOU(Mem{Base: AX}.Offset(48), X3)
	MOVOU(iv0, X4)
	MOVOU(iv1, X5)
	MOVOU(iv2, X6)

	PXOR(X8, X6)
	MOVO(Mem{Base: R10}.Offset(0), X7)

	LOAD_MSG(X8, X9, X10, X11, SI, 0, 2, 4, 6, 1, 3, 5, 7)
	MOVO(X8, Mem{Base: R10}.Offset(16))
	MOVO(X9, Mem{Base: R10}.Offset(32))
	MOVO(X10, Mem{Base: R10}.Offset(48))
	MOVO(X11, Mem{Base: R10}.Offset(64))
	HALF_ROUND(X0, X1, X2, X3, X4, X5, X6, X7, X8, X9, X10, X11, X11, X13, X14)
	SHUFFLE(X2, X3, X4, X5, X6, X7, X8, X9)
	LOAD_MSG(X8, X9, X10, X11, SI, 8, 10, 12, 14, 9, 11, 13, 15)
	MOVO(X8, Mem{Base: R10}.Offset(80))
	MOVO(X9, Mem{Base: R10}.Offset(96))
	MOVO(X10, Mem{Base: R10}.Offset(112))
	MOVO(X11, Mem{Base: R10}.Offset(128))
	HALF_ROUND(X0, X1, X2, X3, X4, X5, X6, X7, X8, X9, X10, X11, X11, X13, X14)
	SHUFFLE_INV(X2, X3, X4, X5, X6, X7, X8, X9)

	LOAD_MSG(X8, X9, X10, X11, SI, 14, 4, 9, 13, 10, 8, 15, 6)
	MOVO(X8, Mem{Base: R10}.Offset(144))
	MOVO(X9, Mem{Base: R10}.Offset(160))
	MOVO(X10, Mem{Base: R10}.Offset(176))
	MOVO(X11, Mem{Base: R10}.Offset(192))
	HALF_ROUND(X0, X1, X2, X3, X4, X5, X6, X7, X8, X9, X10, X11, X11, X13, X14)
	SHUFFLE(X2, X3, X4, X5, X6, X7, X8, X9)
	LOAD_MSG(X8, X9, X10, X11, SI, 1, 0, 11, 5, 12, 2, 7, 3)
	MOVO(X8, Mem{Base: R10}.Offset(208))
	MOVO(X9, Mem{Base: R10}.Offset(224))
	MOVO(X10, Mem{Base: R10}.Offset(240))
	MOVO(X11, Mem{Base: R10}.Offset(256))
	HALF_ROUND(X0, X1, X2, X3, X4, X5, X6, X7, X8, X9, X10, X11, X11, X13, X14)
	SHUFFLE_INV(X2, X3, X4, X5, X6, X7, X8, X9)

	LOAD_MSG(X8, X9, X10, X11, SI, 11, 12, 5, 15, 8, 0, 2, 13)
	HALF_ROUND(X0, X1, X2, X3, X4, X5, X6, X7, X8, X9, X10, X11, X11, X13, X14)
	SHUFFLE(X2, X3, X4, X5, X6, X7, X8, X9)
	LOAD_MSG(X8, X9, X10, X11, SI, 10, 3, 7, 9, 14, 6, 1, 4)
	HALF_ROUND(X0, X1, X2, X3, X4, X5, X6, X7, X8, X9, X10, X11, X11, X13, X14)
	SHUFFLE_INV(X2, X3, X4, X5, X6, X7, X8, X9)

	LOAD_MSG(X8, X9, X10, X11, SI, 7, 3, 13, 11, 9, 1, 12, 14)
	HALF_ROUND(X0, X1, X2, X3, X4, X5, X6, X7, X8, X9, X10, X11, X11, X13, X14)
	SHUFFLE(X2, X3, X4, X5, X6, X7, X8, X9)
	LOAD_MSG(X8, X9, X10, X11, SI, 2, 5, 4, 15, 6, 10, 0, 8)
	HALF_ROUND(X0, X1, X2, X3, X4, X5, X6, X7, X8, X9, X10, X11, X11, X13, X14)
	SHUFFLE_INV(X2, X3, X4, X5, X6, X7, X8, X9)

	LOAD_MSG(X8, X9, X10, X11, SI, 9, 5, 2, 10, 0, 7, 4, 15)
	HALF_ROUND(X0, X1, X2, X3, X4, X5, X6, X7, X8, X9, X10, X11, X11, X13, X14)
	SHUFFLE(X2, X3, X4, X5, X6, X7, X8, X9)
	LOAD_MSG(X8, X9, X10, X11, SI, 14, 11, 6, 3, 1, 12, 8, 13)
	HALF_ROUND(X0, X1, X2, X3, X4, X5, X6, X7, X8, X9, X10, X11, X11, X13, X14)
	SHUFFLE_INV(X2, X3, X4, X5, X6, X7, X8, X9)

	LOAD_MSG(X8, X9, X10, X11, SI, 2, 6, 0, 8, 12, 10, 11, 3)
	HALF_ROUND(X0, X1, X2, X3, X4, X5, X6, X7, X8, X9, X10, X11, X11, X13, X14)
	SHUFFLE(X2, X3, X4, X5, X6, X7, X8, X9)
	LOAD_MSG(X8, X9, X10, X11, SI, 4, 7, 15, 1, 13, 5, 14, 9)
	HALF_ROUND(X0, X1, X2, X3, X4, X5, X6, X7, X8, X9, X10, X11, X11, X13, X14)
	SHUFFLE_INV(X2, X3, X4, X5, X6, X7, X8, X9)

	LOAD_MSG(X8, X9, X10, X11, SI, 12, 1, 14, 4, 5, 15, 13, 10)
	HALF_ROUND(X0, X1, X2, X3, X4, X5, X6, X7, X8, X9, X10, X11, X11, X13, X14)
	SHUFFLE(X2, X3, X4, X5, X6, X7, X8, X9)
	LOAD_MSG(X8, X9, X10, X11, SI, 0, 6, 9, 8, 7, 3, 2, 11)
	HALF_ROUND(X0, X1, X2, X3, X4, X5, X6, X7, X8, X9, X10, X11, X11, X13, X14)
	SHUFFLE_INV(X2, X3, X4, X5, X6, X7, X8, X9)

	LOAD_MSG(X8, X9, X10, X11, SI, 13, 7, 12, 3, 11, 14, 1, 9)
	HALF_ROUND(X0, X1, X2, X3, X4, X5, X6, X7, X8, X9, X10, X11, X11, X13, X14)
	SHUFFLE(X2, X3, X4, X5, X6, X7, X8, X9)
	LOAD_MSG(X8, X9, X10, X11, SI, 5, 15, 8, 2, 0, 4, 6, 10)
	HALF_ROUND(X0, X1, X2, X3, X4, X5, X6, X7, X8, X9, X10, X11, X11, X13, X14)
	SHUFFLE_INV(X2, X3, X4, X5, X6, X7, X8, X9)

	LOAD_MSG(X8, X9, X10, X11, SI, 6, 14, 11, 0, 15, 9, 3, 8)
	HALF_ROUND(X0, X1, X2, X3, X4, X5, X6, X7, X8, X9, X10, X11, X11, X13, X14)
	SHUFFLE(X2, X3, X4, X5, X6, X7, X8, X9)
	LOAD_MSG(X8, X9, X10, X11, SI, 12, 13, 1, 10, 2, 7, 4, 5)
	HALF_ROUND(X0, X1, X2, X3, X4, X5, X6, X7, X8, X9, X10, X11, X11, X13, X14)
	SHUFFLE_INV(X2, X3, X4, X5, X6, X7, X8, X9)

	LOAD_MSG(X8, X9, X10, X11, SI, 10, 8, 7, 1, 2, 4, 6, 5)
	HALF_ROUND(X0, X1, X2, X3, X4, X5, X6, X7, X8, X9, X10, X11, X11, X13, X14)
	SHUFFLE(X2, X3, X4, X5, X6, X7, X8, X9)
	LOAD_MSG(X8, X9, X10, X11, SI, 15, 9, 3, 13, 11, 14, 12, 0)
	HALF_ROUND(X0, X1, X2, X3, X4, X5, X6, X7, X8, X9, X10, X11, X11, X13, X14)
	SHUFFLE_INV(X2, X3, X4, X5, X6, X7, X8, X9)

	HALF_ROUND(X0, X1, X2, X3, X4, X5, X6, X7, Mem{Base: R10}.Offset(16), Mem{Base: R10}.Offset(32), Mem{Base: R10}.Offset(48), Mem{Base: R10}.Offset(64), X11, X13, X14)
	SHUFFLE(X2, X3, X4, X5, X6, X7, X8, X9)
	HALF_ROUND(X0, X1, X2, X3, X4, X5, X6, X7, Mem{Base: R10}.Offset(80), Mem{Base: R10}.Offset(96), Mem{Base: R10}.Offset(112), Mem{Base: R10}.Offset(128), X11, X13, X14)
	SHUFFLE_INV(X2, X3, X4, X5, X6, X7, X8, X9)

	HALF_ROUND(X0, X1, X2, X3, X4, X5, X6, X7, Mem{Base: R10}.Offset(144), Mem{Base: R10}.Offset(160), Mem{Base: R10}.Offset(176), Mem{Base: R10}.Offset(192), X11, X13, X14)
	SHUFFLE(X2, X3, X4, X5, X6, X7, X8, X9)
	HALF_ROUND(X0, X1, X2, X3, X4, X5, X6, X7, Mem{Base: R10}.Offset(208), Mem{Base: R10}.Offset(224), Mem{Base: R10}.Offset(240), Mem{Base: R10}.Offset(256), X11, X13, X14)
	SHUFFLE_INV(X2, X3, X4, X5, X6, X7, X8, X9)

	MOVOU(Mem{Base: AX}.Offset(32), X10)
	MOVOU(Mem{Base: AX}.Offset(48), X11)
	PXOR(X0, X12)
	PXOR(X1, X15)
	PXOR(X2, X10)
	PXOR(X3, X11)
	PXOR(X4, X12)
	PXOR(X5, X15)
	PXOR(X6, X10)
	PXOR(X7, X11)
	MOVOU(X10, Mem{Base: AX}.Offset(32))
	MOVOU(X11, Mem{Base: AX}.Offset(48))

	LEAQ(Mem{Base: SI}.Offset(128), RSI)
	SUBQ(Imm(128), RDI)
	JNE(LabelRef("loop"))

	MOVOU(X12, Mem{Base: AX}.Offset(0))
	MOVOU(X15, Mem{Base: AX}.Offset(16))

	MOVQ(R8, Mem{Base: BX}.Offset(0))
	MOVQ(R9, Mem{Base: BX}.Offset(8))

	RET()
}

// #~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~DATA SECTION~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~##

func iv0_DATA() Mem {
	if iv0_DATA_ptr != nil {
		return *iv0_DATA_ptr
	}

	iv0 := GLOBL(ThatPeskyUnicodeDot+"iv0", NOPTR|RODATA)
	iv0_DATA_ptr = &iv0
	DATA(0x00, U64(0x6a09e667f3bcc908))
	DATA(0x08, U64(0xbb67ae8584caa73b))
	return iv0
}

func iv1_DATA() Mem {
	if iv1_DATA_ptr != nil {
		return *iv1_DATA_ptr
	}

	iv1 := GLOBL(ThatPeskyUnicodeDot+"iv1", NOPTR|RODATA)
	iv1_DATA_ptr = &iv1
	DATA(0x00, U64(0x3c6ef372fe94f82b))
	DATA(0x08, U64(0xa54ff53a5f1d36f1))
	return iv1
}

func iv2_DATA() Mem {
	if iv2_DATA_ptr != nil {
		return *iv2_DATA_ptr
	}

	iv2 := GLOBL(ThatPeskyUnicodeDot+"iv2", NOPTR|RODATA)
	iv2_DATA_ptr = &iv2
	DATA(0x00, U64(0x510e527fade682d1))
	DATA(0x08, U64(0x9b05688c2b3e6c1f))
	return iv2
}

func iv3_DATA() Mem {
	if iv3_DATA_ptr != nil {
		return *iv3_DATA_ptr
	}

	iv3 := GLOBL(ThatPeskyUnicodeDot+"iv3", NOPTR|RODATA)
	iv3_DATA_ptr = &iv3
	DATA(0x00, U64(0x1f83d9abfb41bd6b))
	DATA(0x08, U64(0x5be0cd19137e2179))
	return iv3
}

func c40_DATA() Mem {
	if c40_DATA_ptr != nil {
		return *c40_DATA_ptr
	}

	c40 := GLOBL(ThatPeskyUnicodeDot+"c40", NOPTR|RODATA)
	c40_DATA_ptr = &c40
	DATA(0x00, U64(0x0201000706050403))
	DATA(0x08, U64(0x0a09080f0e0d0c0b))
	return c40
}

func c48_DATA() Mem {
	if c48_DATA_ptr != nil {
		return *c48_DATA_ptr
	}

	c48 := GLOBL(ThatPeskyUnicodeDot+"c48", NOPTR|RODATA)
	c48_DATA_ptr = &c48
	DATA(0x00, U64(0x0100070605040302))
	DATA(0x08, U64(0x09080f0e0d0c0b0a))
	return c48
}
