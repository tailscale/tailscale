// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	. "github.com/mmcloughlin/avo/build"
	"github.com/mmcloughlin/avo/ir"
	. "github.com/mmcloughlin/avo/operand"
	. "github.com/mmcloughlin/avo/reg"
	_ "golang.org/x/crypto/blake2s"
)

//go:generate go run . -out ../blake2s_amd64.s -pkg blake2s

func main() {
	Package("golang.org/x/crypto/blake2s")
	ConstraintExpr("amd64,gc,!purego")
	hashBlocksSSE2()
	hashBlocksSSSE3()
	hashBlocksSSE4()
	Generate()
}

func ROTL_SSE2(n uint64, t, v VecPhysical) {
	MOVO(v, t)
	PSLLL(Imm(n), t)
	PSRLL(Imm(32-n), v)
	PXOR(t, v)
}

func ROTL_SSSE3(c, v VecPhysical) {
	PSHUFB(c, v)
}

func ROUND_SSE2(v0, v1, v2, v3 VecPhysical, m0, m1, m2, m3 Mem, t VecPhysical) {
	PADDL(m0, v0)
	PADDL(v1, v0)
	PXOR(v0, v3)
	ROTL_SSE2(16, t, v3)
	PADDL(v3, v2)
	PXOR(v2, v1)
	ROTL_SSE2(20, t, v1)
	PADDL(m1, v0)
	PADDL(v1, v0)
	PXOR(v0, v3)
	ROTL_SSE2(24, t, v3)
	PADDL(v3, v2)
	PXOR(v2, v1)
	ROTL_SSE2(25, t, v1)
	PSHUFL(Imm(0x39), v1, v1)
	PSHUFL(Imm(0x4E), v2, v2)
	PSHUFL(Imm(0x93), v3, v3)
	PADDL(m2, v0)
	PADDL(v1, v0)
	PXOR(v0, v3)
	ROTL_SSE2(16, t, v3)
	PADDL(v3, v2)
	PXOR(v2, v1)
	ROTL_SSE2(20, t, v1)
	PADDL(m3, v0)
	PADDL(v1, v0)
	PXOR(v0, v3)
	ROTL_SSE2(24, t, v3)
	PADDL(v3, v2)
	PXOR(v2, v1)
	ROTL_SSE2(25, t, v1)
	PSHUFL(Imm(0x39), v3, v3)
	PSHUFL(Imm(0x4E), v2, v2)
	PSHUFL(Imm(0x93), v1, v1)
}

func ROUND_SSSE3(v0, v1, v2, v3 VecPhysical, m0, m1, m2, m3 Op, t, c16, c8 VecPhysical) {
	PADDL(m0, v0)
	PADDL(v1, v0)
	PXOR(v0, v3)
	ROTL_SSSE3(c16, v3)
	PADDL(v3, v2)
	PXOR(v2, v1)
	ROTL_SSE2(20, t, v1)
	PADDL(m1, v0)
	PADDL(v1, v0)
	PXOR(v0, v3)
	ROTL_SSSE3(c8, v3)
	PADDL(v3, v2)
	PXOR(v2, v1)
	ROTL_SSE2(25, t, v1)
	PSHUFL(Imm(0x39), v1, v1)
	PSHUFL(Imm(0x4E), v2, v2)
	PSHUFL(Imm(0x93), v3, v3)
	PADDL(m2, v0)
	PADDL(v1, v0)
	PXOR(v0, v3)
	ROTL_SSSE3(c16, v3)
	PADDL(v3, v2)
	PXOR(v2, v1)
	ROTL_SSE2(20, t, v1)
	PADDL(m3, v0)
	PADDL(v1, v0)
	PXOR(v0, v3)
	ROTL_SSSE3(c8, v3)
	PADDL(v3, v2)
	PXOR(v2, v1)
	ROTL_SSE2(25, t, v1)
	PSHUFL(Imm(0x39), v3, v3)
	PSHUFL(Imm(0x4E), v2, v2)
	PSHUFL(Imm(0x93), v1, v1)
}

func LOAD_MSG_SSE4(m0, m1, m2, m3 VecPhysical, src GPPhysical, i0, i1, i2, i3, i4, i5, i6, i7, i8, i9, i10, i11, i12, i13, i14, i15 int) {
	// Hack to get Avo to emit a MOVL instruction with a VecPhysical as the destination
	Instruction(&ir.Instruction{Opcode: "MOVL", Operands: []Op{Mem{Base: src}.Offset(i0 * 4), m0}})
	PINSRD(Imm(1), Mem{Base: src}.Offset(i1*4), m0)
	PINSRD(Imm(2), Mem{Base: src}.Offset(i2*4), m0)
	PINSRD(Imm(3), Mem{Base: src}.Offset(i3*4), m0)
	Instruction(&ir.Instruction{Opcode: "MOVL", Operands: []Op{Mem{Base: src}.Offset(i4 * 4), m1}})
	PINSRD(Imm(1), Mem{Base: src}.Offset(i5*4), m1)
	PINSRD(Imm(2), Mem{Base: src}.Offset(i6*4), m1)
	PINSRD(Imm(3), Mem{Base: src}.Offset(i7*4), m1)
	Instruction(&ir.Instruction{Opcode: "MOVL", Operands: []Op{Mem{Base: src}.Offset(i8 * 4), m2}})
	PINSRD(Imm(1), Mem{Base: src}.Offset(i9*4), m2)
	PINSRD(Imm(2), Mem{Base: src}.Offset(i10*4), m2)
	PINSRD(Imm(3), Mem{Base: src}.Offset(i11*4), m2)
	Instruction(&ir.Instruction{Opcode: "MOVL", Operands: []Op{Mem{Base: src}.Offset(i12 * 4), m3}})
	PINSRD(Imm(1), Mem{Base: src}.Offset(i13*4), m3)
	PINSRD(Imm(2), Mem{Base: src}.Offset(i14*4), m3)
	PINSRD(Imm(3), Mem{Base: src}.Offset(i15*4), m3)
}

func PRECOMPUTE_MSG(dst GPPhysical, off int, src, R8, R9, R10, R11, R12, R13, R14, R15 GPPhysical) {
	MOVQ(Mem{Base: src}.Offset(0*4), R8)
	MOVQ(Mem{Base: src}.Offset(2*4), R9)
	MOVQ(Mem{Base: src}.Offset(4*4), R10)
	MOVQ(Mem{Base: src}.Offset(6*4), R11)
	MOVQ(Mem{Base: src}.Offset(8*4), R12)
	MOVQ(Mem{Base: src}.Offset(10*4), R13)
	MOVQ(Mem{Base: src}.Offset(12*4), R14)
	MOVQ(Mem{Base: src}.Offset(14*4), R15)

	MOVL(R8L, Mem{Base: dst}.Offset(0*4+off+0))
	MOVL(R8L, Mem{Base: dst}.Offset(9*4+off+64))
	MOVL(R8L, Mem{Base: dst}.Offset(5*4+off+128))
	MOVL(R8L, Mem{Base: dst}.Offset(14*4+off+192))
	MOVL(R8L, Mem{Base: dst}.Offset(4*4+off+256))
	MOVL(R8L, Mem{Base: dst}.Offset(2*4+off+320))
	MOVL(R8L, Mem{Base: dst}.Offset(8*4+off+384))
	MOVL(R8L, Mem{Base: dst}.Offset(12*4+off+448))
	MOVL(R8L, Mem{Base: dst}.Offset(3*4+off+512))
	MOVL(R8L, Mem{Base: dst}.Offset(15*4+off+576))
	SHRQ(Imm(32), R8)
	MOVL(R8L, Mem{Base: dst}.Offset(4*4+off+0))
	MOVL(R8L, Mem{Base: dst}.Offset(8*4+off+64))
	MOVL(R8L, Mem{Base: dst}.Offset(14*4+off+128))
	MOVL(R8L, Mem{Base: dst}.Offset(5*4+off+192))
	MOVL(R8L, Mem{Base: dst}.Offset(12*4+off+256))
	MOVL(R8L, Mem{Base: dst}.Offset(11*4+off+320))
	MOVL(R8L, Mem{Base: dst}.Offset(1*4+off+384))
	MOVL(R8L, Mem{Base: dst}.Offset(6*4+off+448))
	MOVL(R8L, Mem{Base: dst}.Offset(10*4+off+512))
	MOVL(R8L, Mem{Base: dst}.Offset(3*4+off+576))

	MOVL(R9L, Mem{Base: dst}.Offset(1*4+off+0))
	MOVL(R9L, Mem{Base: dst}.Offset(13*4+off+64))
	MOVL(R9L, Mem{Base: dst}.Offset(6*4+off+128))
	MOVL(R9L, Mem{Base: dst}.Offset(8*4+off+192))
	MOVL(R9L, Mem{Base: dst}.Offset(2*4+off+256))
	MOVL(R9L, Mem{Base: dst}.Offset(0*4+off+320))
	MOVL(R9L, Mem{Base: dst}.Offset(14*4+off+384))
	MOVL(R9L, Mem{Base: dst}.Offset(11*4+off+448))
	MOVL(R9L, Mem{Base: dst}.Offset(12*4+off+512))
	MOVL(R9L, Mem{Base: dst}.Offset(4*4+off+576))
	SHRQ(Imm(32), R9)
	MOVL(R9L, Mem{Base: dst}.Offset(5*4+off+0))
	MOVL(R9L, Mem{Base: dst}.Offset(15*4+off+64))
	MOVL(R9L, Mem{Base: dst}.Offset(9*4+off+128))
	MOVL(R9L, Mem{Base: dst}.Offset(1*4+off+192))
	MOVL(R9L, Mem{Base: dst}.Offset(11*4+off+256))
	MOVL(R9L, Mem{Base: dst}.Offset(7*4+off+320))
	MOVL(R9L, Mem{Base: dst}.Offset(13*4+off+384))
	MOVL(R9L, Mem{Base: dst}.Offset(3*4+off+448))
	MOVL(R9L, Mem{Base: dst}.Offset(6*4+off+512))
	MOVL(R9L, Mem{Base: dst}.Offset(10*4+off+576))

	MOVL(R10L, Mem{Base: dst}.Offset(2*4+off+0))
	MOVL(R10L, Mem{Base: dst}.Offset(1*4+off+64))
	MOVL(R10L, Mem{Base: dst}.Offset(15*4+off+128))
	MOVL(R10L, Mem{Base: dst}.Offset(10*4+off+192))
	MOVL(R10L, Mem{Base: dst}.Offset(6*4+off+256))
	MOVL(R10L, Mem{Base: dst}.Offset(8*4+off+320))
	MOVL(R10L, Mem{Base: dst}.Offset(3*4+off+384))
	MOVL(R10L, Mem{Base: dst}.Offset(13*4+off+448))
	MOVL(R10L, Mem{Base: dst}.Offset(14*4+off+512))
	MOVL(R10L, Mem{Base: dst}.Offset(5*4+off+576))
	SHRQ(Imm(32), R10)
	MOVL(R10L, Mem{Base: dst}.Offset(6*4+off+0))
	MOVL(R10L, Mem{Base: dst}.Offset(11*4+off+64))
	MOVL(R10L, Mem{Base: dst}.Offset(2*4+off+128))
	MOVL(R10L, Mem{Base: dst}.Offset(9*4+off+192))
	MOVL(R10L, Mem{Base: dst}.Offset(1*4+off+256))
	MOVL(R10L, Mem{Base: dst}.Offset(13*4+off+320))
	MOVL(R10L, Mem{Base: dst}.Offset(4*4+off+384))
	MOVL(R10L, Mem{Base: dst}.Offset(8*4+off+448))
	MOVL(R10L, Mem{Base: dst}.Offset(15*4+off+512))
	MOVL(R10L, Mem{Base: dst}.Offset(7*4+off+576))

	MOVL(R11L, Mem{Base: dst}.Offset(3*4+off+0))
	MOVL(R11L, Mem{Base: dst}.Offset(7*4+off+64))
	MOVL(R11L, Mem{Base: dst}.Offset(13*4+off+128))
	MOVL(R11L, Mem{Base: dst}.Offset(12*4+off+192))
	MOVL(R11L, Mem{Base: dst}.Offset(10*4+off+256))
	MOVL(R11L, Mem{Base: dst}.Offset(1*4+off+320))
	MOVL(R11L, Mem{Base: dst}.Offset(9*4+off+384))
	MOVL(R11L, Mem{Base: dst}.Offset(14*4+off+448))
	MOVL(R11L, Mem{Base: dst}.Offset(0*4+off+512))
	MOVL(R11L, Mem{Base: dst}.Offset(6*4+off+576))
	SHRQ(Imm(32), R11)
	MOVL(R11L, Mem{Base: dst}.Offset(7*4+off+0))
	MOVL(R11L, Mem{Base: dst}.Offset(14*4+off+64))
	MOVL(R11L, Mem{Base: dst}.Offset(10*4+off+128))
	MOVL(R11L, Mem{Base: dst}.Offset(0*4+off+192))
	MOVL(R11L, Mem{Base: dst}.Offset(5*4+off+256))
	MOVL(R11L, Mem{Base: dst}.Offset(9*4+off+320))
	MOVL(R11L, Mem{Base: dst}.Offset(12*4+off+384))
	MOVL(R11L, Mem{Base: dst}.Offset(1*4+off+448))
	MOVL(R11L, Mem{Base: dst}.Offset(13*4+off+512))
	MOVL(R11L, Mem{Base: dst}.Offset(2*4+off+576))

	MOVL(R12L, Mem{Base: dst}.Offset(8*4+off+0))
	MOVL(R12L, Mem{Base: dst}.Offset(5*4+off+64))
	MOVL(R12L, Mem{Base: dst}.Offset(4*4+off+128))
	MOVL(R12L, Mem{Base: dst}.Offset(15*4+off+192))
	MOVL(R12L, Mem{Base: dst}.Offset(14*4+off+256))
	MOVL(R12L, Mem{Base: dst}.Offset(3*4+off+320))
	MOVL(R12L, Mem{Base: dst}.Offset(11*4+off+384))
	MOVL(R12L, Mem{Base: dst}.Offset(10*4+off+448))
	MOVL(R12L, Mem{Base: dst}.Offset(7*4+off+512))
	MOVL(R12L, Mem{Base: dst}.Offset(1*4+off+576))
	SHRQ(Imm(32), R12)
	MOVL(R12L, Mem{Base: dst}.Offset(12*4+off+0))
	MOVL(R12L, Mem{Base: dst}.Offset(2*4+off+64))
	MOVL(R12L, Mem{Base: dst}.Offset(11*4+off+128))
	MOVL(R12L, Mem{Base: dst}.Offset(4*4+off+192))
	MOVL(R12L, Mem{Base: dst}.Offset(0*4+off+256))
	MOVL(R12L, Mem{Base: dst}.Offset(15*4+off+320))
	MOVL(R12L, Mem{Base: dst}.Offset(10*4+off+384))
	MOVL(R12L, Mem{Base: dst}.Offset(7*4+off+448))
	MOVL(R12L, Mem{Base: dst}.Offset(5*4+off+512))
	MOVL(R12L, Mem{Base: dst}.Offset(9*4+off+576))

	MOVL(R13L, Mem{Base: dst}.Offset(9*4+off+0))
	MOVL(R13L, Mem{Base: dst}.Offset(4*4+off+64))
	MOVL(R13L, Mem{Base: dst}.Offset(8*4+off+128))
	MOVL(R13L, Mem{Base: dst}.Offset(13*4+off+192))
	MOVL(R13L, Mem{Base: dst}.Offset(3*4+off+256))
	MOVL(R13L, Mem{Base: dst}.Offset(5*4+off+320))
	MOVL(R13L, Mem{Base: dst}.Offset(7*4+off+384))
	MOVL(R13L, Mem{Base: dst}.Offset(15*4+off+448))
	MOVL(R13L, Mem{Base: dst}.Offset(11*4+off+512))
	MOVL(R13L, Mem{Base: dst}.Offset(0*4+off+576))
	SHRQ(Imm(32), R13)
	MOVL(R13L, Mem{Base: dst}.Offset(13*4+off+0))
	MOVL(R13L, Mem{Base: dst}.Offset(10*4+off+64))
	MOVL(R13L, Mem{Base: dst}.Offset(0*4+off+128))
	MOVL(R13L, Mem{Base: dst}.Offset(3*4+off+192))
	MOVL(R13L, Mem{Base: dst}.Offset(9*4+off+256))
	MOVL(R13L, Mem{Base: dst}.Offset(6*4+off+320))
	MOVL(R13L, Mem{Base: dst}.Offset(15*4+off+384))
	MOVL(R13L, Mem{Base: dst}.Offset(4*4+off+448))
	MOVL(R13L, Mem{Base: dst}.Offset(2*4+off+512))
	MOVL(R13L, Mem{Base: dst}.Offset(12*4+off+576))

	MOVL(R14L, Mem{Base: dst}.Offset(10*4+off+0))
	MOVL(R14L, Mem{Base: dst}.Offset(12*4+off+64))
	MOVL(R14L, Mem{Base: dst}.Offset(1*4+off+128))
	MOVL(R14L, Mem{Base: dst}.Offset(6*4+off+192))
	MOVL(R14L, Mem{Base: dst}.Offset(13*4+off+256))
	MOVL(R14L, Mem{Base: dst}.Offset(4*4+off+320))
	MOVL(R14L, Mem{Base: dst}.Offset(0*4+off+384))
	MOVL(R14L, Mem{Base: dst}.Offset(2*4+off+448))
	MOVL(R14L, Mem{Base: dst}.Offset(8*4+off+512))
	MOVL(R14L, Mem{Base: dst}.Offset(14*4+off+576))
	SHRQ(Imm(32), R14)
	MOVL(R14L, Mem{Base: dst}.Offset(14*4+off+0))
	MOVL(R14L, Mem{Base: dst}.Offset(3*4+off+64))
	MOVL(R14L, Mem{Base: dst}.Offset(7*4+off+128))
	MOVL(R14L, Mem{Base: dst}.Offset(2*4+off+192))
	MOVL(R14L, Mem{Base: dst}.Offset(15*4+off+256))
	MOVL(R14L, Mem{Base: dst}.Offset(12*4+off+320))
	MOVL(R14L, Mem{Base: dst}.Offset(6*4+off+384))
	MOVL(R14L, Mem{Base: dst}.Offset(0*4+off+448))
	MOVL(R14L, Mem{Base: dst}.Offset(9*4+off+512))
	MOVL(R14L, Mem{Base: dst}.Offset(11*4+off+576))

	MOVL(R15L, Mem{Base: dst}.Offset(11*4+off+0))
	MOVL(R15L, Mem{Base: dst}.Offset(0*4+off+64))
	MOVL(R15L, Mem{Base: dst}.Offset(12*4+off+128))
	MOVL(R15L, Mem{Base: dst}.Offset(7*4+off+192))
	MOVL(R15L, Mem{Base: dst}.Offset(8*4+off+256))
	MOVL(R15L, Mem{Base: dst}.Offset(14*4+off+320))
	MOVL(R15L, Mem{Base: dst}.Offset(2*4+off+384))
	MOVL(R15L, Mem{Base: dst}.Offset(5*4+off+448))
	MOVL(R15L, Mem{Base: dst}.Offset(1*4+off+512))
	MOVL(R15L, Mem{Base: dst}.Offset(13*4+off+576))
	SHRQ(Imm(32), R15)
	MOVL(R15L, Mem{Base: dst}.Offset(15*4+off+0))
	MOVL(R15L, Mem{Base: dst}.Offset(6*4+off+64))
	MOVL(R15L, Mem{Base: dst}.Offset(3*4+off+128))
	MOVL(R15L, Mem{Base: dst}.Offset(11*4+off+192))
	MOVL(R15L, Mem{Base: dst}.Offset(7*4+off+256))
	MOVL(R15L, Mem{Base: dst}.Offset(10*4+off+320))
	MOVL(R15L, Mem{Base: dst}.Offset(5*4+off+384))
	MOVL(R15L, Mem{Base: dst}.Offset(9*4+off+448))
	MOVL(R15L, Mem{Base: dst}.Offset(4*4+off+512))
	MOVL(R15L, Mem{Base: dst}.Offset(8*4+off+576))
}

func BLAKE2s_SSE2() {
	PRECOMPUTE_MSG(BP, 16, SI, R8, R9, R10, R11, R12, R13, R14, R15)
	for i := 0; i < 10; i++ {
		ROUND_SSE2(X4, X5, X6, X7, Mem{Base: BP}.Offset(16+64*i), Mem{Base: BP}.Offset(32+64*i), Mem{Base: BP}.Offset(48+64*i), Mem{Base: BP}.Offset(64+64*i), X8)
	}
}

func BLAKE2s_SSSE3() {
	PRECOMPUTE_MSG(BP, 16, SI, R8, R9, R10, R11, R12, R13, R14, R15)
	for i := 0; i < 10; i++ {
		ROUND_SSSE3(X4, X5, X6, X7, Mem{Base: BP}.Offset(16+64*i), Mem{Base: BP}.Offset(32+64*i), Mem{Base: BP}.Offset(48+64*i), Mem{Base: BP}.Offset(64+64*i), X8, X13, X14)
	}
}

func BLAKE2s_SSE4() {
	LOAD_MSG_SSE4(X8, X9, X10, X11, SI, 0, 2, 4, 6, 1, 3, 5, 7, 8, 10, 12, 14, 9, 11, 13, 15)
	ROUND_SSSE3(X4, X5, X6, X7, X8, X9, X10, X11, X8, X13, X14)
	LOAD_MSG_SSE4(X8, X9, X10, X11, SI, 14, 4, 9, 13, 10, 8, 15, 6, 1, 0, 11, 5, 12, 2, 7, 3)
	ROUND_SSSE3(X4, X5, X6, X7, X8, X9, X10, X11, X8, X13, X14)
	LOAD_MSG_SSE4(X8, X9, X10, X11, SI, 11, 12, 5, 15, 8, 0, 2, 13, 10, 3, 7, 9, 14, 6, 1, 4)
	ROUND_SSSE3(X4, X5, X6, X7, X8, X9, X10, X11, X8, X13, X14)
	LOAD_MSG_SSE4(X8, X9, X10, X11, SI, 7, 3, 13, 11, 9, 1, 12, 14, 2, 5, 4, 15, 6, 10, 0, 8)
	ROUND_SSSE3(X4, X5, X6, X7, X8, X9, X10, X11, X8, X13, X14)
	LOAD_MSG_SSE4(X8, X9, X10, X11, SI, 9, 5, 2, 10, 0, 7, 4, 15, 14, 11, 6, 3, 1, 12, 8, 13)
	ROUND_SSSE3(X4, X5, X6, X7, X8, X9, X10, X11, X8, X13, X14)
	LOAD_MSG_SSE4(X8, X9, X10, X11, SI, 2, 6, 0, 8, 12, 10, 11, 3, 4, 7, 15, 1, 13, 5, 14, 9)
	ROUND_SSSE3(X4, X5, X6, X7, X8, X9, X10, X11, X8, X13, X14)
	LOAD_MSG_SSE4(X8, X9, X10, X11, SI, 12, 1, 14, 4, 5, 15, 13, 10, 0, 6, 9, 8, 7, 3, 2, 11)
	ROUND_SSSE3(X4, X5, X6, X7, X8, X9, X10, X11, X8, X13, X14)
	LOAD_MSG_SSE4(X8, X9, X10, X11, SI, 13, 7, 12, 3, 11, 14, 1, 9, 5, 15, 8, 2, 0, 4, 6, 10)
	ROUND_SSSE3(X4, X5, X6, X7, X8, X9, X10, X11, X8, X13, X14)
	LOAD_MSG_SSE4(X8, X9, X10, X11, SI, 6, 14, 11, 0, 15, 9, 3, 8, 12, 13, 1, 10, 2, 7, 4, 5)
	ROUND_SSSE3(X4, X5, X6, X7, X8, X9, X10, X11, X8, X13, X14)
	LOAD_MSG_SSE4(X8, X9, X10, X11, SI, 10, 8, 7, 1, 2, 4, 6, 5, 15, 9, 3, 13, 11, 14, 12, 0)
	ROUND_SSSE3(X4, X5, X6, X7, X8, X9, X10, X11, X8, X13, X14)
}

func HASH_BLOCKS(h, c, flag, blocks_base, blocks_len Mem, BLAKE2s_FUNC func()) {
	MOVQ(h, RAX)
	MOVQ(c, RBX)
	MOVL(flag, ECX)
	MOVQ(blocks_base, RSI)
	MOVQ(blocks_len, RDX)

	MOVQ(RSP, RBP)
	ADDQ(Imm(15), RBP)
	ANDQ(I32(^15), RBP)

	MOVQ(Mem{Base: BX}.Offset(0), R9)
	MOVQ(R9, Mem{Base: BP}.Offset(0))
	MOVQ(RCX, Mem{Base: BP}.Offset(8))

	MOVOU(Mem{Base: AX}.Offset(0), X0)
	MOVOU(Mem{Base: AX}.Offset(16), X1)

	iv0 := iv0_DATA()
	iv1 := iv1_DATA()
	MOVOU(iv0, X2)
	MOVOU(iv1, X3)

	counter := counter_DATA()
	rol16 := rol16_DATA()
	rol8 := rol8_DATA()
	MOVOU(counter, X12)
	MOVOU(rol16, X13)
	MOVOU(rol8, X14)
	MOVO(Mem{Base: BP}.Offset(0), X15)

	Label("loop")
	MOVO(X0, X4)
	MOVO(X1, X5)
	MOVO(X2, X6)
	MOVO(X3, X7)

	PADDQ(X12, X15)
	PXOR(X15, X7)

	BLAKE2s_FUNC()

	PXOR(X4, X0)
	PXOR(X5, X1)
	PXOR(X6, X0)
	PXOR(X7, X1)

	LEAQ(Mem{Base: SI}.Offset(64), RSI)
	SUBQ(Imm(64), RDX)
	JNE(LabelRef("loop"))

	MOVO(X15, Mem{Base: BP}.Offset(0))
	MOVQ(Mem{Base: BP}.Offset(0), R9)
	MOVQ(R9, Mem{Base: BX}.Offset(0))

	MOVOU(X0, Mem{Base: AX}.Offset(0))
	MOVOU(X1, Mem{Base: AX}.Offset(16))
}

func hashBlocksSSE2() {
	Implement("hashBlocksSSE2")
	Attributes(0)
	AllocLocal(672) // frame = 656 + 16 byte alignment

	h := NewParamAddr("h", 0)
	c := NewParamAddr("c", 8)
	flag := NewParamAddr("flag", 16)
	blocks_base := NewParamAddr("blocks_base", 24)
	blocks_len := NewParamAddr("blocks_len", 32)

	HASH_BLOCKS(h, c, flag, blocks_base, blocks_len, BLAKE2s_SSE2)
	RET()
}

func hashBlocksSSSE3() {
	Implement("hashBlocksSSSE3")
	Attributes(0)
	AllocLocal(672) // frame = 656 + 16 byte alignment

	h := NewParamAddr("h", 0)
	c := NewParamAddr("c", 8)
	flag := NewParamAddr("flag", 16)
	blocks_base := NewParamAddr("blocks_base", 24)
	blocks_len := NewParamAddr("blocks_len", 32)

	HASH_BLOCKS(h, c, flag, blocks_base, blocks_len, BLAKE2s_SSSE3)
	RET()
}

func hashBlocksSSE4() {
	Implement("hashBlocksSSE4")
	Attributes(0)
	AllocLocal(32) // frame = 16 + 16 byte alignment

	h := NewParamAddr("h", 0)
	c := NewParamAddr("c", 8)
	flag := NewParamAddr("flag", 16)
	blocks_base := NewParamAddr("blocks_base", 24)
	blocks_len := NewParamAddr("blocks_len", 32)

	HASH_BLOCKS(h, c, flag, blocks_base, blocks_len, BLAKE2s_SSE4)
	RET()
}

// ##~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~DATA SECTION~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~##

var iv0_DATA_ptr, iv1_DATA_ptr, rol16_DATA_ptr, rol8_DATA_ptr, counter_DATA_ptr *Mem

func iv0_DATA() Mem {
	if iv0_DATA_ptr != nil {
		return *iv0_DATA_ptr
	}

	iv0_DATA := GLOBL("iv0", NOPTR|RODATA)
	iv0_DATA_ptr = &iv0_DATA
	DATA(0x00, U32(0x6a09e667))
	DATA(0x04, U32(0xbb67ae85))
	DATA(0x08, U32(0x3c6ef372))
	DATA(0x0c, U32(0xa54ff53a))
	return iv0_DATA
}

func iv1_DATA() Mem {
	if iv1_DATA_ptr != nil {
		return *iv1_DATA_ptr
	}

	iv1_DATA := GLOBL("iv1", NOPTR|RODATA)
	iv1_DATA_ptr = &iv1_DATA
	DATA(0x00, U32(0x510e527f))
	DATA(0x04, U32(0x9b05688c))
	DATA(0x08, U32(0x1f83d9ab))
	DATA(0x0c, U32(0x5be0cd19))
	return iv1_DATA
}

func rol16_DATA() Mem {
	if rol16_DATA_ptr != nil {
		return *rol16_DATA_ptr
	}

	rol16_DATA := GLOBL("rol16", NOPTR|RODATA)
	rol16_DATA_ptr = &rol16_DATA
	DATA(0x00, U64(0x0504070601000302))
	DATA(0x08, U64(0x0D0C0F0E09080B0A))
	return rol16_DATA
}

func rol8_DATA() Mem {
	if rol8_DATA_ptr != nil {
		return *rol8_DATA_ptr
	}

	rol8_DATA := GLOBL("rol8", NOPTR|RODATA)
	rol8_DATA_ptr = &rol8_DATA
	DATA(0x00, U64(0x0407060500030201))
	DATA(0x08, U64(0x0C0F0E0D080B0A09))
	return rol8_DATA
}

func counter_DATA() Mem {
	if counter_DATA_ptr != nil {
		return *counter_DATA_ptr
	}

	counter_DATA := GLOBL("counter", NOPTR|RODATA)
	counter_DATA_ptr = &counter_DATA
	DATA(0x00, U64(0x0000000000000040))
	DATA(0x08, U64(0x0000000000000000))
	return counter_DATA
}
