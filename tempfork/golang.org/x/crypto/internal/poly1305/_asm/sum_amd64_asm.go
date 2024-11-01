// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	. "github.com/mmcloughlin/avo/build"
	. "github.com/mmcloughlin/avo/operand"
	. "github.com/mmcloughlin/avo/reg"
	_ "golang.org/x/crypto/sha3"
)

//go:generate go run . -out ../sum_amd64.s -pkg poly1305

func main() {
	Package("golang.org/x/crypto/internal/poly1305")
	ConstraintExpr("gc,!purego")
	update()
	Generate()
}

func update() {
	Implement("update")

	Load(Param("state"), RDI)
	MOVQ(NewParamAddr("msg_base", 8), RSI)
	MOVQ(NewParamAddr("msg_len", 16), R15)

	MOVQ(Mem{Base: DI}.Offset(0), R8)   // h0
	MOVQ(Mem{Base: DI}.Offset(8), R9)   // h1
	MOVQ(Mem{Base: DI}.Offset(16), R10) // h2
	MOVQ(Mem{Base: DI}.Offset(24), R11) // r0
	MOVQ(Mem{Base: DI}.Offset(32), R12) // r1

	CMPQ(R15, Imm(16))
	JB(LabelRef("bytes_between_0_and_15"))

	Label("loop")
	POLY1305_ADD(RSI, R8, R9, R10)

	Label("multiply")
	POLY1305_MUL(R8, R9, R10, R11, R12, RBX, RCX, R13, R14)
	SUBQ(Imm(16), R15)
	CMPQ(R15, Imm(16))
	JAE(LabelRef("loop"))

	Label("bytes_between_0_and_15")
	TESTQ(R15, R15)
	JZ(LabelRef("done"))
	MOVQ(U32(1), RBX)
	XORQ(RCX, RCX)
	XORQ(R13, R13)
	ADDQ(R15, RSI)

	Label("flush_buffer")
	SHLQ(Imm(8), RBX, RCX)
	SHLQ(Imm(8), RBX)
	MOVB(Mem{Base: SI}.Offset(-1), R13B)
	XORQ(R13, RBX)
	DECQ(RSI)
	DECQ(R15)
	JNZ(LabelRef("flush_buffer"))

	ADDQ(RBX, R8)
	ADCQ(RCX, R9)
	ADCQ(Imm(0), R10)
	MOVQ(U32(16), R15)
	JMP(LabelRef("multiply"))

	Label("done")
	MOVQ(R8, Mem{Base: DI}.Offset(0))
	MOVQ(R9, Mem{Base: DI}.Offset(8))
	MOVQ(R10, Mem{Base: DI}.Offset(16))
	RET()
}

func POLY1305_ADD(msg, h0, h1, h2 GPPhysical) {
	ADDQ(Mem{Base: msg}.Offset(0), h0)
	ADCQ(Mem{Base: msg}.Offset(8), h1)
	ADCQ(Imm(1), h2)
	LEAQ(Mem{Base: msg}.Offset(16), msg)
}

func POLY1305_MUL(h0, h1, h2, r0, r1, t0, t1, t2, t3 GPPhysical) {
	MOVQ(r0, RAX)
	MULQ(h0)
	MOVQ(RAX, t0)
	MOVQ(RDX, t1)
	MOVQ(r0, RAX)
	MULQ(h1)
	ADDQ(RAX, t1)
	ADCQ(Imm(0), RDX)
	MOVQ(r0, t2)
	IMULQ(h2, t2)
	ADDQ(RDX, t2)

	MOVQ(r1, RAX)
	MULQ(h0)
	ADDQ(RAX, t1)
	ADCQ(Imm(0), RDX)
	MOVQ(RDX, h0)
	MOVQ(r1, t3)
	IMULQ(h2, t3)
	MOVQ(r1, RAX)
	MULQ(h1)
	ADDQ(RAX, t2)
	ADCQ(RDX, t3)
	ADDQ(h0, t2)
	ADCQ(Imm(0), t3)

	MOVQ(t0, h0)
	MOVQ(t1, h1)
	MOVQ(t2, h2)
	ANDQ(Imm(3), h2)
	MOVQ(t2, t0)
	ANDQ(I32(-4), t0)
	ADDQ(t0, h0)
	ADCQ(t3, h1)
	ADCQ(Imm(0), h2)
	SHRQ(Imm(2), t3, t2)
	SHRQ(Imm(2), t3)
	ADDQ(t2, h0)
	ADCQ(t3, h1)
	ADCQ(Imm(0), h2)
}
