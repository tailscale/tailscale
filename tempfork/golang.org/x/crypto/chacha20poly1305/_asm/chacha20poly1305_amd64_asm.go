// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// This assembly implementation was originally from https://golang.org/cl/24717 by Vlad Krasnov of CloudFlare.

package main

import (
	"fmt"
	"os"
	"strings"

	. "github.com/mmcloughlin/avo/build"
	"github.com/mmcloughlin/avo/ir"
	. "github.com/mmcloughlin/avo/operand"
	. "github.com/mmcloughlin/avo/reg"
	_ "golang.org/x/crypto/chacha20poly1305"
)

//go:generate go run . -out ../chacha20poly1305_amd64.s -pkg chacha20poly1305

var (
	// General register allocation
	oup  GPPhysical = RDI
	inp             = RSI
	inl             = RBX
	adp             = RCX // free to reuse, after we hash the additional data
	keyp            = R8  // free to reuse, when we copy the key to stack
	itr2            = R9  // general iterator
	itr1            = RCX // general iterator
	acc0            = R10
	acc1            = R11
	acc2            = R12
	t0              = R13
	t1              = R14
	t2              = R15
	t3              = R8

	// Register and stack allocation for the SSE code
	rStore      Mem         = Mem{Base: BP}.Offset(0 * 16)
	sStore                  = Mem{Base: BP}.Offset(1 * 16)
	state1Store             = Mem{Base: BP}.Offset(2 * 16)
	state2Store             = Mem{Base: BP}.Offset(3 * 16)
	tmpStore                = Mem{Base: BP}.Offset(4 * 16)
	ctr0Store               = Mem{Base: BP}.Offset(5 * 16)
	ctr1Store               = Mem{Base: BP}.Offset(6 * 16)
	ctr2Store               = Mem{Base: BP}.Offset(7 * 16)
	ctr3Store               = Mem{Base: BP}.Offset(8 * 16)
	A0          VecPhysical = X0
	A1                      = X1
	A2                      = X2
	B0                      = X3
	B1                      = X4
	B2                      = X5
	C0                      = X6
	C1                      = X7
	C2                      = X8
	D0                      = X9
	D1                      = X10
	D2                      = X11
	T0                      = X12
	T1                      = X13
	T2                      = X14
	T3                      = X15
	A3                      = T0
	B3                      = T1
	C3                      = T2
	D3                      = T3

	// Register and stack allocation for the AVX2 code
	rsStoreAVX2     Mem         = Mem{Base: BP}.Offset(0 * 32)
	state1StoreAVX2             = Mem{Base: BP}.Offset(1 * 32)
	state2StoreAVX2             = Mem{Base: BP}.Offset(2 * 32)
	ctr0StoreAVX2               = Mem{Base: BP}.Offset(3 * 32)
	ctr1StoreAVX2               = Mem{Base: BP}.Offset(4 * 32)
	ctr2StoreAVX2               = Mem{Base: BP}.Offset(5 * 32)
	ctr3StoreAVX2               = Mem{Base: BP}.Offset(6 * 32)
	tmpStoreAVX2                = Mem{Base: BP}.Offset(7 * 32) // 256 bytes on stack
	AA0             VecPhysical = Y0
	AA1                         = Y5
	AA2                         = Y6
	AA3                         = Y7
	BB0                         = Y14
	BB1                         = Y9
	BB2                         = Y10
	BB3                         = Y11
	CC0                         = Y12
	CC1                         = Y13
	CC2                         = Y8
	CC3                         = Y15
	DD0                         = Y4
	DD1                         = Y1
	DD2                         = Y2
	DD3                         = Y3
	TT0                         = DD3
	TT1                         = AA3
	TT2                         = BB3
	TT3                         = CC3
)

const ThatPeskyUnicodeDot = "\u00b7"

func main() {
	Package("golang.org/x/crypto/chacha20poly1305")
	ConstraintExpr("gc,!purego")
	polyHashADInternal()
	chacha20Poly1305Open()
	chacha20Poly1305Seal()
	Generate()

	var internalFunctions []string = []string{"·polyHashADInternal"}
	removePeskyUnicodeDot(internalFunctions, "../chacha20poly1305_amd64.s")
}

// Utility function to emit BYTE instruction
func BYTE(u8 U8) {
	Instruction(&ir.Instruction{Opcode: "BYTE", Operands: []Op{u8}})
}

// PALIGNR $4, X3, X3
func shiftB0Left() {
	BYTE(U8(0x66))
	BYTE(U8(0x0f))
	BYTE(U8(0x3a))
	BYTE(U8(0x0f))
	BYTE(U8(0xdb))
	BYTE(U8(0x04))
}

// PALIGNR $4, X4, X4
func shiftB1Left() {
	BYTE(U8(0x66))
	BYTE(U8(0x0f))
	BYTE(U8(0x3a))
	BYTE(U8(0x0f))
	BYTE(U8(0xe4))
	BYTE(U8(0x04))
}

// PALIGNR $4, X5, X5
func shiftB2Left() {
	BYTE(U8(0x66))
	BYTE(U8(0x0f))
	BYTE(U8(0x3a))
	BYTE(U8(0x0f))
	BYTE(U8(0xed))
	BYTE(U8(0x04))
}

// PALIGNR $4, X13, X13
func shiftB3Left() {
	BYTE(U8(0x66))
	BYTE(U8(0x45))
	BYTE(U8(0x0f))
	BYTE(U8(0x3a))
	BYTE(U8(0x0f))
	BYTE(U8(0xed))
	BYTE(U8(0x04))
}

// PALIGNR $8, X6, X6
func shiftC0Left() {
	BYTE(U8(0x66))
	BYTE(U8(0x0f))
	BYTE(U8(0x3a))
	BYTE(U8(0x0f))
	BYTE(U8(0xf6))
	BYTE(U8(0x08))
}

// PALIGNR $8, X7, X7
func shiftC1Left() {
	BYTE(U8(0x66))
	BYTE(U8(0x0f))
	BYTE(U8(0x3a))
	BYTE(U8(0x0f))
	BYTE(U8(0xff))
	BYTE(U8(0x08))
}

// PALIGNR $8, X8, X8
func shiftC2Left() {
	BYTE(U8(0x66))
	BYTE(U8(0x45))
	BYTE(U8(0x0f))
	BYTE(U8(0x3a))
	BYTE(U8(0x0f))
	BYTE(U8(0xc0))
	BYTE(U8(0x08))
}

// PALIGNR $8, X14, X14
func shiftC3Left() {
	BYTE(U8(0x66))
	BYTE(U8(0x45))
	BYTE(U8(0x0f))
	BYTE(U8(0x3a))
	BYTE(U8(0x0f))
	BYTE(U8(0xf6))
	BYTE(U8(0x08))
}

// PALIGNR $12, X9, X9
func shiftD0Left() {
	BYTE(U8(0x66))
	BYTE(U8(0x45))
	BYTE(U8(0x0f))
	BYTE(U8(0x3a))
	BYTE(U8(0x0f))
	BYTE(U8(0xc9))
	BYTE(U8(0x0c))
}

// PALIGNR $12, X10, X10
func shiftD1Left() {
	BYTE(U8(0x66))
	BYTE(U8(0x45))
	BYTE(U8(0x0f))
	BYTE(U8(0x3a))
	BYTE(U8(0x0f))
	BYTE(U8(0xd2))
	BYTE(U8(0x0c))
}

// PALIGNR $12, X11, X11
func shiftD2Left() {
	BYTE(U8(0x66))
	BYTE(U8(0x45))
	BYTE(U8(0x0f))
	BYTE(U8(0x3a))
	BYTE(U8(0x0f))
	BYTE(U8(0xdb))
	BYTE(U8(0x0c))
}

// PALIGNR $12, X15, X15
func shiftD3Left() {
	BYTE(U8(0x66))
	BYTE(U8(0x45))
	BYTE(U8(0x0f))
	BYTE(U8(0x3a))
	BYTE(U8(0x0f))
	BYTE(U8(0xff))
	BYTE(U8(0x0c))
}

// PALIGNR $12, X3, X3
func shiftB0Right() {
	BYTE(U8(0x66))
	BYTE(U8(0x0f))
	BYTE(U8(0x3a))
	BYTE(U8(0x0f))
	BYTE(U8(0xdb))
	BYTE(U8(0x0c))
}

// PALIGNR $12, X4, X4
func shiftB1Right() {
	BYTE(U8(0x66))
	BYTE(U8(0x0f))
	BYTE(U8(0x3a))
	BYTE(U8(0x0f))
	BYTE(U8(0xe4))
	BYTE(U8(0x0c))
}

// PALIGNR $12, X5, X5
func shiftB2Right() {
	BYTE(U8(0x66))
	BYTE(U8(0x0f))
	BYTE(U8(0x3a))
	BYTE(U8(0x0f))
	BYTE(U8(0xed))
	BYTE(U8(0x0c))
}

// PALIGNR $12, X13, X13
func shiftB3Right() {
	BYTE(U8(0x66))
	BYTE(U8(0x45))
	BYTE(U8(0x0f))
	BYTE(U8(0x3a))
	BYTE(U8(0x0f))
	BYTE(U8(0xed))
	BYTE(U8(0x0c))
}

func shiftC0Right() {
	shiftC0Left()
}

func shiftC1Right() {
	shiftC1Left()
}

func shiftC2Right() {
	shiftC2Left()
}

func shiftC3Right() {
	shiftC3Left()
}

// PALIGNR $4, X9, X9
func shiftD0Right() {
	BYTE(U8(0x66))
	BYTE(U8(0x45))
	BYTE(U8(0x0f))
	BYTE(U8(0x3a))
	BYTE(U8(0x0f))
	BYTE(U8(0xc9))
	BYTE(U8(0x04))
}

// PALIGNR $4, X10, X10
func shiftD1Right() {
	BYTE(U8(0x66))
	BYTE(U8(0x45))
	BYTE(U8(0x0f))
	BYTE(U8(0x3a))
	BYTE(U8(0x0f))
	BYTE(U8(0xd2))
	BYTE(U8(0x04))
}

// PALIGNR $4, X11, X11
func shiftD2Right() {
	BYTE(U8(0x66))
	BYTE(U8(0x45))
	BYTE(U8(0x0f))
	BYTE(U8(0x3a))
	BYTE(U8(0x0f))
	BYTE(U8(0xdb))
	BYTE(U8(0x04))
}

// PALIGNR $4, X15, X15
func shiftD3Right() {
	BYTE(U8(0x66))
	BYTE(U8(0x45))
	BYTE(U8(0x0f))
	BYTE(U8(0x3a))
	BYTE(U8(0x0f))
	BYTE(U8(0xff))
	BYTE(U8(0x04))
}

// ##~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~SOME  MACROS~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~##

// Hack: ROL must be a #define macro as it is referenced by other macros
func defineROL() {
	definition :=
		`#define ROL(N, R, T) \
		MOVO R, T; \
		PSLLL $(N), T; \
		PSRLL $(32-(N)), R; \
		PXOR T, R`
	Comment("ROL rotates the uint32s in register R left by N bits, using temporary T.")
	Instruction(&ir.Instruction{Opcode: definition})
}

// ROL rotates the uint32s in register R left by N bits, using temporary T.
func ROL(N uint64, R, T VecPhysical) {
	// Hack: ROL must be a #define macro as it is referenced by other macros
	Instruction(&ir.Instruction{Opcode: fmt.Sprintf("ROL(%s, %s, %s)", I8(N).Asm(), R.Asm(), T.Asm())})
}

// Hack to get Avo to generate an #ifdef
//
// ROL16(R, T) definition depends on a compiler flag that specifies amd64 architectural level.
func defineROL16() {
	definition :=
		`#ifdef GOAMD64_v2
		#define ROL16(R, T) PSHUFB ·rol16<>(SB), R
	#else
		#define ROL16(R, T) ROL(16, R, T)
	#endif`

	Comment("ROL16 rotates the uint32s in register R left by 16, using temporary T if needed.")
	Instruction(&ir.Instruction{Opcode: definition})
}

// Hack to emit macro call
//
// ROL16 rotates the uint32s in register R left by 16, using temporary T if needed.
func ROL16(R, T VecPhysical) {
	Instruction(&ir.Instruction{Opcode: fmt.Sprintf("ROL16(%s, %s)", R.Asm(), T.Asm())})
}

// Hack to get Avo to generate an #ifdef
//
// ROL8(R, T) definition depends on a compiler flag that specifies amd64 architectural level.
func defineROL8() {
	definition :=
		`#ifdef GOAMD64_v2
		#define ROL8(R, T) PSHUFB ·rol8<>(SB), R
	#else
		#define ROL8(R, T) ROL(8, R, T)
	#endif`

	Comment("ROL8 rotates the uint32s in register R left by 8, using temporary T if needed.")
	Instruction(&ir.Instruction{Opcode: definition})
}

// Hack to emit macro call
//
// ROL8 rotates the uint32s in register R left by 8, using temporary T if needed.
func ROL8(R, T VecPhysical) {
	Instruction(&ir.Instruction{Opcode: fmt.Sprintf("ROL8(%s, %s)", R.Asm(), T.Asm())})
}

func chachaQR(A, B, C, D, T VecPhysical) {
	PADDD(B, A)
	PXOR(A, D)
	ROL16(D, T)
	PADDD(D, C)
	PXOR(C, B)
	MOVO(B, T)
	PSLLL(Imm(12), T)
	PSRLL(Imm(20), B)
	PXOR(T, B)
	PADDD(B, A)
	PXOR(A, D)
	ROL8(D, T)
	PADDD(D, C)
	PXOR(C, B)
	MOVO(B, T)
	PSLLL(Imm(7), T)
	PSRLL(Imm(25), B)
	PXOR(T, B)
}

func chachaQR_AVX2(A, B, C, D, T VecPhysical) {
	VPADDD(B, A, A)
	VPXOR(A, D, D)
	rol16 := rol16_DATA()
	VPSHUFB(rol16, D, D)
	VPADDD(D, C, C)
	VPXOR(C, B, B)
	VPSLLD(Imm(12), B, T)
	VPSRLD(Imm(20), B, B)
	VPXOR(T, B, B)
	VPADDD(B, A, A)
	VPXOR(A, D, D)
	rol8 := rol8_DATA()
	VPSHUFB(rol8, D, D)
	VPADDD(D, C, C)
	VPXOR(C, B, B)
	VPSLLD(Imm(7), B, T)
	VPSRLD(Imm(25), B, B)
	VPXOR(T, B, B)
}

func polyAdd(S Mem) {
	ADDQ(S, acc0)
	ADCQ(S.Offset(8), acc1)
	ADCQ(Imm(1), acc2)
}

func polyMulStage1() {
	MOVQ(Mem{Base: BP}.Offset(0*8), RAX)
	MOVQ(RAX, t2)
	MULQ(acc0)
	MOVQ(RAX, t0)
	MOVQ(RDX, t1)
	MOVQ(Mem{Base: BP}.Offset(0*8), RAX)
	MULQ(acc1)
	IMULQ(acc2, t2)
	ADDQ(RAX, t1)
	ADCQ(RDX, t2)
}

func polyMulStage2() {
	MOVQ(Mem{Base: BP}.Offset(1*8), RAX)
	MOVQ(RAX, t3)
	MULQ(acc0)
	ADDQ(RAX, t1)
	ADCQ(Imm(0), RDX)
	MOVQ(RDX, acc0)
	MOVQ(Mem{Base: BP}.Offset(1*8), RAX)
	MULQ(acc1)
	ADDQ(RAX, t2)
	ADCQ(Imm(0), RDX)
}

func polyMulStage3() {
	IMULQ(acc2, t3)
	ADDQ(acc0, t2)
	ADCQ(RDX, t3)
}

func polyMulReduceStage() {
	MOVQ(t0, acc0)
	MOVQ(t1, acc1)
	MOVQ(t2, acc2)
	ANDQ(Imm(3), acc2)
	MOVQ(t2, t0)
	ANDQ(I8(-4), t0)
	MOVQ(t3, t1)
	SHRQ(Imm(2), t3, t2)
	SHRQ(Imm(2), t3)
	ADDQ(t0, acc0)
	ADCQ(t1, acc1)
	ADCQ(Imm(0), acc2)
	ADDQ(t2, acc0)
	ADCQ(t3, acc1)
	ADCQ(Imm(0), acc2)
}

func polyMulStage1_AVX2() {
	MOVQ(Mem{Base: BP}.Offset(0*8), RDX)
	MOVQ(RDX, t2)
	MULXQ(acc0, t0, t1)
	IMULQ(acc2, t2)
	MULXQ(acc1, RAX, RDX)
	ADDQ(RAX, t1)
	ADCQ(RDX, t2)
}

func polyMulStage2_AVX2() {
	MOVQ(Mem{Base: BP}.Offset(1*8), RDX)
	MULXQ(acc0, acc0, RAX)
	ADDQ(acc0, t1)
	MULXQ(acc1, acc1, t3)
	ADCQ(acc1, t2)
	ADCQ(Imm(0), t3)
}

func polyMulStage3_AVX2() {
	IMULQ(acc2, RDX)
	ADDQ(RAX, t2)
	ADCQ(RDX, t3)
}

func polyMul() {
	polyMulStage1()
	polyMulStage2()
	polyMulStage3()
	polyMulReduceStage()
}

func polyMulAVX2() {
	polyMulStage1_AVX2()
	polyMulStage2_AVX2()
	polyMulStage3_AVX2()
	polyMulReduceStage()
}

// ----------------------------------------------------------------------------
// ----------------------------------------------------------------------------

func polyHashADInternal() {
	Function("polyHashADInternal<>")
	Attributes(NOSPLIT)
	AllocLocal(0)

	Comment("Hack: Must declare #define macros inside of a function due to Avo constraints")
	defineROL()
	defineROL8()
	defineROL16()

	// adp points to beginning of additional data
	// itr2 holds ad length
	XORQ(acc0, acc0)
	XORQ(acc1, acc1)
	XORQ(acc2, acc2)
	CMPQ(itr2, Imm(13))
	JNE(LabelRef("hashADLoop"))

	openFastTLSAD()
	hashADLoop()
	hashADTail()
	hashADTailLoop()
	hashADTailFinish()
	hashADDone()
}

// Special treatment for the TLS case of 13 bytes
func openFastTLSAD() {
	Label("openFastTLSAD")
	MOVQ(Mem{Base: adp}, acc0)
	MOVQ(Mem{Base: adp}.Offset(5), acc1)
	SHRQ(Imm(24), acc1)
	MOVQ(U32(1), acc2)
	polyMul()
	RET()
}

// Hash in 16 byte chunks
func hashADLoop() {
	Label("hashADLoop")
	Comment("Hash in 16 byte chunks")
	CMPQ(itr2, Imm(16))
	JB(LabelRef("hashADTail"))
	polyAdd(Mem{Base: adp}.Offset(0))
	LEAQ(Mem{Base: adp}.Offset(1*16), adp)
	SUBQ(Imm(16), itr2)
	polyMul()
	JMP(LabelRef("hashADLoop"))
}

func hashADTail() {
	Label("hashADTail")
	CMPQ(itr2, Imm(0))
	JE(LabelRef("hashADDone"))

	Comment("Hash last < 16 byte tail")
	XORQ(t0, t0)
	XORQ(t1, t1)
	XORQ(t2, t2)
	ADDQ(itr2, adp)
}

func hashADTailLoop() {
	Label("hashADTailLoop")
	SHLQ(Imm(8), t0, t1)
	SHLQ(Imm(8), t0)
	// Hack to get Avo to emit:
	// 	MOVB -1(adp), t2
	Instruction(&ir.Instruction{Opcode: "MOVB", Operands: []Op{Mem{Base: adp}.Offset(-1), t2}})
	XORQ(t2, t0)
	DECQ(adp)
	DECQ(itr2)
	JNE(LabelRef("hashADTailLoop"))
}

func hashADTailFinish() {
	ADDQ(t0, acc0)
	ADCQ(t1, acc1)
	ADCQ(Imm(1), acc2)
	polyMul()
}

// Finished AD
func hashADDone() {
	Label("hashADDone")
	RET()
}

// ----------------------------------------------------------------------------
// ----------------------------------------------------------------------------

// Implements the following function fignature:
//
//	func chacha20Poly1305Open(dst []byte, key []uint32, src []byte, ad []byte) bool
func chacha20Poly1305Open() {
	Implement("chacha20Poly1305Open")
	Attributes(0)
	AllocLocal(288)

	Comment("For aligned stack access")
	MOVQ(RSP, RBP)
	ADDQ(Imm(32), RBP)
	ANDQ(I8(-32), RBP)

	Load(Param("dst").Base(), oup)
	Load(Param("key").Base(), keyp)
	Load(Param("src").Base(), inp)
	Load(Param("src").Len(), inl)
	Load(Param("ad").Base(), adp)

	Comment("Check for AVX2 support")
	CMPB(Mem{Symbol: Symbol{Name: ThatPeskyUnicodeDot + "useAVX2"}, Base: StaticBase}, Imm(1))
	JE(LabelRef("chacha20Poly1305Open_AVX2"))

	Comment("Special optimization, for very short buffers")
	CMPQ(inl, Imm(128))
	JBE(LabelRef("openSSE128")) // About 16% faster

	Comment("For long buffers, prepare the poly key first")
	chacha20Constants := chacha20Constants_DATA()
	MOVOU(chacha20Constants, A0)
	MOVOU(Mem{Base: keyp}.Offset(1*16), B0)
	MOVOU(Mem{Base: keyp}.Offset(2*16), C0)
	MOVOU(Mem{Base: keyp}.Offset(3*16), D0)
	MOVO(D0, T1)

	Comment("Store state on stack for future use")
	MOVO(B0, state1Store)
	MOVO(C0, state2Store)
	MOVO(D0, ctr3Store)
	MOVQ(U32(10), itr2)

	openSSEPreparePolyKey()
	openSSEMainLoop()
	openSSEInternalLoop()
	openSSEMainLoopDone()
	openSSEFinalize()

	// ----------------------------------------------------------------------------
	// Special optimization for buffers smaller than 129 bytes
	openSSE128()
	openSSE128InnerCipherLoop()
	openSSE128Open()
	openSSETail16()
	openSSETail16Store()

	// ----------------------------------------------------------------------------
	// Special optimization for the last 64 bytes of ciphertext
	openSSETail64()
	openSSETail64LoopA()
	openSSETail64LoopB()
	openSSETail64DecLoop()
	openSSETail64DecLoopDone()

	// ----------------------------------------------------------------------------
	// Special optimization for the last 128 bytes of ciphertext
	openSSETail128()
	openSSETail128LoopA()
	openSSETail128LoopB()

	// ----------------------------------------------------------------------------
	// Special optimization for the last 192 bytes of ciphertext
	openSSETail192()
	openSSLTail192LoopA()
	openSSLTail192LoopB()
	openSSLTail192Store()

	// ----------------------------------------------------------------------------
	// Special optimization for the last 256 bytes of ciphertext
	openSSETail256()
	openSSETail256Loop()
	openSSETail256HashLoop()

	// ----------------------------------------------------------------------------
	// ------------------------- AVX2 Code ----------------------------------------
	chacha20Poly1305Open_AVX2()
	openAVX2PreparePolyKey()
	openAVX2InitialHash64()
	openAVX2MainLoop()
	openAVX2InternalLoop()
	openAVX2MainLoopDone()

	// ----------------------------------------------------------------------------
	// Special optimization for buffers smaller than 193 bytes
	openAVX2192()
	openAVX2192InnerCipherLoop()
	openAVX2ShortOpen()
	openAVX2ShortOpenLoop()
	openAVX2ShortTail32()
	openAVX2ShortDone()

	// ----------------------------------------------------------------------------
	// Special optimization for buffers smaller than 321 bytes
	openAVX2320()
	openAVX2320InnerCipherLoop()

	// ----------------------------------------------------------------------------
	// Special optimization for the last 128 bytes of ciphertext
	openAVX2Tail128()
	openAVX2Tail128LoopA()
	openAVX2Tail128LoopB()
	openAVX2TailLoop()
	openAVX2Tail()
	openAVX2TailDone()

	// ----------------------------------------------------------------------------
	// Special optimization for the last 256 bytes of ciphertext
	openAVX2Tail256()
	openAVX2Tail256LoopA()
	openAVX2Tail256LoopB()
	openAVX2Tail256Hash()
	openAVX2Tail256HashEnd()

	// ----------------------------------------------------------------------------
	// Special optimization for the last 384 bytes of ciphertext
	openAVX2Tail384()
	openAVX2Tail384LoopB()
	openAVX2Tail384LoopA()
	openAVX2Tail384Hash()
	openAVX2Tail384HashEnd()

	// ----------------------------------------------------------------------------
	// Special optimization for the last 512 bytes of ciphertext
	openAVX2Tail512()
	openAVX2Tail512LoopB()
	openAVX2Tail512LoopA()
	openAVX2Tail512HashLoop()
	openAVX2Tail512HashEnd()
}

func openSSEPreparePolyKey() {
	Label("openSSEPreparePolyKey")
	chachaQR(A0, B0, C0, D0, T0)
	shiftB0Left()
	shiftC0Left()
	shiftD0Left()
	chachaQR(A0, B0, C0, D0, T0)
	shiftB0Right()
	shiftC0Right()
	shiftD0Right()
	DECQ(itr2)
	JNE(LabelRef("openSSEPreparePolyKey"))

	Comment("A0|B0 hold the Poly1305 32-byte key, C0,D0 can be discarded")
	chacha20Constants := chacha20Constants_DATA()
	PADDL(chacha20Constants, A0)
	PADDL(state1Store, B0)

	Comment("Clamp and store the key")
	polyClampMask := polyClampMask_DATA()
	PAND(polyClampMask, A0)
	MOVO(A0, rStore)
	MOVO(B0, sStore)

	Comment("Hash AAD")
	Load(Param("ad").Len(), itr2)
	CALL(LabelRef("polyHashADInternal<>(SB)"))
}

func openSSEMainLoop() {
	Label("openSSEMainLoop")
	CMPQ(inl, U32(256))
	JB(LabelRef("openSSEMainLoopDone"))

	chacha20Constants := chacha20Constants_DATA()
	sseIncMask := sseIncMask_DATA()

	Comment("Load state, increment counter blocks")
	MOVO(chacha20Constants, A0)
	MOVO(state1Store, B0)
	MOVO(state2Store, C0)
	MOVO(ctr3Store, D0)
	PADDL(sseIncMask, D0)
	MOVO(A0, A1)
	MOVO(B0, B1)
	MOVO(C0, C1)
	MOVO(D0, D1)
	PADDL(sseIncMask, D1)
	MOVO(A1, A2)
	MOVO(B1, B2)
	MOVO(C1, C2)
	MOVO(D1, D2)
	PADDL(sseIncMask, D2)
	MOVO(A2, A3)
	MOVO(B2, B3)
	MOVO(C2, C3)
	MOVO(D2, D3)
	PADDL(sseIncMask, D3)

	Comment("Store counters")
	MOVO(D0, ctr0Store)
	MOVO(D1, ctr1Store)
	MOVO(D2, ctr2Store)
	MOVO(D3, ctr3Store)

	Comment("There are 10 ChaCha20 iterations of 2QR each, so for 6 iterations we hash")
	Comment("2 blocks, and for the remaining 4 only 1 block - for a total of 16")
	MOVQ(U32(4), itr1)
	MOVQ(inp, itr2)
}

func openSSEInternalLoop() {
	Label("openSSEInternalLoop")
	MOVO(C3, tmpStore)
	chachaQR(A0, B0, C0, D0, C3)
	chachaQR(A1, B1, C1, D1, C3)
	chachaQR(A2, B2, C2, D2, C3)
	MOVO(tmpStore, C3)
	MOVO(C1, tmpStore)
	chachaQR(A3, B3, C3, D3, C1)
	MOVO(tmpStore, C1)
	polyAdd(Mem{Base: itr2}.Offset(0))
	shiftB0Left()
	shiftB1Left()
	shiftB2Left()
	shiftB3Left()
	shiftC0Left()
	shiftC1Left()
	shiftC2Left()
	shiftC3Left()
	shiftD0Left()
	shiftD1Left()
	shiftD2Left()
	shiftD3Left()
	polyMulStage1()
	polyMulStage2()
	LEAQ(Mem{Base: itr2}.Offset(2*8), itr2)
	MOVO(C3, tmpStore)
	chachaQR(A0, B0, C0, D0, C3)
	chachaQR(A1, B1, C1, D1, C3)
	chachaQR(A2, B2, C2, D2, C3)
	MOVO(tmpStore, C3)
	MOVO(C1, tmpStore)
	polyMulStage3()
	chachaQR(A3, B3, C3, D3, C1)
	MOVO(tmpStore, C1)
	polyMulReduceStage()
	shiftB0Right()
	shiftB1Right()
	shiftB2Right()
	shiftB3Right()
	shiftC0Right()
	shiftC1Right()
	shiftC2Right()
	shiftC3Right()
	shiftD0Right()
	shiftD1Right()
	shiftD2Right()
	shiftD3Right()
	DECQ(itr1)
	JGE(LabelRef("openSSEInternalLoop"))

	polyAdd(Mem{Base: itr2}.Offset(0))
	polyMul()
	LEAQ(Mem{Base: itr2}.Offset(2*8), itr2)

	CMPQ(itr1, I8(-6))
	JG(LabelRef("openSSEInternalLoop"))

	chacha20Constants := chacha20Constants_DATA()
	Comment("Add in the state")
	PADDD(chacha20Constants, A0)
	PADDD(chacha20Constants, A1)
	PADDD(chacha20Constants, A2)
	PADDD(chacha20Constants, A3)
	PADDD(state1Store, B0)
	PADDD(state1Store, B1)
	PADDD(state1Store, B2)
	PADDD(state1Store, B3)
	PADDD(state2Store, C0)
	PADDD(state2Store, C1)
	PADDD(state2Store, C2)
	PADDD(state2Store, C3)
	PADDD(ctr0Store, D0)
	PADDD(ctr1Store, D1)
	PADDD(ctr2Store, D2)
	PADDD(ctr3Store, D3)

	Comment("Load - xor - store")
	MOVO(D3, tmpStore)
	MOVOU(Mem{Base: inp}.Offset(0*16), D3)
	PXOR(D3, A0)
	MOVOU(A0, Mem{Base: oup}.Offset(0*16))
	MOVOU(Mem{Base: inp}.Offset(1*16), D3)
	PXOR(D3, B0)
	MOVOU(B0, Mem{Base: oup}.Offset(1*16))
	MOVOU(Mem{Base: inp}.Offset(2*16), D3)
	PXOR(D3, C0)
	MOVOU(C0, Mem{Base: oup}.Offset(2*16))
	MOVOU(Mem{Base: inp}.Offset(3*16), D3)
	PXOR(D3, D0)
	MOVOU(D0, Mem{Base: oup}.Offset(3*16))
	MOVOU(Mem{Base: inp}.Offset(4*16), D0)
	PXOR(D0, A1)
	MOVOU(A1, Mem{Base: oup}.Offset(4*16))
	MOVOU(Mem{Base: inp}.Offset(5*16), D0)
	PXOR(D0, B1)
	MOVOU(B1, Mem{Base: oup}.Offset(5*16))
	MOVOU(Mem{Base: inp}.Offset(6*16), D0)
	PXOR(D0, C1)
	MOVOU(C1, Mem{Base: oup}.Offset(6*16))
	MOVOU(Mem{Base: inp}.Offset(7*16), D0)
	PXOR(D0, D1)
	MOVOU(D1, Mem{Base: oup}.Offset(7*16))
	MOVOU(Mem{Base: inp}.Offset(8*16), D0)
	PXOR(D0, A2)
	MOVOU(A2, Mem{Base: oup}.Offset(8*16))
	MOVOU(Mem{Base: inp}.Offset(9*16), D0)
	PXOR(D0, B2)
	MOVOU(B2, Mem{Base: oup}.Offset(9*16))
	MOVOU(Mem{Base: inp}.Offset(10*16), D0)
	PXOR(D0, C2)
	MOVOU(C2, Mem{Base: oup}.Offset(10*16))
	MOVOU(Mem{Base: inp}.Offset(11*16), D0)
	PXOR(D0, D2)
	MOVOU(D2, Mem{Base: oup}.Offset(11*16))
	MOVOU(Mem{Base: inp}.Offset(12*16), D0)
	PXOR(D0, A3)
	MOVOU(A3, Mem{Base: oup}.Offset(12*16))
	MOVOU(Mem{Base: inp}.Offset(13*16), D0)
	PXOR(D0, B3)
	MOVOU(B3, Mem{Base: oup}.Offset(13*16))
	MOVOU(Mem{Base: inp}.Offset(14*16), D0)
	PXOR(D0, C3)
	MOVOU(C3, Mem{Base: oup}.Offset(14*16))
	MOVOU(Mem{Base: inp}.Offset(15*16), D0)
	PXOR(tmpStore, D0)
	MOVOU(D0, Mem{Base: oup}.Offset(15*16))
	LEAQ(Mem{Base: inp}.Offset(256), inp)
	LEAQ(Mem{Base: oup}.Offset(256), oup)
	SUBQ(U32(256), inl)
	JMP(LabelRef("openSSEMainLoop"))
}

func openSSEMainLoopDone() {
	Label("openSSEMainLoopDone")
	Comment("Handle the various tail sizes efficiently")
	TESTQ(inl, inl)
	JE(LabelRef("openSSEFinalize"))
	CMPQ(inl, Imm(64))
	JBE(LabelRef("openSSETail64"))
	CMPQ(inl, Imm(128))
	JBE(LabelRef("openSSETail128"))
	CMPQ(inl, Imm(192))
	JBE(LabelRef("openSSETail192"))
	JMP(LabelRef("openSSETail256"))
}

func openSSEFinalize() {
	Label("openSSEFinalize")
	Comment("Hash in the PT, AAD lengths")
	ADDQ(NewParamAddr("ad_len", 80), acc0)
	ADCQ(NewParamAddr("src_len", 56), acc1)
	ADCQ(Imm(1), acc2)
	polyMul()

	Comment("Final reduce")
	MOVQ(acc0, t0)
	MOVQ(acc1, t1)
	MOVQ(acc2, t2)
	SUBQ(I8(-5), acc0)
	SBBQ(I8(-1), acc1)
	SBBQ(Imm(3), acc2)
	CMOVQCS(t0, acc0)
	CMOVQCS(t1, acc1)
	CMOVQCS(t2, acc2)

	Comment("Add in the \"s\" part of the key")
	ADDQ(sStore.Offset(0), acc0)
	ADCQ(sStore.Offset(8), acc1)

	Comment("Finally, constant time compare to the tag at the end of the message")
	XORQ(RAX, RAX)
	MOVQ(U32(1), RDX)
	XORQ(Mem{Base: inp}.Offset(0*8), acc0)
	XORQ(Mem{Base: inp}.Offset(1*8), acc1)
	ORQ(acc1, acc0)
	CMOVQEQ(RDX, RAX)

	Comment("Return true iff tags are equal")
	// Hack to get Avo to emit:
	// 	MOVB AX, ret+96(FP)
	Instruction(&ir.Instruction{Opcode: "MOVB", Operands: []Op{AX, NewParamAddr("ret", 96)}})
	RET()
}

// ----------------------------------------------------------------------------
// Special optimization for buffers smaller than 129 bytes

// For up to 128 bytes of ciphertext and 64 bytes for the poly key, we require to process three blocks
func openSSE128() {
	Label("openSSE128")

	chacha20Constants := chacha20Constants_DATA()
	sseIncMask := sseIncMask_DATA()

	MOVOU(chacha20Constants, A0)
	MOVOU(Mem{Base: keyp}.Offset(1*16), B0)
	MOVOU(Mem{Base: keyp}.Offset(2*16), C0)
	MOVOU(Mem{Base: keyp}.Offset(3*16), D0)
	MOVO(A0, A1)
	MOVO(B0, B1)
	MOVO(C0, C1)
	MOVO(D0, D1)
	PADDL(sseIncMask, D1)
	MOVO(A1, A2)
	MOVO(B1, B2)
	MOVO(C1, C2)
	MOVO(D1, D2)
	PADDL(sseIncMask, D2)
	MOVO(B0, T1)
	MOVO(C0, T2)
	MOVO(D1, T3)
	MOVQ(U32(10), itr2)
}

func openSSE128InnerCipherLoop() {
	Label("openSSE128InnerCipherLoop")
	chachaQR(A0, B0, C0, D0, T0)
	chachaQR(A1, B1, C1, D1, T0)
	chachaQR(A2, B2, C2, D2, T0)
	shiftB0Left()
	shiftB1Left()
	shiftB2Left()
	shiftC0Left()
	shiftC1Left()
	shiftC2Left()
	shiftD0Left()
	shiftD1Left()
	shiftD2Left()
	chachaQR(A0, B0, C0, D0, T0)
	chachaQR(A1, B1, C1, D1, T0)
	chachaQR(A2, B2, C2, D2, T0)
	shiftB0Right()
	shiftB1Right()
	shiftB2Right()
	shiftC0Right()
	shiftC1Right()
	shiftC2Right()
	shiftD0Right()
	shiftD1Right()
	shiftD2Right()
	DECQ(itr2)
	JNE(LabelRef("openSSE128InnerCipherLoop"))

	Comment("A0|B0 hold the Poly1305 32-byte key, C0,D0 can be discarded")

	chacha20Constants := chacha20Constants_DATA()
	PADDL(chacha20Constants, A0)
	PADDL(chacha20Constants, A1)
	PADDL(chacha20Constants, A2)
	PADDL(T1, B0)
	PADDL(T1, B1)
	PADDL(T1, B2)
	PADDL(T2, C1)
	PADDL(T2, C2)
	PADDL(T3, D1)
	sseIncMask := sseIncMask_DATA()
	PADDL(sseIncMask, T3)
	PADDL(T3, D2)

	Comment("Clamp and store the key")
	polyClampMask := polyClampMask_DATA()
	PAND(polyClampMask, A0)
	MOVOU(A0, rStore)
	MOVOU(B0, sStore)

	Comment("Hash")
	Load(Param("ad").Len(), itr2)
	CALL(LabelRef("polyHashADInternal<>(SB)"))
}

func openSSE128Open() {
	Label("openSSE128Open")
	CMPQ(inl, Imm(16))
	JB(LabelRef("openSSETail16"))
	SUBQ(Imm(16), inl)

	Comment("Load for hashing")
	polyAdd(Mem{Base: inp}.Offset(0))

	Comment("Load for decryption")
	MOVOU(Mem{Base: inp}, T0)
	PXOR(T0, A1)
	MOVOU(A1, Mem{Base: oup})
	LEAQ(Mem{Base: inp}.Offset(1*16), inp)
	LEAQ(Mem{Base: oup}.Offset(1*16), oup)
	polyMul()

	Comment("Shift the stream \"left\"")
	MOVO(B1, A1)
	MOVO(C1, B1)
	MOVO(D1, C1)
	MOVO(A2, D1)
	MOVO(B2, A2)
	MOVO(C2, B2)
	MOVO(D2, C2)
	JMP(LabelRef("openSSE128Open"))
}

func openSSETail16() {
	Label("openSSETail16")
	TESTQ(inl, inl)
	JE(LabelRef("openSSEFinalize"))

	Comment("We can safely load the CT from the end, because it is padded with the MAC")
	MOVQ(inl, itr2)
	SHLQ(Imm(4), itr2)
	andMask := andMask_DATA()
	LEAQ(andMask, t0)
	MOVOU(Mem{Base: inp}, T0)
	ADDQ(inl, inp)
	PAND(Mem{Base: t0, Index: itr2, Scale: 1}.Offset(-16), T0)
	MOVO(T0, tmpStore.Offset(0))
	MOVQ(T0, t0)
	MOVQ(tmpStore.Offset(8), t1)
	PXOR(A1, T0)
}

func openSSETail16Store() {
	Comment("We can only store one byte at a time, since plaintext can be shorter than 16 bytes")
	Label("openSSETail16Store")
	MOVQ(T0, t3)
	// Hack to get Avo to emit:
	// 	MOVB t3, (oup)
	Instruction(&ir.Instruction{Opcode: "MOVB", Operands: []Op{t3, Mem{Base: oup}}})
	PSRLDQ(Imm(1), T0)
	INCQ(oup)
	DECQ(inl)
	JNE(LabelRef("openSSETail16Store"))
	ADDQ(t0, acc0)
	ADCQ(t1, acc1)
	ADCQ(Imm(1), acc2)
	polyMul()
	JMP(LabelRef("openSSEFinalize"))
}

// ----------------------------------------------------------------------------
// Special optimization for the last 64 bytes of ciphertext

// Need to decrypt up to 64 bytes - prepare single block
func openSSETail64() {
	Label("openSSETail64")
	chacha20Constants := chacha20Constants_DATA()
	MOVO(chacha20Constants, A0)
	MOVO(state1Store, B0)
	MOVO(state2Store, C0)
	MOVO(ctr3Store, D0)
	sseIncMask := sseIncMask_DATA()
	PADDL(sseIncMask, D0)
	MOVO(D0, ctr0Store)
	XORQ(itr2, itr2)
	MOVQ(inl, itr1)
	CMPQ(itr1, Imm(16))
	JB(LabelRef("openSSETail64LoopB"))
}

// Perform ChaCha rounds, while hashing the remaining input
func openSSETail64LoopA() {
	Label("openSSETail64LoopA")
	polyAdd(Mem{Base: inp, Index: itr2, Scale: 1}.Offset(0))
	polyMul()
	SUBQ(Imm(16), itr1)
}

func openSSETail64LoopB() {
	Label("openSSETail64LoopB")
	ADDQ(Imm(16), itr2)
	chachaQR(A0, B0, C0, D0, T0)
	shiftB0Left()
	shiftC0Left()
	shiftD0Left()
	chachaQR(A0, B0, C0, D0, T0)
	shiftB0Right()
	shiftC0Right()
	shiftD0Right()

	CMPQ(itr1, Imm(16))
	JAE(LabelRef("openSSETail64LoopA"))

	CMPQ(itr2, Imm(160))
	JNE(LabelRef("openSSETail64LoopB"))

	chacha20Constants := chacha20Constants_DATA()
	PADDL(chacha20Constants, A0)
	PADDL(state1Store, B0)
	PADDL(state2Store, C0)
	PADDL(ctr0Store, D0)
}

func openSSETail64DecLoop() {
	Label("openSSETail64DecLoop")
	CMPQ(inl, Imm(16))
	JB(LabelRef("openSSETail64DecLoopDone"))
	SUBQ(Imm(16), inl)
	MOVOU(Mem{Base: inp}, T0)
	PXOR(T0, A0)
	MOVOU(A0, Mem{Base: oup})
	LEAQ(Mem{Base: inp}.Offset(16), inp)
	LEAQ(Mem{Base: oup}.Offset(16), oup)
	MOVO(B0, A0)
	MOVO(C0, B0)
	MOVO(D0, C0)
	JMP(LabelRef("openSSETail64DecLoop"))
}

func openSSETail64DecLoopDone() {
	Label("openSSETail64DecLoopDone")
	MOVO(A0, A1)
	JMP(LabelRef("openSSETail16"))
}

// ----------------------------------------------------------------------------
// Special optimization for the last 128 bytes of ciphertext

// Need to decrypt up to 128 bytes - prepare two blocks
func openSSETail128() {
	Label("openSSETail128")
	chacha20Constants := chacha20Constants_DATA()
	MOVO(chacha20Constants, A1)
	MOVO(state1Store, B1)
	MOVO(state2Store, C1)
	MOVO(ctr3Store, D1)
	sseIncMask := sseIncMask_DATA()
	PADDL(sseIncMask, D1)
	MOVO(D1, ctr0Store)
	MOVO(A1, A0)
	MOVO(B1, B0)
	MOVO(C1, C0)
	MOVO(D1, D0)
	PADDL(sseIncMask, D0)
	MOVO(D0, ctr1Store)
	XORQ(itr2, itr2)
	MOVQ(inl, itr1)
	ANDQ(I8(-16), itr1)
}

// Perform ChaCha rounds, while hashing the remaining input
func openSSETail128LoopA() {
	Label("openSSETail128LoopA")
	polyAdd(Mem{Base: inp, Index: itr2, Scale: 1}.Offset(0))
	polyMul()
}

func openSSETail128LoopB() {
	Label("openSSETail128LoopB")
	ADDQ(Imm(16), itr2)
	chachaQR(A0, B0, C0, D0, T0)
	chachaQR(A1, B1, C1, D1, T0)
	shiftB0Left()
	shiftC0Left()
	shiftD0Left()
	shiftB1Left()
	shiftC1Left()
	shiftD1Left()
	chachaQR(A0, B0, C0, D0, T0)
	chachaQR(A1, B1, C1, D1, T0)
	shiftB0Right()
	shiftC0Right()
	shiftD0Right()
	shiftB1Right()
	shiftC1Right()
	shiftD1Right()

	CMPQ(itr2, itr1)
	JB(LabelRef("openSSETail128LoopA"))

	CMPQ(itr2, Imm(160))
	JNE(LabelRef("openSSETail128LoopB"))

	chacha20Constants := chacha20Constants_DATA()
	PADDL(chacha20Constants, A0)
	PADDL(chacha20Constants, A1)
	PADDL(state1Store, B0)
	PADDL(state1Store, B1)
	PADDL(state2Store, C0)
	PADDL(state2Store, C1)
	PADDL(ctr1Store, D0)
	PADDL(ctr0Store, D1)

	MOVOU(Mem{Base: inp}.Offset(0*16), T0)
	MOVOU(Mem{Base: inp}.Offset(1*16), T1)
	MOVOU(Mem{Base: inp}.Offset(2*16), T2)
	MOVOU(Mem{Base: inp}.Offset(3*16), T3)
	PXOR(T0, A1)
	PXOR(T1, B1)
	PXOR(T2, C1)
	PXOR(T3, D1)
	MOVOU(A1, Mem{Base: oup}.Offset(0*16))
	MOVOU(B1, Mem{Base: oup}.Offset(1*16))
	MOVOU(C1, Mem{Base: oup}.Offset(2*16))
	MOVOU(D1, Mem{Base: oup}.Offset(3*16))

	SUBQ(Imm(64), inl)
	LEAQ(Mem{Base: inp}.Offset(64), inp)
	LEAQ(Mem{Base: oup}.Offset(64), oup)
	JMP(LabelRef("openSSETail64DecLoop"))
}

// ----------------------------------------------------------------------------
// Special optimization for the last 192 bytes of ciphertext

// Need to decrypt up to 192 bytes - prepare three blocks
func openSSETail192() {
	Label("openSSETail192")
	chacha20Constants := chacha20Constants_DATA()
	MOVO(chacha20Constants, A2)
	MOVO(state1Store, B2)
	MOVO(state2Store, C2)
	MOVO(ctr3Store, D2)
	sseIncMask := sseIncMask_DATA()
	PADDL(sseIncMask, D2)
	MOVO(D2, ctr0Store)
	MOVO(A2, A1)
	MOVO(B2, B1)
	MOVO(C2, C1)
	MOVO(D2, D1)
	PADDL(sseIncMask, D1)
	MOVO(D1, ctr1Store)
	MOVO(A1, A0)
	MOVO(B1, B0)
	MOVO(C1, C0)
	MOVO(D1, D0)
	PADDL(sseIncMask, D0)
	MOVO(D0, ctr2Store)

	MOVQ(inl, itr1)
	MOVQ(U32(160), itr2)
	CMPQ(itr1, Imm(160))
	CMOVQGT(itr2, itr1)
	ANDQ(I8(-16), itr1)
	XORQ(itr2, itr2)
}

// Perform ChaCha rounds, while hashing the remaining input
func openSSLTail192LoopA() {
	Label("openSSLTail192LoopA")
	polyAdd(Mem{Base: inp, Index: itr2, Scale: 1}.Offset(0))
	polyMul()
}

func openSSLTail192LoopB() {
	Label("openSSLTail192LoopB")
	ADDQ(Imm(16), itr2)
	chachaQR(A0, B0, C0, D0, T0)
	chachaQR(A1, B1, C1, D1, T0)
	chachaQR(A2, B2, C2, D2, T0)
	shiftB0Left()
	shiftC0Left()
	shiftD0Left()
	shiftB1Left()
	shiftC1Left()
	shiftD1Left()
	shiftB2Left()
	shiftC2Left()
	shiftD2Left()

	chachaQR(A0, B0, C0, D0, T0)
	chachaQR(A1, B1, C1, D1, T0)
	chachaQR(A2, B2, C2, D2, T0)
	shiftB0Right()
	shiftC0Right()
	shiftD0Right()
	shiftB1Right()
	shiftC1Right()
	shiftD1Right()
	shiftB2Right()
	shiftC2Right()
	shiftD2Right()

	CMPQ(itr2, itr1)
	JB(LabelRef("openSSLTail192LoopA"))

	CMPQ(itr2, Imm(160))
	JNE(LabelRef("openSSLTail192LoopB"))

	CMPQ(inl, Imm(176))
	JB(LabelRef("openSSLTail192Store"))

	polyAdd(Mem{Base: inp}.Offset(160))
	polyMul()

	CMPQ(inl, Imm(192))
	JB(LabelRef("openSSLTail192Store"))

	polyAdd(Mem{Base: inp}.Offset(176))
	polyMul()
}

func openSSLTail192Store() {
	Label("openSSLTail192Store")
	chacha20Constants := chacha20Constants_DATA()
	PADDL(chacha20Constants, A0)
	PADDL(chacha20Constants, A1)
	PADDL(chacha20Constants, A2)
	PADDL(state1Store, B0)
	PADDL(state1Store, B1)
	PADDL(state1Store, B2)
	PADDL(state2Store, C0)
	PADDL(state2Store, C1)
	PADDL(state2Store, C2)
	PADDL(ctr2Store, D0)
	PADDL(ctr1Store, D1)
	PADDL(ctr0Store, D2)

	MOVOU(Mem{Base: inp}.Offset(0*16), T0)
	MOVOU(Mem{Base: inp}.Offset(1*16), T1)
	MOVOU(Mem{Base: inp}.Offset(2*16), T2)
	MOVOU(Mem{Base: inp}.Offset(3*16), T3)
	PXOR(T0, A2)
	PXOR(T1, B2)
	PXOR(T2, C2)
	PXOR(T3, D2)
	MOVOU(A2, Mem{Base: oup}.Offset(0*16))
	MOVOU(B2, Mem{Base: oup}.Offset(1*16))
	MOVOU(C2, Mem{Base: oup}.Offset(2*16))
	MOVOU(D2, Mem{Base: oup}.Offset(3*16))

	MOVOU(Mem{Base: inp}.Offset(4*16), T0)
	MOVOU(Mem{Base: inp}.Offset(5*16), T1)
	MOVOU(Mem{Base: inp}.Offset(6*16), T2)
	MOVOU(Mem{Base: inp}.Offset(7*16), T3)
	PXOR(T0, A1)
	PXOR(T1, B1)
	PXOR(T2, C1)
	PXOR(T3, D1)
	MOVOU(A1, Mem{Base: oup}.Offset(4*16))
	MOVOU(B1, Mem{Base: oup}.Offset(5*16))
	MOVOU(C1, Mem{Base: oup}.Offset(6*16))
	MOVOU(D1, Mem{Base: oup}.Offset(7*16))

	SUBQ(Imm(128), inl)
	LEAQ(Mem{Base: inp}.Offset(128), inp)
	LEAQ(Mem{Base: oup}.Offset(128), oup)
	JMP(LabelRef("openSSETail64DecLoop"))
}

// ----------------------------------------------------------------------------
// Special optimization for the last 256 bytes of ciphertext

// Need to decrypt up to 256 bytes - prepare four blocks
func openSSETail256() {
	Label("openSSETail256")
	chacha20Constants := chacha20Constants_DATA()
	MOVO(chacha20Constants, A0)
	MOVO(state1Store, B0)
	MOVO(state2Store, C0)
	MOVO(ctr3Store, D0)
	sseIncMask := sseIncMask_DATA()
	PADDL(sseIncMask, D0)
	MOVO(A0, A1)
	MOVO(B0, B1)
	MOVO(C0, C1)
	MOVO(D0, D1)
	PADDL(sseIncMask, D1)
	MOVO(A1, A2)
	MOVO(B1, B2)
	MOVO(C1, C2)
	MOVO(D1, D2)
	PADDL(sseIncMask, D2)
	MOVO(A2, A3)
	MOVO(B2, B3)
	MOVO(C2, C3)
	MOVO(D2, D3)
	PADDL(sseIncMask, D3)

	Comment("Store counters")
	MOVO(D0, ctr0Store)
	MOVO(D1, ctr1Store)
	MOVO(D2, ctr2Store)
	MOVO(D3, ctr3Store)
	XORQ(itr2, itr2)
}

// This loop inteleaves 8 ChaCha quarter rounds with 1 poly multiplication
func openSSETail256Loop() {
	Label("openSSETail256Loop")
	polyAdd(Mem{Base: inp, Index: itr2, Scale: 1}.Offset(0))
	MOVO(C3, tmpStore)
	chachaQR(A0, B0, C0, D0, C3)
	chachaQR(A1, B1, C1, D1, C3)
	chachaQR(A2, B2, C2, D2, C3)
	MOVO(tmpStore, C3)
	MOVO(C1, tmpStore)
	chachaQR(A3, B3, C3, D3, C1)
	MOVO(tmpStore, C1)
	shiftB0Left()
	shiftB1Left()
	shiftB2Left()
	shiftB3Left()
	shiftC0Left()
	shiftC1Left()
	shiftC2Left()
	shiftC3Left()
	shiftD0Left()
	shiftD1Left()
	shiftD2Left()
	shiftD3Left()
	polyMulStage1()
	polyMulStage2()
	MOVO(C3, tmpStore)
	chachaQR(A0, B0, C0, D0, C3)
	chachaQR(A1, B1, C1, D1, C3)
	chachaQR(A2, B2, C2, D2, C3)
	MOVO(tmpStore, C3)
	MOVO(C1, tmpStore)
	chachaQR(A3, B3, C3, D3, C1)
	MOVO(tmpStore, C1)
	polyMulStage3()
	polyMulReduceStage()
	shiftB0Right()
	shiftB1Right()
	shiftB2Right()
	shiftB3Right()
	shiftC0Right()
	shiftC1Right()
	shiftC2Right()
	shiftC3Right()
	shiftD0Right()
	shiftD1Right()
	shiftD2Right()
	shiftD3Right()
	ADDQ(Imm(2*8), itr2)
	CMPQ(itr2, Imm(160))
	JB(LabelRef("openSSETail256Loop"))
	MOVQ(inl, itr1)
	ANDQ(I8(-16), itr1)
}

func openSSETail256HashLoop() {
	Label("openSSETail256HashLoop")
	polyAdd(Mem{Base: inp, Index: itr2, Scale: 1}.Offset(0))
	polyMul()
	ADDQ(Imm(2*8), itr2)
	CMPQ(itr2, itr1)
	JB(LabelRef("openSSETail256HashLoop"))

	Comment("Add in the state")
	chacha20Constants := chacha20Constants_DATA()
	PADDD(chacha20Constants, A0)
	PADDD(chacha20Constants, A1)
	PADDD(chacha20Constants, A2)
	PADDD(chacha20Constants, A3)
	PADDD(state1Store, B0)
	PADDD(state1Store, B1)
	PADDD(state1Store, B2)
	PADDD(state1Store, B3)
	PADDD(state2Store, C0)
	PADDD(state2Store, C1)
	PADDD(state2Store, C2)
	PADDD(state2Store, C3)
	PADDD(ctr0Store, D0)
	PADDD(ctr1Store, D1)
	PADDD(ctr2Store, D2)
	PADDD(ctr3Store, D3)
	MOVO(D3, tmpStore)

	Comment("Load - xor - store")
	MOVOU(Mem{Base: inp}.Offset(0*16), D3)
	PXOR(D3, A0)
	MOVOU(Mem{Base: inp}.Offset(1*16), D3)
	PXOR(D3, B0)
	MOVOU(Mem{Base: inp}.Offset(2*16), D3)
	PXOR(D3, C0)
	MOVOU(Mem{Base: inp}.Offset(3*16), D3)
	PXOR(D3, D0)
	MOVOU(A0, Mem{Base: oup}.Offset(0*16))
	MOVOU(B0, Mem{Base: oup}.Offset(1*16))
	MOVOU(C0, Mem{Base: oup}.Offset(2*16))
	MOVOU(D0, Mem{Base: oup}.Offset(3*16))
	MOVOU(Mem{Base: inp}.Offset(4*16), A0)
	MOVOU(Mem{Base: inp}.Offset(5*16), B0)
	MOVOU(Mem{Base: inp}.Offset(6*16), C0)
	MOVOU(Mem{Base: inp}.Offset(7*16), D0)
	PXOR(A0, A1)
	PXOR(B0, B1)
	PXOR(C0, C1)
	PXOR(D0, D1)
	MOVOU(A1, Mem{Base: oup}.Offset(4*16))
	MOVOU(B1, Mem{Base: oup}.Offset(5*16))
	MOVOU(C1, Mem{Base: oup}.Offset(6*16))
	MOVOU(D1, Mem{Base: oup}.Offset(7*16))
	MOVOU(Mem{Base: inp}.Offset(8*16), A0)
	MOVOU(Mem{Base: inp}.Offset(9*16), B0)
	MOVOU(Mem{Base: inp}.Offset(10*16), C0)
	MOVOU(Mem{Base: inp}.Offset(11*16), D0)
	PXOR(A0, A2)
	PXOR(B0, B2)
	PXOR(C0, C2)
	PXOR(D0, D2)
	MOVOU(A2, Mem{Base: oup}.Offset(8*16))
	MOVOU(B2, Mem{Base: oup}.Offset(9*16))
	MOVOU(C2, Mem{Base: oup}.Offset(10*16))
	MOVOU(D2, Mem{Base: oup}.Offset(11*16))
	LEAQ(Mem{Base: inp}.Offset(192), inp)
	LEAQ(Mem{Base: oup}.Offset(192), oup)
	SUBQ(Imm(192), inl)
	MOVO(A3, A0)
	MOVO(B3, B0)
	MOVO(C3, C0)
	MOVO(tmpStore, D0)

	JMP(LabelRef("openSSETail64DecLoop"))
}

// Functions to emit AVX instructions via BYTE directive

// broadcasti128 16(r8), ymm14
func VBROADCASTI128_16_R8_YMM14() {
	BYTE(U8(0xc4))
	BYTE(U8(0x42))
	BYTE(U8(0x7d))
	BYTE(U8(0x5a))
	BYTE(U8(0x70))
	BYTE(U8(0x10))
}

// broadcasti128 32(r8), ymm12
func VBROADCASTI128_32_R8_YMM12() {
	BYTE(U8(0xc4))
	BYTE(U8(0x42))
	BYTE(U8(0x7d))
	BYTE(U8(0x5a))
	BYTE(U8(0x60))
	BYTE(U8(0x20))
}

// broadcasti128 48(r8), ymm4
func VBROADCASTI128_48_R8_YMM4() {
	BYTE(U8(0xc4))
	BYTE(U8(0xc2))
	BYTE(U8(0x7d))
	BYTE(U8(0x5a))
	BYTE(U8(0x60))
	BYTE(U8(0x30))
}

// ----------------------------------------------------------------------------
// ------------------------- AVX2 Code ----------------------------------------

func chacha20Poly1305Open_AVX2() {
	Label("chacha20Poly1305Open_AVX2")
	VZEROUPPER()
	chacha20Constants := chacha20Constants_DATA()
	VMOVDQU(chacha20Constants, AA0)
	VBROADCASTI128_16_R8_YMM14()
	VBROADCASTI128_32_R8_YMM12()
	VBROADCASTI128_48_R8_YMM4()
	avx2InitMask := avx2InitMask_DATA()
	VPADDD(avx2InitMask, DD0, DD0)

	Comment("Special optimization, for very short buffers")
	CMPQ(inl, Imm(192))
	JBE(LabelRef("openAVX2192"))
	CMPQ(inl, U32(320))
	JBE(LabelRef("openAVX2320"))

	Comment("For the general key prepare the key first - as a byproduct we have 64 bytes of cipher stream")
	VMOVDQA(BB0, state1StoreAVX2)
	VMOVDQA(CC0, state2StoreAVX2)
	VMOVDQA(DD0, ctr3StoreAVX2)
	MOVQ(U32(10), itr2)
}

func openAVX2PreparePolyKey() {
	Label("openAVX2PreparePolyKey")
	chachaQR_AVX2(AA0, BB0, CC0, DD0, TT0)
	VPALIGNR(Imm(4), BB0, BB0, BB0)
	VPALIGNR(Imm(8), CC0, CC0, CC0)
	VPALIGNR(Imm(12), DD0, DD0, DD0)
	chachaQR_AVX2(AA0, BB0, CC0, DD0, TT0)
	VPALIGNR(Imm(12), BB0, BB0, BB0)
	VPALIGNR(Imm(8), CC0, CC0, CC0)
	VPALIGNR(Imm(4), DD0, DD0, DD0)
	DECQ(itr2)
	JNE(LabelRef("openAVX2PreparePolyKey"))

	chacha20Constants := chacha20Constants_DATA()
	VPADDD(chacha20Constants, AA0, AA0)
	VPADDD(state1StoreAVX2, BB0, BB0)
	VPADDD(state2StoreAVX2, CC0, CC0)
	VPADDD(ctr3StoreAVX2, DD0, DD0)

	VPERM2I128(Imm(0x02), AA0, BB0, TT0)

	Comment("Clamp and store poly key")
	polyClampMask := polyClampMask_DATA()
	VPAND(polyClampMask, TT0, TT0)
	VMOVDQA(TT0, rsStoreAVX2)

	Comment("Stream for the first 64 bytes")
	VPERM2I128(Imm(0x13), AA0, BB0, AA0)
	VPERM2I128(Imm(0x13), CC0, DD0, BB0)

	Comment("Hash AD + first 64 bytes")
	// MOVQ ad_len+80(FP), itr2
	MOVQ(NewParamAddr("ad_len", 80), itr2)
	CALL(LabelRef("polyHashADInternal<>(SB)"))
	XORQ(itr1, itr1)
}

func openAVX2InitialHash64() {
	Label("openAVX2InitialHash64")
	// polyAdd(0(inp)(itr1*1))
	polyAdd(Mem{Base: inp, Index: itr1, Scale: 1}.Offset(0))
	polyMulAVX2()
	ADDQ(Imm(16), itr1)
	CMPQ(itr1, Imm(64))
	JNE(LabelRef("openAVX2InitialHash64"))

	Comment("Decrypt the first 64 bytes")
	VPXOR(Mem{Base: inp}.Offset(0*32), AA0, AA0)
	VPXOR(Mem{Base: inp}.Offset(1*32), BB0, BB0)
	VMOVDQU(AA0, Mem{Base: oup}.Offset(0*32))
	VMOVDQU(BB0, Mem{Base: oup}.Offset(1*32))
	LEAQ(Mem{Base: inp}.Offset(2*32), inp)
	LEAQ(Mem{Base: oup}.Offset(2*32), oup)
	SUBQ(Imm(64), inl)
}

func openAVX2MainLoop() {
	Label("openAVX2MainLoop")
	CMPQ(inl, U32(512))
	JB(LabelRef("openAVX2MainLoopDone"))

	Comment("Load state, increment counter blocks, store the incremented counters")
	chacha20Constants := chacha20Constants_DATA()
	VMOVDQU(chacha20Constants, AA0)
	VMOVDQA(AA0, AA1)
	VMOVDQA(AA0, AA2)
	VMOVDQA(AA0, AA3)
	VMOVDQA(state1StoreAVX2, BB0)
	VMOVDQA(BB0, BB1)
	VMOVDQA(BB0, BB2)
	VMOVDQA(BB0, BB3)
	VMOVDQA(state2StoreAVX2, CC0)
	VMOVDQA(CC0, CC1)
	VMOVDQA(CC0, CC2)
	VMOVDQA(CC0, CC3)
	VMOVDQA(ctr3StoreAVX2, DD0)
	avx2IncMask := avx2IncMask_DATA()
	VPADDD(avx2IncMask, DD0, DD0)
	VPADDD(avx2IncMask, DD0, DD1)
	VPADDD(avx2IncMask, DD1, DD2)
	VPADDD(avx2IncMask, DD2, DD3)
	VMOVDQA(DD0, ctr0StoreAVX2)
	VMOVDQA(DD1, ctr1StoreAVX2)
	VMOVDQA(DD2, ctr2StoreAVX2)
	VMOVDQA(DD3, ctr3StoreAVX2)
	XORQ(itr1, itr1)
}

// Lets just say this spaghetti loop interleaves 2 quarter rounds with 3 poly multiplications
// Effectively per 512 bytes of stream we hash 480 bytes of ciphertext
func openAVX2InternalLoop() {
	Label("openAVX2InternalLoop")
	polyAdd(Mem{Base: inp, Index: itr1, Scale: 1}.Offset(0 * 8))
	VPADDD(BB0, AA0, AA0)
	VPADDD(BB1, AA1, AA1)
	VPADDD(BB2, AA2, AA2)
	VPADDD(BB3, AA3, AA3)
	polyMulStage1_AVX2()
	VPXOR(AA0, DD0, DD0)
	VPXOR(AA1, DD1, DD1)
	VPXOR(AA2, DD2, DD2)
	VPXOR(AA3, DD3, DD3)
	rol16 := rol16_DATA()
	VPSHUFB(rol16, DD0, DD0)
	VPSHUFB(rol16, DD1, DD1)
	VPSHUFB(rol16, DD2, DD2)
	VPSHUFB(rol16, DD3, DD3)
	polyMulStage2_AVX2()
	VPADDD(DD0, CC0, CC0)
	VPADDD(DD1, CC1, CC1)
	VPADDD(DD2, CC2, CC2)
	VPADDD(DD3, CC3, CC3)
	VPXOR(CC0, BB0, BB0)
	VPXOR(CC1, BB1, BB1)
	VPXOR(CC2, BB2, BB2)
	VPXOR(CC3, BB3, BB3)
	polyMulStage3_AVX2()
	VMOVDQA(CC3, tmpStoreAVX2)
	VPSLLD(Imm(12), BB0, CC3)
	VPSRLD(Imm(20), BB0, BB0)
	VPXOR(CC3, BB0, BB0)
	VPSLLD(Imm(12), BB1, CC3)
	VPSRLD(Imm(20), BB1, BB1)
	VPXOR(CC3, BB1, BB1)
	VPSLLD(Imm(12), BB2, CC3)
	VPSRLD(Imm(20), BB2, BB2)
	VPXOR(CC3, BB2, BB2)
	VPSLLD(Imm(12), BB3, CC3)
	VPSRLD(Imm(20), BB3, BB3)
	VPXOR(CC3, BB3, BB3)
	VMOVDQA(tmpStoreAVX2, CC3)
	polyMulReduceStage()
	VPADDD(BB0, AA0, AA0)
	VPADDD(BB1, AA1, AA1)
	VPADDD(BB2, AA2, AA2)
	VPADDD(BB3, AA3, AA3)
	VPXOR(AA0, DD0, DD0)
	VPXOR(AA1, DD1, DD1)
	VPXOR(AA2, DD2, DD2)
	VPXOR(AA3, DD3, DD3)
	rol8 := rol8_DATA()
	VPSHUFB(rol8, DD0, DD0)
	VPSHUFB(rol8, DD1, DD1)
	VPSHUFB(rol8, DD2, DD2)
	VPSHUFB(rol8, DD3, DD3)
	polyAdd(Mem{Base: inp, Index: itr1, Scale: 1}.Offset(2 * 8))
	VPADDD(DD0, CC0, CC0)
	VPADDD(DD1, CC1, CC1)
	VPADDD(DD2, CC2, CC2)
	VPADDD(DD3, CC3, CC3)
	polyMulStage1_AVX2()
	VPXOR(CC0, BB0, BB0)
	VPXOR(CC1, BB1, BB1)
	VPXOR(CC2, BB2, BB2)
	VPXOR(CC3, BB3, BB3)
	VMOVDQA(CC3, tmpStoreAVX2)
	VPSLLD(Imm(7), BB0, CC3)
	VPSRLD(Imm(25), BB0, BB0)
	VPXOR(CC3, BB0, BB0)
	VPSLLD(Imm(7), BB1, CC3)
	VPSRLD(Imm(25), BB1, BB1)
	VPXOR(CC3, BB1, BB1)
	VPSLLD(Imm(7), BB2, CC3)
	VPSRLD(Imm(25), BB2, BB2)
	VPXOR(CC3, BB2, BB2)
	VPSLLD(Imm(7), BB3, CC3)
	VPSRLD(Imm(25), BB3, BB3)
	VPXOR(CC3, BB3, BB3)
	VMOVDQA(tmpStoreAVX2, CC3)
	polyMulStage2_AVX2()
	VPALIGNR(Imm(4), BB0, BB0, BB0)
	VPALIGNR(Imm(4), BB1, BB1, BB1)
	VPALIGNR(Imm(4), BB2, BB2, BB2)
	VPALIGNR(Imm(4), BB3, BB3, BB3)
	VPALIGNR(Imm(8), CC0, CC0, CC0)
	VPALIGNR(Imm(8), CC1, CC1, CC1)
	VPALIGNR(Imm(8), CC2, CC2, CC2)
	VPALIGNR(Imm(8), CC3, CC3, CC3)
	VPALIGNR(Imm(12), DD0, DD0, DD0)
	VPALIGNR(Imm(12), DD1, DD1, DD1)
	VPALIGNR(Imm(12), DD2, DD2, DD2)
	VPALIGNR(Imm(12), DD3, DD3, DD3)
	VPADDD(BB0, AA0, AA0)
	VPADDD(BB1, AA1, AA1)
	VPADDD(BB2, AA2, AA2)
	VPADDD(BB3, AA3, AA3)
	polyMulStage3_AVX2()
	VPXOR(AA0, DD0, DD0)
	VPXOR(AA1, DD1, DD1)
	VPXOR(AA2, DD2, DD2)
	VPXOR(AA3, DD3, DD3)
	VPSHUFB(rol16, DD0, DD0)
	VPSHUFB(rol16, DD1, DD1)
	VPSHUFB(rol16, DD2, DD2)
	VPSHUFB(rol16, DD3, DD3)
	polyMulReduceStage()
	VPADDD(DD0, CC0, CC0)
	VPADDD(DD1, CC1, CC1)
	VPADDD(DD2, CC2, CC2)
	VPADDD(DD3, CC3, CC3)
	VPXOR(CC0, BB0, BB0)
	VPXOR(CC1, BB1, BB1)
	VPXOR(CC2, BB2, BB2)
	VPXOR(CC3, BB3, BB3)
	polyAdd(Mem{Base: inp, Index: itr1, Scale: 1}.Offset(4 * 8))
	LEAQ(Mem{Base: itr1}.Offset(6*8), itr1)
	VMOVDQA(CC3, tmpStoreAVX2)
	VPSLLD(Imm(12), BB0, CC3)
	VPSRLD(Imm(20), BB0, BB0)
	VPXOR(CC3, BB0, BB0)
	VPSLLD(Imm(12), BB1, CC3)
	VPSRLD(Imm(20), BB1, BB1)
	VPXOR(CC3, BB1, BB1)
	VPSLLD(Imm(12), BB2, CC3)
	VPSRLD(Imm(20), BB2, BB2)
	VPXOR(CC3, BB2, BB2)
	VPSLLD(Imm(12), BB3, CC3)
	VPSRLD(Imm(20), BB3, BB3)
	VPXOR(CC3, BB3, BB3)
	VMOVDQA(tmpStoreAVX2, CC3)
	polyMulStage1_AVX2()
	VPADDD(BB0, AA0, AA0)
	VPADDD(BB1, AA1, AA1)
	VPADDD(BB2, AA2, AA2)
	VPADDD(BB3, AA3, AA3)
	VPXOR(AA0, DD0, DD0)
	VPXOR(AA1, DD1, DD1)
	VPXOR(AA2, DD2, DD2)
	VPXOR(AA3, DD3, DD3)
	polyMulStage2_AVX2()
	VPSHUFB(rol8, DD0, DD0)
	VPSHUFB(rol8, DD1, DD1)
	VPSHUFB(rol8, DD2, DD2)
	VPSHUFB(rol8, DD3, DD3)
	VPADDD(DD0, CC0, CC0)
	VPADDD(DD1, CC1, CC1)
	VPADDD(DD2, CC2, CC2)
	VPADDD(DD3, CC3, CC3)
	polyMulStage3_AVX2()
	VPXOR(CC0, BB0, BB0)
	VPXOR(CC1, BB1, BB1)
	VPXOR(CC2, BB2, BB2)
	VPXOR(CC3, BB3, BB3)
	VMOVDQA(CC3, tmpStoreAVX2)
	VPSLLD(Imm(7), BB0, CC3)
	VPSRLD(Imm(25), BB0, BB0)
	VPXOR(CC3, BB0, BB0)
	VPSLLD(Imm(7), BB1, CC3)
	VPSRLD(Imm(25), BB1, BB1)
	VPXOR(CC3, BB1, BB1)
	VPSLLD(Imm(7), BB2, CC3)
	VPSRLD(Imm(25), BB2, BB2)
	VPXOR(CC3, BB2, BB2)
	VPSLLD(Imm(7), BB3, CC3)
	VPSRLD(Imm(25), BB3, BB3)
	VPXOR(CC3, BB3, BB3)
	VMOVDQA(tmpStoreAVX2, CC3)
	polyMulReduceStage()
	VPALIGNR(Imm(12), BB0, BB0, BB0)
	VPALIGNR(Imm(12), BB1, BB1, BB1)
	VPALIGNR(Imm(12), BB2, BB2, BB2)
	VPALIGNR(Imm(12), BB3, BB3, BB3)
	VPALIGNR(Imm(8), CC0, CC0, CC0)
	VPALIGNR(Imm(8), CC1, CC1, CC1)
	VPALIGNR(Imm(8), CC2, CC2, CC2)
	VPALIGNR(Imm(8), CC3, CC3, CC3)
	VPALIGNR(Imm(4), DD0, DD0, DD0)
	VPALIGNR(Imm(4), DD1, DD1, DD1)
	VPALIGNR(Imm(4), DD2, DD2, DD2)
	VPALIGNR(Imm(4), DD3, DD3, DD3)
	CMPQ(itr1, U32(480))
	JNE(LabelRef("openAVX2InternalLoop"))

	chacha20Constants := chacha20Constants_DATA()
	VPADDD(chacha20Constants, AA0, AA0)
	VPADDD(chacha20Constants, AA1, AA1)
	VPADDD(chacha20Constants, AA2, AA2)
	VPADDD(chacha20Constants, AA3, AA3)
	VPADDD(state1StoreAVX2, BB0, BB0)
	VPADDD(state1StoreAVX2, BB1, BB1)
	VPADDD(state1StoreAVX2, BB2, BB2)
	VPADDD(state1StoreAVX2, BB3, BB3)
	VPADDD(state2StoreAVX2, CC0, CC0)
	VPADDD(state2StoreAVX2, CC1, CC1)
	VPADDD(state2StoreAVX2, CC2, CC2)
	VPADDD(state2StoreAVX2, CC3, CC3)
	VPADDD(ctr0StoreAVX2, DD0, DD0)
	VPADDD(ctr1StoreAVX2, DD1, DD1)
	VPADDD(ctr2StoreAVX2, DD2, DD2)
	VPADDD(ctr3StoreAVX2, DD3, DD3)
	VMOVDQA(CC3, tmpStoreAVX2)

	Comment("We only hashed 480 of the 512 bytes available - hash the remaining 32 here")
	polyAdd(Mem{Base: inp}.Offset(480))
	polyMulAVX2()
	VPERM2I128(Imm(0x02), AA0, BB0, CC3)
	VPERM2I128(Imm(0x13), AA0, BB0, BB0)
	VPERM2I128(Imm(0x02), CC0, DD0, AA0)
	VPERM2I128(Imm(0x13), CC0, DD0, CC0)
	VPXOR(Mem{Base: inp}.Offset(0*32), CC3, CC3)
	VPXOR(Mem{Base: inp}.Offset(1*32), AA0, AA0)
	VPXOR(Mem{Base: inp}.Offset(2*32), BB0, BB0)
	VPXOR(Mem{Base: inp}.Offset(3*32), CC0, CC0)
	VMOVDQU(CC3, Mem{Base: oup}.Offset(0*32))
	VMOVDQU(AA0, Mem{Base: oup}.Offset(1*32))
	VMOVDQU(BB0, Mem{Base: oup}.Offset(2*32))
	VMOVDQU(CC0, Mem{Base: oup}.Offset(3*32))
	VPERM2I128(Imm(0x02), AA1, BB1, AA0)
	VPERM2I128(Imm(0x02), CC1, DD1, BB0)
	VPERM2I128(Imm(0x13), AA1, BB1, CC0)
	VPERM2I128(Imm(0x13), CC1, DD1, DD0)
	VPXOR(Mem{Base: inp}.Offset(4*32), AA0, AA0)
	VPXOR(Mem{Base: inp}.Offset(5*32), BB0, BB0)
	VPXOR(Mem{Base: inp}.Offset(6*32), CC0, CC0)
	VPXOR(Mem{Base: inp}.Offset(7*32), DD0, DD0)
	VMOVDQU(AA0, Mem{Base: oup}.Offset(4*32))
	VMOVDQU(BB0, Mem{Base: oup}.Offset(5*32))
	VMOVDQU(CC0, Mem{Base: oup}.Offset(6*32))
	VMOVDQU(DD0, Mem{Base: oup}.Offset(7*32))

	Comment("and here")
	polyAdd(Mem{Base: inp}.Offset(496))
	polyMulAVX2()
	VPERM2I128(Imm(0x02), AA2, BB2, AA0)
	VPERM2I128(Imm(0x02), CC2, DD2, BB0)
	VPERM2I128(Imm(0x13), AA2, BB2, CC0)
	VPERM2I128(Imm(0x13), CC2, DD2, DD0)
	VPXOR(Mem{Base: inp}.Offset(8*32), AA0, AA0)
	VPXOR(Mem{Base: inp}.Offset(9*32), BB0, BB0)
	VPXOR(Mem{Base: inp}.Offset(10*32), CC0, CC0)
	VPXOR(Mem{Base: inp}.Offset(11*32), DD0, DD0)
	VMOVDQU(AA0, Mem{Base: oup}.Offset(8*32))
	VMOVDQU(BB0, Mem{Base: oup}.Offset(9*32))
	VMOVDQU(CC0, Mem{Base: oup}.Offset(10*32))
	VMOVDQU(DD0, Mem{Base: oup}.Offset(11*32))
	VPERM2I128(Imm(0x02), AA3, BB3, AA0)
	VPERM2I128(Imm(0x02), tmpStoreAVX2, DD3, BB0)
	VPERM2I128(Imm(0x13), AA3, BB3, CC0)
	VPERM2I128(Imm(0x13), tmpStoreAVX2, DD3, DD0)
	VPXOR(Mem{Base: inp}.Offset(12*32), AA0, AA0)
	VPXOR(Mem{Base: inp}.Offset(13*32), BB0, BB0)
	VPXOR(Mem{Base: inp}.Offset(14*32), CC0, CC0)
	VPXOR(Mem{Base: inp}.Offset(15*32), DD0, DD0)
	VMOVDQU(AA0, Mem{Base: oup}.Offset(12*32))
	VMOVDQU(BB0, Mem{Base: oup}.Offset(13*32))
	VMOVDQU(CC0, Mem{Base: oup}.Offset(14*32))
	VMOVDQU(DD0, Mem{Base: oup}.Offset(15*32))
	LEAQ(Mem{Base: inp}.Offset(32*16), inp)
	LEAQ(Mem{Base: oup}.Offset(32*16), oup)
	SUBQ(U32(32*16), inl)
	JMP(LabelRef("openAVX2MainLoop"))
}

// Handle the various tail sizes efficiently
func openAVX2MainLoopDone() {
	Label("openAVX2MainLoopDone")
	Comment("Handle the various tail sizes efficiently")
	TESTQ(inl, inl)
	JE(LabelRef("openSSEFinalize"))
	CMPQ(inl, Imm(128))
	JBE(LabelRef("openAVX2Tail128"))
	CMPQ(inl, U32(256))
	JBE(LabelRef("openAVX2Tail256"))
	CMPQ(inl, U32(384))
	JBE(LabelRef("openAVX2Tail384"))
	JMP(LabelRef("openAVX2Tail512"))
}

// ----------------------------------------------------------------------------
// Special optimization for buffers smaller than 193 bytes

// For up to 192 bytes of ciphertext and 64 bytes for the poly key, we process four blocks
func openAVX2192() {
	Label("openAVX2192")
	VMOVDQA(AA0, AA1)
	VMOVDQA(BB0, BB1)
	VMOVDQA(CC0, CC1)
	avx2IncMask := avx2IncMask_DATA()
	VPADDD(avx2IncMask, DD0, DD1)
	VMOVDQA(AA0, AA2)
	VMOVDQA(BB0, BB2)
	VMOVDQA(CC0, CC2)
	VMOVDQA(DD0, DD2)
	VMOVDQA(DD1, TT3)
	MOVQ(U32(10), itr2)
}

func openAVX2192InnerCipherLoop() {
	Label("openAVX2192InnerCipherLoop")
	chachaQR_AVX2(AA0, BB0, CC0, DD0, TT0)
	chachaQR_AVX2(AA1, BB1, CC1, DD1, TT0)
	VPALIGNR(Imm(4), BB0, BB0, BB0)
	VPALIGNR(Imm(4), BB1, BB1, BB1)
	VPALIGNR(Imm(8), CC0, CC0, CC0)
	VPALIGNR(Imm(8), CC1, CC1, CC1)
	VPALIGNR(Imm(12), DD0, DD0, DD0)
	VPALIGNR(Imm(12), DD1, DD1, DD1)
	chachaQR_AVX2(AA0, BB0, CC0, DD0, TT0)
	chachaQR_AVX2(AA1, BB1, CC1, DD1, TT0)
	VPALIGNR(Imm(12), BB0, BB0, BB0)
	VPALIGNR(Imm(12), BB1, BB1, BB1)
	VPALIGNR(Imm(8), CC0, CC0, CC0)
	VPALIGNR(Imm(8), CC1, CC1, CC1)
	VPALIGNR(Imm(4), DD0, DD0, DD0)
	VPALIGNR(Imm(4), DD1, DD1, DD1)
	DECQ(itr2)
	JNE(LabelRef("openAVX2192InnerCipherLoop"))
	VPADDD(AA2, AA0, AA0)
	VPADDD(AA2, AA1, AA1)
	VPADDD(BB2, BB0, BB0)
	VPADDD(BB2, BB1, BB1)
	VPADDD(CC2, CC0, CC0)
	VPADDD(CC2, CC1, CC1)
	VPADDD(DD2, DD0, DD0)
	VPADDD(TT3, DD1, DD1)
	VPERM2I128(Imm(0x02), AA0, BB0, TT0)

	Comment("Clamp and store poly key")
	polyClampMask := polyClampMask_DATA()
	VPAND(polyClampMask, TT0, TT0)
	VMOVDQA(TT0, rsStoreAVX2)

	Comment("Stream for up to 192 bytes")
	VPERM2I128(Imm(0x13), AA0, BB0, AA0)
	VPERM2I128(Imm(0x13), CC0, DD0, BB0)
	VPERM2I128(Imm(0x02), AA1, BB1, CC0)
	VPERM2I128(Imm(0x02), CC1, DD1, DD0)
	VPERM2I128(Imm(0x13), AA1, BB1, AA1)
	VPERM2I128(Imm(0x13), CC1, DD1, BB1)
}

func openAVX2ShortOpen() {
	Label("openAVX2ShortOpen")
	Comment("Hash")
	Load(Param("ad").Len(), itr2)
	CALL(LabelRef("polyHashADInternal<>(SB)"))
}

func openAVX2ShortOpenLoop() {
	Label("openAVX2ShortOpenLoop")
	CMPQ(inl, Imm(32))
	JB(LabelRef("openAVX2ShortTail32"))
	SUBQ(Imm(32), inl)

	Comment("Load for hashing")
	polyAdd(Mem{Base: inp}.Offset(0 * 8))
	polyMulAVX2()
	polyAdd(Mem{Base: inp}.Offset(2 * 8))
	polyMulAVX2()

	Comment("Load for decryption")
	VPXOR(Mem{Base: inp}, AA0, AA0)
	VMOVDQU(AA0, Mem{Base: oup})
	LEAQ(Mem{Base: inp}.Offset(1*32), inp)
	LEAQ(Mem{Base: oup}.Offset(1*32), oup)

	Comment("Shift stream left")
	VMOVDQA(BB0, AA0)
	VMOVDQA(CC0, BB0)
	VMOVDQA(DD0, CC0)
	VMOVDQA(AA1, DD0)
	VMOVDQA(BB1, AA1)
	VMOVDQA(CC1, BB1)
	VMOVDQA(DD1, CC1)
	VMOVDQA(AA2, DD1)
	VMOVDQA(BB2, AA2)
	JMP(LabelRef("openAVX2ShortOpenLoop"))
}

func openAVX2ShortTail32() {
	Label("openAVX2ShortTail32")
	CMPQ(inl, Imm(16))
	VMOVDQA(A0, A1)
	JB(LabelRef("openAVX2ShortDone"))

	SUBQ(Imm(16), inl)

	Comment("Load for hashing")
	polyAdd(Mem{Base: inp}.Offset(0 * 8))
	polyMulAVX2()

	Comment("Load for decryption")
	VPXOR(Mem{Base: inp}, A0, T0)
	VMOVDQU(T0, Mem{Base: oup})
	LEAQ(Mem{Base: inp}.Offset(1*16), inp)
	LEAQ(Mem{Base: oup}.Offset(1*16), oup)
	VPERM2I128(Imm(0x11), AA0, AA0, AA0)
	VMOVDQA(A0, A1)
}

func openAVX2ShortDone() {
	Label("openAVX2ShortDone")
	VZEROUPPER()
	JMP(LabelRef("openSSETail16"))
}

// ----------------------------------------------------------------------------
// Special optimization for buffers smaller than 321 bytes

// For up to 320 bytes of ciphertext and 64 bytes for the poly key, we process six blocks
func openAVX2320() {
	Label("openAVX2320")
	VMOVDQA(AA0, AA1)
	VMOVDQA(BB0, BB1)
	VMOVDQA(CC0, CC1)
	avx2IncMask := avx2IncMask_DATA()
	VPADDD(avx2IncMask, DD0, DD1)
	VMOVDQA(AA0, AA2)
	VMOVDQA(BB0, BB2)
	VMOVDQA(CC0, CC2)
	VPADDD(avx2IncMask, DD1, DD2)
	VMOVDQA(BB0, TT1)
	VMOVDQA(CC0, TT2)
	VMOVDQA(DD0, TT3)
	MOVQ(U32(10), itr2)
}

func openAVX2320InnerCipherLoop() {
	Label("openAVX2320InnerCipherLoop")
	chachaQR_AVX2(AA0, BB0, CC0, DD0, TT0)
	chachaQR_AVX2(AA1, BB1, CC1, DD1, TT0)
	chachaQR_AVX2(AA2, BB2, CC2, DD2, TT0)
	VPALIGNR(Imm(4), BB0, BB0, BB0)
	VPALIGNR(Imm(4), BB1, BB1, BB1)
	VPALIGNR(Imm(4), BB2, BB2, BB2)
	VPALIGNR(Imm(8), CC0, CC0, CC0)
	VPALIGNR(Imm(8), CC1, CC1, CC1)
	VPALIGNR(Imm(8), CC2, CC2, CC2)
	VPALIGNR(Imm(12), DD0, DD0, DD0)
	VPALIGNR(Imm(12), DD1, DD1, DD1)
	VPALIGNR(Imm(12), DD2, DD2, DD2)
	chachaQR_AVX2(AA0, BB0, CC0, DD0, TT0)
	chachaQR_AVX2(AA1, BB1, CC1, DD1, TT0)
	chachaQR_AVX2(AA2, BB2, CC2, DD2, TT0)
	VPALIGNR(Imm(12), BB0, BB0, BB0)
	VPALIGNR(Imm(12), BB1, BB1, BB1)
	VPALIGNR(Imm(12), BB2, BB2, BB2)
	VPALIGNR(Imm(8), CC0, CC0, CC0)
	VPALIGNR(Imm(8), CC1, CC1, CC1)
	VPALIGNR(Imm(8), CC2, CC2, CC2)
	VPALIGNR(Imm(4), DD0, DD0, DD0)
	VPALIGNR(Imm(4), DD1, DD1, DD1)
	VPALIGNR(Imm(4), DD2, DD2, DD2)
	DECQ(itr2)
	JNE(LabelRef("openAVX2320InnerCipherLoop"))

	chacha20Constants := chacha20Constants_DATA()
	VMOVDQA(chacha20Constants, TT0)
	VPADDD(TT0, AA0, AA0)
	VPADDD(TT0, AA1, AA1)
	VPADDD(TT0, AA2, AA2)
	VPADDD(TT1, BB0, BB0)
	VPADDD(TT1, BB1, BB1)
	VPADDD(TT1, BB2, BB2)
	VPADDD(TT2, CC0, CC0)
	VPADDD(TT2, CC1, CC1)
	VPADDD(TT2, CC2, CC2)
	avx2IncMask := avx2IncMask_DATA()
	VMOVDQA(avx2IncMask, TT0)
	VPADDD(TT3, DD0, DD0)
	VPADDD(TT0, TT3, TT3)
	VPADDD(TT3, DD1, DD1)
	VPADDD(TT0, TT3, TT3)
	VPADDD(TT3, DD2, DD2)

	Comment("Clamp and store poly key")
	VPERM2I128(Imm(0x02), AA0, BB0, TT0)
	polyClampMask := polyClampMask_DATA()
	VPAND(polyClampMask, TT0, TT0)
	VMOVDQA(TT0, rsStoreAVX2)

	Comment("Stream for up to 320 bytes")
	VPERM2I128(Imm(0x13), AA0, BB0, AA0)
	VPERM2I128(Imm(0x13), CC0, DD0, BB0)
	VPERM2I128(Imm(0x02), AA1, BB1, CC0)
	VPERM2I128(Imm(0x02), CC1, DD1, DD0)
	VPERM2I128(Imm(0x13), AA1, BB1, AA1)
	VPERM2I128(Imm(0x13), CC1, DD1, BB1)
	VPERM2I128(Imm(0x02), AA2, BB2, CC1)
	VPERM2I128(Imm(0x02), CC2, DD2, DD1)
	VPERM2I128(Imm(0x13), AA2, BB2, AA2)
	VPERM2I128(Imm(0x13), CC2, DD2, BB2)
	JMP(LabelRef("openAVX2ShortOpen"))
}

// ----------------------------------------------------------------------------
// Special optimization for the last 128 bytes of ciphertext

// Need to decrypt up to 128 bytes - prepare two blocks
func openAVX2Tail128() {
	Label("openAVX2Tail128")
	Comment("Need to decrypt up to 128 bytes - prepare two blocks")
	chacha20Constants := chacha20Constants_DATA()
	VMOVDQA(chacha20Constants, AA1)
	VMOVDQA(state1StoreAVX2, BB1)
	VMOVDQA(state2StoreAVX2, CC1)
	VMOVDQA(ctr3StoreAVX2, DD1)
	avx2IncMask := avx2IncMask_DATA()
	VPADDD(avx2IncMask, DD1, DD1)
	VMOVDQA(DD1, DD0)

	XORQ(itr2, itr2)
	MOVQ(inl, itr1)
	ANDQ(I8(-16), itr1)
	TESTQ(itr1, itr1)
	JE(LabelRef("openAVX2Tail128LoopB"))
}

// Perform ChaCha rounds, while hashing the remaining input
func openAVX2Tail128LoopA() {
	Label("openAVX2Tail128LoopA")
	polyAdd(Mem{Base: inp, Index: itr2, Scale: 1}.Offset(0))
	polyMulAVX2()
}

func openAVX2Tail128LoopB() {
	Label("openAVX2Tail128LoopB")
	ADDQ(Imm(16), itr2)
	chachaQR_AVX2(AA1, BB1, CC1, DD1, TT0)
	VPALIGNR(Imm(4), BB1, BB1, BB1)
	VPALIGNR(Imm(8), CC1, CC1, CC1)
	VPALIGNR(Imm(12), DD1, DD1, DD1)
	chachaQR_AVX2(AA1, BB1, CC1, DD1, TT0)
	VPALIGNR(Imm(12), BB1, BB1, BB1)
	VPALIGNR(Imm(8), CC1, CC1, CC1)
	VPALIGNR(Imm(4), DD1, DD1, DD1)
	CMPQ(itr2, itr1)
	JB(LabelRef("openAVX2Tail128LoopA"))
	CMPQ(itr2, Imm(160))
	JNE(LabelRef("openAVX2Tail128LoopB"))

	chacha20Constants := chacha20Constants_DATA()
	VPADDD(chacha20Constants, AA1, AA1)
	VPADDD(state1StoreAVX2, BB1, BB1)
	VPADDD(state2StoreAVX2, CC1, CC1)
	VPADDD(DD0, DD1, DD1)
	VPERM2I128(Imm(0x02), AA1, BB1, AA0)
	VPERM2I128(Imm(0x02), CC1, DD1, BB0)
	VPERM2I128(Imm(0x13), AA1, BB1, CC0)
	VPERM2I128(Imm(0x13), CC1, DD1, DD0)
}

func openAVX2TailLoop() {
	Label("openAVX2TailLoop")
	CMPQ(inl, Imm(32))
	JB(LabelRef("openAVX2Tail"))
	SUBQ(Imm(32), inl)

	Comment("Load for decryption")
	VPXOR(Mem{Base: inp}, AA0, AA0)
	VMOVDQU(AA0, Mem{Base: oup})
	LEAQ(Mem{Base: inp}.Offset(1*32), inp)
	LEAQ(Mem{Base: oup}.Offset(1*32), oup)
	VMOVDQA(BB0, AA0)
	VMOVDQA(CC0, BB0)
	VMOVDQA(DD0, CC0)
	JMP(LabelRef("openAVX2TailLoop"))
}

func openAVX2Tail() {
	Label("openAVX2Tail")
	CMPQ(inl, Imm(16))
	VMOVDQA(A0, A1)
	JB(LabelRef("openAVX2TailDone"))
	SUBQ(Imm(16), inl)

	Comment("Load for decryption")
	VPXOR(Mem{Base: inp}, A0, T0)
	VMOVDQU(T0, Mem{Base: oup})
	LEAQ(Mem{Base: inp}.Offset(1*16), inp)
	LEAQ(Mem{Base: oup}.Offset(1*16), oup)
	VPERM2I128(Imm(0x11), AA0, AA0, AA0)
	VMOVDQA(A0, A1)
}

func openAVX2TailDone() {
	Label("openAVX2TailDone")
	VZEROUPPER()
	JMP(LabelRef("openSSETail16"))
}

// ----------------------------------------------------------------------------
// Special optimization for the last 256 bytes of ciphertext

// Need to decrypt up to 256 bytes - prepare four blocks
func openAVX2Tail256() {
	Label("openAVX2Tail256")
	chacha20Constants := chacha20Constants_DATA()
	VMOVDQA(chacha20Constants, AA0)
	VMOVDQA(AA0, AA1)
	VMOVDQA(state1StoreAVX2, BB0)
	VMOVDQA(BB0, BB1)
	VMOVDQA(state2StoreAVX2, CC0)
	VMOVDQA(CC0, CC1)
	VMOVDQA(ctr3StoreAVX2, DD0)
	avx2IncMask := avx2IncMask_DATA()
	VPADDD(avx2IncMask, DD0, DD0)
	VPADDD(avx2IncMask, DD0, DD1)
	VMOVDQA(DD0, TT1)
	VMOVDQA(DD1, TT2)

	Comment("Compute the number of iterations that will hash data")
	MOVQ(inl, tmpStoreAVX2)
	MOVQ(inl, itr1)
	SUBQ(Imm(128), itr1)
	SHRQ(Imm(4), itr1)
	MOVQ(U32(10), itr2)
	CMPQ(itr1, Imm(10))
	CMOVQGT(itr2, itr1)
	MOVQ(inp, inl)
	XORQ(itr2, itr2)
}

func openAVX2Tail256LoopA() {
	Label("openAVX2Tail256LoopA")
	polyAdd(Mem{Base: inl}.Offset(0))
	polyMulAVX2()
	LEAQ(Mem{Base: inl}.Offset(16), inl)
}

// Perform ChaCha rounds, while hashing the remaining input
func openAVX2Tail256LoopB() {
	Label("openAVX2Tail256LoopB")
	chachaQR_AVX2(AA0, BB0, CC0, DD0, TT0)
	chachaQR_AVX2(AA1, BB1, CC1, DD1, TT0)
	VPALIGNR(Imm(4), BB0, BB0, BB0)
	VPALIGNR(Imm(4), BB1, BB1, BB1)
	VPALIGNR(Imm(8), CC0, CC0, CC0)
	VPALIGNR(Imm(8), CC1, CC1, CC1)
	VPALIGNR(Imm(12), DD0, DD0, DD0)
	VPALIGNR(Imm(12), DD1, DD1, DD1)
	INCQ(itr2)
	chachaQR_AVX2(AA0, BB0, CC0, DD0, TT0)
	chachaQR_AVX2(AA1, BB1, CC1, DD1, TT0)
	VPALIGNR(Imm(12), BB0, BB0, BB0)
	VPALIGNR(Imm(12), BB1, BB1, BB1)
	VPALIGNR(Imm(8), CC0, CC0, CC0)
	VPALIGNR(Imm(8), CC1, CC1, CC1)
	VPALIGNR(Imm(4), DD0, DD0, DD0)
	VPALIGNR(Imm(4), DD1, DD1, DD1)
	CMPQ(itr2, itr1)
	JB(LabelRef("openAVX2Tail256LoopA"))

	CMPQ(itr2, Imm(10))
	JNE(LabelRef("openAVX2Tail256LoopB"))

	MOVQ(inl, itr2)
	SUBQ(inp, inl)
	MOVQ(inl, itr1)
	MOVQ(tmpStoreAVX2, inl)
}

// Hash the remainder of data (if any)
func openAVX2Tail256Hash() {
	Label("openAVX2Tail256Hash")
	ADDQ(Imm(16), itr1)
	CMPQ(itr1, inl)
	JGT(LabelRef("openAVX2Tail256HashEnd"))
	polyAdd(Mem{Base: itr2}.Offset(0))
	polyMulAVX2()
	LEAQ(Mem{Base: itr2}.Offset(16), itr2)
	JMP(LabelRef("openAVX2Tail256Hash"))
}

// Store 128 bytes safely, then go to store loop
func openAVX2Tail256HashEnd() {
	Label("openAVX2Tail256HashEnd")
	chacha20Constants := chacha20Constants_DATA()
	VPADDD(chacha20Constants, AA0, AA0)
	VPADDD(chacha20Constants, AA1, AA1)
	VPADDD(state1StoreAVX2, BB0, BB0)
	VPADDD(state1StoreAVX2, BB1, BB1)
	VPADDD(state2StoreAVX2, CC0, CC0)
	VPADDD(state2StoreAVX2, CC1, CC1)
	VPADDD(TT1, DD0, DD0)
	VPADDD(TT2, DD1, DD1)
	VPERM2I128(Imm(0x02), AA0, BB0, AA2)
	VPERM2I128(Imm(0x02), CC0, DD0, BB2)
	VPERM2I128(Imm(0x13), AA0, BB0, CC2)
	VPERM2I128(Imm(0x13), CC0, DD0, DD2)
	VPERM2I128(Imm(0x02), AA1, BB1, AA0)
	VPERM2I128(Imm(0x02), CC1, DD1, BB0)
	VPERM2I128(Imm(0x13), AA1, BB1, CC0)
	VPERM2I128(Imm(0x13), CC1, DD1, DD0)

	VPXOR(Mem{Base: inp}.Offset(0*32), AA2, AA2)
	VPXOR(Mem{Base: inp}.Offset(1*32), BB2, BB2)
	VPXOR(Mem{Base: inp}.Offset(2*32), CC2, CC2)
	VPXOR(Mem{Base: inp}.Offset(3*32), DD2, DD2)
	VMOVDQU(AA2, Mem{Base: oup}.Offset(0*32))
	VMOVDQU(BB2, Mem{Base: oup}.Offset(1*32))
	VMOVDQU(CC2, Mem{Base: oup}.Offset(2*32))
	VMOVDQU(DD2, Mem{Base: oup}.Offset(3*32))
	LEAQ(Mem{Base: inp}.Offset(4*32), inp)
	LEAQ(Mem{Base: oup}.Offset(4*32), oup)
	SUBQ(Imm(4*32), inl)

	JMP(LabelRef("openAVX2TailLoop"))
}

// ----------------------------------------------------------------------------
// Special optimization for the last 384 bytes of ciphertext

// Need to decrypt up to 384 bytes - prepare six blocks
func openAVX2Tail384() {
	Label("openAVX2Tail384")
	Comment("Need to decrypt up to 384 bytes - prepare six blocks")
	chacha20Constants := chacha20Constants_DATA()
	VMOVDQA(chacha20Constants, AA0)
	VMOVDQA(AA0, AA1)
	VMOVDQA(AA0, AA2)
	VMOVDQA(state1StoreAVX2, BB0)
	VMOVDQA(BB0, BB1)
	VMOVDQA(BB0, BB2)
	VMOVDQA(state2StoreAVX2, CC0)
	VMOVDQA(CC0, CC1)
	VMOVDQA(CC0, CC2)
	VMOVDQA(ctr3StoreAVX2, DD0)
	avx2IncMask := avx2IncMask_DATA()
	VPADDD(avx2IncMask, DD0, DD0)
	VPADDD(avx2IncMask, DD0, DD1)
	VPADDD(avx2IncMask, DD1, DD2)
	VMOVDQA(DD0, ctr0StoreAVX2)
	VMOVDQA(DD1, ctr1StoreAVX2)
	VMOVDQA(DD2, ctr2StoreAVX2)

	Comment("Compute the number of iterations that will hash two blocks of data")
	MOVQ(inl, tmpStoreAVX2)
	MOVQ(inl, itr1)
	SUBQ(U32(256), itr1)
	SHRQ(Imm(4), itr1)
	ADDQ(Imm(6), itr1)
	MOVQ(U32(10), itr2)
	CMPQ(itr1, Imm(10))
	CMOVQGT(itr2, itr1)
	MOVQ(inp, inl)
	XORQ(itr2, itr2)
}

// Perform ChaCha rounds, while hashing the remaining input
func openAVX2Tail384LoopB() {
	Label("openAVX2Tail384LoopB")
	polyAdd(Mem{Base: inl}.Offset(0))
	polyMulAVX2()
	LEAQ(Mem{Base: inl}.Offset(16), inl)
}

func openAVX2Tail384LoopA() {
	Label("openAVX2Tail384LoopA")
	chachaQR_AVX2(AA0, BB0, CC0, DD0, TT0)
	chachaQR_AVX2(AA1, BB1, CC1, DD1, TT0)
	chachaQR_AVX2(AA2, BB2, CC2, DD2, TT0)
	VPALIGNR(Imm(4), BB0, BB0, BB0)
	VPALIGNR(Imm(4), BB1, BB1, BB1)
	VPALIGNR(Imm(4), BB2, BB2, BB2)
	VPALIGNR(Imm(8), CC0, CC0, CC0)
	VPALIGNR(Imm(8), CC1, CC1, CC1)
	VPALIGNR(Imm(8), CC2, CC2, CC2)
	VPALIGNR(Imm(12), DD0, DD0, DD0)
	VPALIGNR(Imm(12), DD1, DD1, DD1)
	VPALIGNR(Imm(12), DD2, DD2, DD2)
	polyAdd(Mem{Base: inl}.Offset(0))
	polyMulAVX2()
	LEAQ(Mem{Base: inl}.Offset(16), inl)
	INCQ(itr2)
	chachaQR_AVX2(AA0, BB0, CC0, DD0, TT0)
	chachaQR_AVX2(AA1, BB1, CC1, DD1, TT0)
	chachaQR_AVX2(AA2, BB2, CC2, DD2, TT0)
	VPALIGNR(Imm(12), BB0, BB0, BB0)
	VPALIGNR(Imm(12), BB1, BB1, BB1)
	VPALIGNR(Imm(12), BB2, BB2, BB2)
	VPALIGNR(Imm(8), CC0, CC0, CC0)
	VPALIGNR(Imm(8), CC1, CC1, CC1)
	VPALIGNR(Imm(8), CC2, CC2, CC2)
	VPALIGNR(Imm(4), DD0, DD0, DD0)
	VPALIGNR(Imm(4), DD1, DD1, DD1)
	VPALIGNR(Imm(4), DD2, DD2, DD2)

	CMPQ(itr2, itr1)
	JB(LabelRef("openAVX2Tail384LoopB"))

	CMPQ(itr2, Imm(10))
	JNE(LabelRef("openAVX2Tail384LoopA"))

	MOVQ(inl, itr2)
	SUBQ(inp, inl)
	MOVQ(inl, itr1)
	MOVQ(tmpStoreAVX2, inl)
}

func openAVX2Tail384Hash() {
	Label("openAVX2Tail384Hash")
	ADDQ(Imm(16), itr1)
	CMPQ(itr1, inl)
	JGT(LabelRef("openAVX2Tail384HashEnd"))
	polyAdd(Mem{Base: itr2}.Offset(0))
	polyMulAVX2()
	LEAQ(Mem{Base: itr2}.Offset(16), itr2)
	JMP(LabelRef("openAVX2Tail384Hash"))
}

// Store 256 bytes safely, then go to store loop
func openAVX2Tail384HashEnd() {
	Label("openAVX2Tail384HashEnd")
	chacha20Constants := chacha20Constants_DATA()
	VPADDD(chacha20Constants, AA0, AA0)
	VPADDD(chacha20Constants, AA1, AA1)
	VPADDD(chacha20Constants, AA2, AA2)
	VPADDD(state1StoreAVX2, BB0, BB0)
	VPADDD(state1StoreAVX2, BB1, BB1)
	VPADDD(state1StoreAVX2, BB2, BB2)
	VPADDD(state2StoreAVX2, CC0, CC0)
	VPADDD(state2StoreAVX2, CC1, CC1)
	VPADDD(state2StoreAVX2, CC2, CC2)
	VPADDD(ctr0StoreAVX2, DD0, DD0)
	VPADDD(ctr1StoreAVX2, DD1, DD1)
	VPADDD(ctr2StoreAVX2, DD2, DD2)
	VPERM2I128(Imm(0x02), AA0, BB0, TT0)
	VPERM2I128(Imm(0x02), CC0, DD0, TT1)
	VPERM2I128(Imm(0x13), AA0, BB0, TT2)
	VPERM2I128(Imm(0x13), CC0, DD0, TT3)
	VPXOR(Mem{Base: inp}.Offset(0*32), TT0, TT0)
	VPXOR(Mem{Base: inp}.Offset(1*32), TT1, TT1)
	VPXOR(Mem{Base: inp}.Offset(2*32), TT2, TT2)
	VPXOR(Mem{Base: inp}.Offset(3*32), TT3, TT3)
	VMOVDQU(TT0, Mem{Base: oup}.Offset(0*32))
	VMOVDQU(TT1, Mem{Base: oup}.Offset(1*32))
	VMOVDQU(TT2, Mem{Base: oup}.Offset(2*32))
	VMOVDQU(TT3, Mem{Base: oup}.Offset(3*32))
	VPERM2I128(Imm(0x02), AA1, BB1, TT0)
	VPERM2I128(Imm(0x02), CC1, DD1, TT1)
	VPERM2I128(Imm(0x13), AA1, BB1, TT2)
	VPERM2I128(Imm(0x13), CC1, DD1, TT3)
	VPXOR(Mem{Base: inp}.Offset(4*32), TT0, TT0)
	VPXOR(Mem{Base: inp}.Offset(5*32), TT1, TT1)
	VPXOR(Mem{Base: inp}.Offset(6*32), TT2, TT2)
	VPXOR(Mem{Base: inp}.Offset(7*32), TT3, TT3)
	VMOVDQU(TT0, Mem{Base: oup}.Offset(4*32))
	VMOVDQU(TT1, Mem{Base: oup}.Offset(5*32))
	VMOVDQU(TT2, Mem{Base: oup}.Offset(6*32))
	VMOVDQU(TT3, Mem{Base: oup}.Offset(7*32))
	VPERM2I128(Imm(0x02), AA2, BB2, AA0)
	VPERM2I128(Imm(0x02), CC2, DD2, BB0)
	VPERM2I128(Imm(0x13), AA2, BB2, CC0)
	VPERM2I128(Imm(0x13), CC2, DD2, DD0)
	LEAQ(Mem{Base: inp}.Offset(8*32), inp)
	LEAQ(Mem{Base: oup}.Offset(8*32), oup)
	SUBQ(U32(8*32), inl)
	JMP(LabelRef("openAVX2TailLoop"))
}

// ----------------------------------------------------------------------------
// Special optimization for the last 512 bytes of ciphertext

func openAVX2Tail512() {
	Label("openAVX2Tail512")
	chacha20Constants := chacha20Constants_DATA()
	VMOVDQU(chacha20Constants, AA0)
	VMOVDQA(AA0, AA1)
	VMOVDQA(AA0, AA2)
	VMOVDQA(AA0, AA3)
	VMOVDQA(state1StoreAVX2, BB0)
	VMOVDQA(BB0, BB1)
	VMOVDQA(BB0, BB2)
	VMOVDQA(BB0, BB3)
	VMOVDQA(state2StoreAVX2, CC0)
	VMOVDQA(CC0, CC1)
	VMOVDQA(CC0, CC2)
	VMOVDQA(CC0, CC3)
	VMOVDQA(ctr3StoreAVX2, DD0)
	avx2IncMask := avx2IncMask_DATA()
	VPADDD(avx2IncMask, DD0, DD0)
	VPADDD(avx2IncMask, DD0, DD1)
	VPADDD(avx2IncMask, DD1, DD2)
	VPADDD(avx2IncMask, DD2, DD3)
	VMOVDQA(DD0, ctr0StoreAVX2)
	VMOVDQA(DD1, ctr1StoreAVX2)
	VMOVDQA(DD2, ctr2StoreAVX2)
	VMOVDQA(DD3, ctr3StoreAVX2)
	XORQ(itr1, itr1)
	MOVQ(inp, itr2)
}

func openAVX2Tail512LoopB() {
	Label("openAVX2Tail512LoopB")
	polyAdd(Mem{Base: itr2}.Offset(0))
	polyMulAVX2()
	LEAQ(Mem{Base: itr2}.Offset(2*8), itr2)
}

func openAVX2Tail512LoopA() {
	Label("openAVX2Tail512LoopA")
	VPADDD(BB0, AA0, AA0)
	VPADDD(BB1, AA1, AA1)
	VPADDD(BB2, AA2, AA2)
	VPADDD(BB3, AA3, AA3)
	VPXOR(AA0, DD0, DD0)
	VPXOR(AA1, DD1, DD1)
	VPXOR(AA2, DD2, DD2)
	VPXOR(AA3, DD3, DD3)
	rol16 := rol16_DATA()
	VPSHUFB(rol16, DD0, DD0)
	VPSHUFB(rol16, DD1, DD1)
	VPSHUFB(rol16, DD2, DD2)
	VPSHUFB(rol16, DD3, DD3)
	VPADDD(DD0, CC0, CC0)
	VPADDD(DD1, CC1, CC1)
	VPADDD(DD2, CC2, CC2)
	VPADDD(DD3, CC3, CC3)
	VPXOR(CC0, BB0, BB0)
	VPXOR(CC1, BB1, BB1)
	VPXOR(CC2, BB2, BB2)
	VPXOR(CC3, BB3, BB3)
	VMOVDQA(CC3, tmpStoreAVX2)
	VPSLLD(Imm(12), BB0, CC3)
	VPSRLD(Imm(20), BB0, BB0)
	VPXOR(CC3, BB0, BB0)
	VPSLLD(Imm(12), BB1, CC3)
	VPSRLD(Imm(20), BB1, BB1)
	VPXOR(CC3, BB1, BB1)
	VPSLLD(Imm(12), BB2, CC3)
	VPSRLD(Imm(20), BB2, BB2)
	VPXOR(CC3, BB2, BB2)
	VPSLLD(Imm(12), BB3, CC3)
	VPSRLD(Imm(20), BB3, BB3)
	VPXOR(CC3, BB3, BB3)
	VMOVDQA(tmpStoreAVX2, CC3)
	polyAdd(Mem{Base: itr2}.Offset(0 * 8))
	polyMulAVX2()
	VPADDD(BB0, AA0, AA0)
	VPADDD(BB1, AA1, AA1)
	VPADDD(BB2, AA2, AA2)
	VPADDD(BB3, AA3, AA3)
	VPXOR(AA0, DD0, DD0)
	VPXOR(AA1, DD1, DD1)
	VPXOR(AA2, DD2, DD2)
	VPXOR(AA3, DD3, DD3)
	rol8 := rol8_DATA()
	VPSHUFB(rol8, DD0, DD0)
	VPSHUFB(rol8, DD1, DD1)
	VPSHUFB(rol8, DD2, DD2)
	VPSHUFB(rol8, DD3, DD3)
	VPADDD(DD0, CC0, CC0)
	VPADDD(DD1, CC1, CC1)
	VPADDD(DD2, CC2, CC2)
	VPADDD(DD3, CC3, CC3)
	VPXOR(CC0, BB0, BB0)
	VPXOR(CC1, BB1, BB1)
	VPXOR(CC2, BB2, BB2)
	VPXOR(CC3, BB3, BB3)
	VMOVDQA(CC3, tmpStoreAVX2)
	VPSLLD(Imm(7), BB0, CC3)
	VPSRLD(Imm(25), BB0, BB0)
	VPXOR(CC3, BB0, BB0)
	VPSLLD(Imm(7), BB1, CC3)
	VPSRLD(Imm(25), BB1, BB1)
	VPXOR(CC3, BB1, BB1)
	VPSLLD(Imm(7), BB2, CC3)
	VPSRLD(Imm(25), BB2, BB2)
	VPXOR(CC3, BB2, BB2)
	VPSLLD(Imm(7), BB3, CC3)
	VPSRLD(Imm(25), BB3, BB3)
	VPXOR(CC3, BB3, BB3)
	VMOVDQA(tmpStoreAVX2, CC3)
	VPALIGNR(Imm(4), BB0, BB0, BB0)
	VPALIGNR(Imm(4), BB1, BB1, BB1)
	VPALIGNR(Imm(4), BB2, BB2, BB2)
	VPALIGNR(Imm(4), BB3, BB3, BB3)
	VPALIGNR(Imm(8), CC0, CC0, CC0)
	VPALIGNR(Imm(8), CC1, CC1, CC1)
	VPALIGNR(Imm(8), CC2, CC2, CC2)
	VPALIGNR(Imm(8), CC3, CC3, CC3)
	VPALIGNR(Imm(12), DD0, DD0, DD0)
	VPALIGNR(Imm(12), DD1, DD1, DD1)
	VPALIGNR(Imm(12), DD2, DD2, DD2)
	VPALIGNR(Imm(12), DD3, DD3, DD3)
	VPADDD(BB0, AA0, AA0)
	VPADDD(BB1, AA1, AA1)
	VPADDD(BB2, AA2, AA2)
	VPADDD(BB3, AA3, AA3)
	VPXOR(AA0, DD0, DD0)
	VPXOR(AA1, DD1, DD1)
	VPXOR(AA2, DD2, DD2)
	VPXOR(AA3, DD3, DD3)
	VPSHUFB(rol16, DD0, DD0)
	VPSHUFB(rol16, DD1, DD1)
	VPSHUFB(rol16, DD2, DD2)
	VPSHUFB(rol16, DD3, DD3)
	VPADDD(DD0, CC0, CC0)
	VPADDD(DD1, CC1, CC1)
	VPADDD(DD2, CC2, CC2)
	VPADDD(DD3, CC3, CC3)
	VPXOR(CC0, BB0, BB0)
	VPXOR(CC1, BB1, BB1)
	VPXOR(CC2, BB2, BB2)
	VPXOR(CC3, BB3, BB3)
	polyAdd(Mem{Base: itr2}.Offset(2 * 8))
	polyMulAVX2()
	LEAQ(Mem{Base: itr2}.Offset(4*8), itr2)
	VMOVDQA(CC3, tmpStoreAVX2)
	VPSLLD(Imm(12), BB0, CC3)
	VPSRLD(Imm(20), BB0, BB0)
	VPXOR(CC3, BB0, BB0)
	VPSLLD(Imm(12), BB1, CC3)
	VPSRLD(Imm(20), BB1, BB1)
	VPXOR(CC3, BB1, BB1)
	VPSLLD(Imm(12), BB2, CC3)
	VPSRLD(Imm(20), BB2, BB2)
	VPXOR(CC3, BB2, BB2)
	VPSLLD(Imm(12), BB3, CC3)
	VPSRLD(Imm(20), BB3, BB3)
	VPXOR(CC3, BB3, BB3)
	VMOVDQA(tmpStoreAVX2, CC3)
	VPADDD(BB0, AA0, AA0)
	VPADDD(BB1, AA1, AA1)
	VPADDD(BB2, AA2, AA2)
	VPADDD(BB3, AA3, AA3)
	VPXOR(AA0, DD0, DD0)
	VPXOR(AA1, DD1, DD1)
	VPXOR(AA2, DD2, DD2)
	VPXOR(AA3, DD3, DD3)
	VPSHUFB(rol8, DD0, DD0)
	VPSHUFB(rol8, DD1, DD1)
	VPSHUFB(rol8, DD2, DD2)
	VPSHUFB(rol8, DD3, DD3)
	VPADDD(DD0, CC0, CC0)
	VPADDD(DD1, CC1, CC1)
	VPADDD(DD2, CC2, CC2)
	VPADDD(DD3, CC3, CC3)
	VPXOR(CC0, BB0, BB0)
	VPXOR(CC1, BB1, BB1)
	VPXOR(CC2, BB2, BB2)
	VPXOR(CC3, BB3, BB3)
	VMOVDQA(CC3, tmpStoreAVX2)
	VPSLLD(Imm(7), BB0, CC3)
	VPSRLD(Imm(25), BB0, BB0)
	VPXOR(CC3, BB0, BB0)
	VPSLLD(Imm(7), BB1, CC3)
	VPSRLD(Imm(25), BB1, BB1)
	VPXOR(CC3, BB1, BB1)
	VPSLLD(Imm(7), BB2, CC3)
	VPSRLD(Imm(25), BB2, BB2)
	VPXOR(CC3, BB2, BB2)
	VPSLLD(Imm(7), BB3, CC3)
	VPSRLD(Imm(25), BB3, BB3)
	VPXOR(CC3, BB3, BB3)
	VMOVDQA(tmpStoreAVX2, CC3)
	VPALIGNR(Imm(12), BB0, BB0, BB0)
	VPALIGNR(Imm(12), BB1, BB1, BB1)
	VPALIGNR(Imm(12), BB2, BB2, BB2)
	VPALIGNR(Imm(12), BB3, BB3, BB3)
	VPALIGNR(Imm(8), CC0, CC0, CC0)
	VPALIGNR(Imm(8), CC1, CC1, CC1)
	VPALIGNR(Imm(8), CC2, CC2, CC2)
	VPALIGNR(Imm(8), CC3, CC3, CC3)
	VPALIGNR(Imm(4), DD0, DD0, DD0)
	VPALIGNR(Imm(4), DD1, DD1, DD1)
	VPALIGNR(Imm(4), DD2, DD2, DD2)
	VPALIGNR(Imm(4), DD3, DD3, DD3)
	INCQ(itr1)
	CMPQ(itr1, Imm(4))
	JLT(LabelRef("openAVX2Tail512LoopB"))

	CMPQ(itr1, Imm(10))
	JNE(LabelRef("openAVX2Tail512LoopA"))

	MOVQ(inl, itr1)
	SUBQ(U32(384), itr1)
	ANDQ(I8(-16), itr1)
}

func openAVX2Tail512HashLoop() {
	Label("openAVX2Tail512HashLoop")
	TESTQ(itr1, itr1)
	JE(LabelRef("openAVX2Tail512HashEnd"))
	polyAdd(Mem{Base: itr2}.Offset(0))
	polyMulAVX2()
	LEAQ(Mem{Base: itr2}.Offset(16), itr2)
	SUBQ(Imm(16), itr1)
	JMP(LabelRef("openAVX2Tail512HashLoop"))
}

func openAVX2Tail512HashEnd() {
	Label("openAVX2Tail512HashEnd")
	chacha20Constants := chacha20Constants_DATA()
	VPADDD(chacha20Constants, AA0, AA0)
	VPADDD(chacha20Constants, AA1, AA1)
	VPADDD(chacha20Constants, AA2, AA2)
	VPADDD(chacha20Constants, AA3, AA3)
	VPADDD(state1StoreAVX2, BB0, BB0)
	VPADDD(state1StoreAVX2, BB1, BB1)
	VPADDD(state1StoreAVX2, BB2, BB2)
	VPADDD(state1StoreAVX2, BB3, BB3)
	VPADDD(state2StoreAVX2, CC0, CC0)
	VPADDD(state2StoreAVX2, CC1, CC1)
	VPADDD(state2StoreAVX2, CC2, CC2)
	VPADDD(state2StoreAVX2, CC3, CC3)
	VPADDD(ctr0StoreAVX2, DD0, DD0)
	VPADDD(ctr1StoreAVX2, DD1, DD1)
	VPADDD(ctr2StoreAVX2, DD2, DD2)
	VPADDD(ctr3StoreAVX2, DD3, DD3)
	VMOVDQA(CC3, tmpStoreAVX2)
	VPERM2I128(Imm(0x02), AA0, BB0, CC3)
	VPERM2I128(Imm(0x13), AA0, BB0, BB0)
	VPERM2I128(Imm(0x02), CC0, DD0, AA0)
	VPERM2I128(Imm(0x13), CC0, DD0, CC0)
	VPXOR(Mem{Base: inp}.Offset(0*32), CC3, CC3)
	VPXOR(Mem{Base: inp}.Offset(1*32), AA0, AA0)
	VPXOR(Mem{Base: inp}.Offset(2*32), BB0, BB0)
	VPXOR(Mem{Base: inp}.Offset(3*32), CC0, CC0)
	VMOVDQU(CC3, Mem{Base: oup}.Offset(0*32))
	VMOVDQU(AA0, Mem{Base: oup}.Offset(1*32))
	VMOVDQU(BB0, Mem{Base: oup}.Offset(2*32))
	VMOVDQU(CC0, Mem{Base: oup}.Offset(3*32))
	VPERM2I128(Imm(0x02), AA1, BB1, AA0)
	VPERM2I128(Imm(0x02), CC1, DD1, BB0)
	VPERM2I128(Imm(0x13), AA1, BB1, CC0)
	VPERM2I128(Imm(0x13), CC1, DD1, DD0)
	VPXOR(Mem{Base: inp}.Offset(4*32), AA0, AA0)
	VPXOR(Mem{Base: inp}.Offset(5*32), BB0, BB0)
	VPXOR(Mem{Base: inp}.Offset(6*32), CC0, CC0)
	VPXOR(Mem{Base: inp}.Offset(7*32), DD0, DD0)
	VMOVDQU(AA0, Mem{Base: oup}.Offset(4*32))
	VMOVDQU(BB0, Mem{Base: oup}.Offset(5*32))
	VMOVDQU(CC0, Mem{Base: oup}.Offset(6*32))
	VMOVDQU(DD0, Mem{Base: oup}.Offset(7*32))
	VPERM2I128(Imm(0x02), AA2, BB2, AA0)
	VPERM2I128(Imm(0x02), CC2, DD2, BB0)
	VPERM2I128(Imm(0x13), AA2, BB2, CC0)
	VPERM2I128(Imm(0x13), CC2, DD2, DD0)
	VPXOR(Mem{Base: inp}.Offset(8*32), AA0, AA0)
	VPXOR(Mem{Base: inp}.Offset(9*32), BB0, BB0)
	VPXOR(Mem{Base: inp}.Offset(10*32), CC0, CC0)
	VPXOR(Mem{Base: inp}.Offset(11*32), DD0, DD0)
	VMOVDQU(AA0, Mem{Base: oup}.Offset(8*32))
	VMOVDQU(BB0, Mem{Base: oup}.Offset(9*32))
	VMOVDQU(CC0, Mem{Base: oup}.Offset(10*32))
	VMOVDQU(DD0, Mem{Base: oup}.Offset(11*32))
	VPERM2I128(Imm(0x02), AA3, BB3, AA0)
	VPERM2I128(Imm(0x02), tmpStoreAVX2, DD3, BB0)
	VPERM2I128(Imm(0x13), AA3, BB3, CC0)
	VPERM2I128(Imm(0x13), tmpStoreAVX2, DD3, DD0)

	LEAQ(Mem{Base: inp}.Offset(12*32), inp)
	LEAQ(Mem{Base: oup}.Offset(12*32), oup)
	SUBQ(U32(12*32), inl)

	JMP(LabelRef("openAVX2TailLoop"))
}

// ----------------------------------------------------------------------------
// ----------------------------------------------------------------------------

// Implements the following function fignature:
//
//	func chacha20Poly1305Seal(dst []byte, key []uint32, src, ad []byte)
func chacha20Poly1305Seal() {
	Implement("chacha20Poly1305Seal")
	Attributes(0)
	AllocLocal(288)

	MOVQ(RSP, RBP)
	ADDQ(Imm(32), RBP)
	ANDQ(I32(-32), RBP)
	Load(Param("dst").Base(), oup)
	Load(Param("key").Base(), keyp)
	Load(Param("src").Base(), inp)
	Load(Param("src").Len(), inl)
	Load(Param("ad").Base(), adp)

	CMPB(Mem{Symbol: Symbol{Name: ThatPeskyUnicodeDot + "useAVX2"}, Base: StaticBase}, Imm(1))
	JE(LabelRef("chacha20Poly1305Seal_AVX2"))

	Comment("Special optimization, for very short buffers")
	CMPQ(inl, Imm(128))
	JBE(LabelRef("sealSSE128"))

	Comment("In the seal case - prepare the poly key + 3 blocks of stream in the first iteration")
	chacha20Constants := chacha20Constants_DATA()
	MOVOU(chacha20Constants, A0)
	MOVOU(Mem{Base: keyp}.Offset(1*16), B0)
	MOVOU(Mem{Base: keyp}.Offset(2*16), C0)
	MOVOU(Mem{Base: keyp}.Offset(3*16), D0)

	Comment("Store state on stack for future use")
	MOVO(B0, state1Store)
	MOVO(C0, state2Store)

	Comment("Load state, increment counter blocks")
	MOVO(A0, A1)
	MOVO(B0, B1)
	MOVO(C0, C1)
	MOVO(D0, D1)
	sseIncMask := sseIncMask_DATA()
	PADDL(sseIncMask, D1)
	MOVO(A1, A2)
	MOVO(B1, B2)
	MOVO(C1, C2)
	MOVO(D1, D2)
	PADDL(sseIncMask, D2)
	MOVO(A2, A3)
	MOVO(B2, B3)
	MOVO(C2, C3)
	MOVO(D2, D3)
	PADDL(sseIncMask, D3)

	Comment("Store counters")
	MOVO(D0, ctr0Store)
	MOVO(D1, ctr1Store)
	MOVO(D2, ctr2Store)
	MOVO(D3, ctr3Store)
	MOVQ(U32(10), itr2)

	sealSSEIntroLoop()
	sealSSEMainLoop()

	// ----------------------------------------------------------------------------
	// Special optimization for the last 64 bytes of plaintext
	sealSSETail64()
	sealSSETail64LoopA()
	sealSSETail64LoopB()

	// ----------------------------------------------------------------------------
	// Special optimization for the last 128 bytes of plaintext
	sealSSETail128()
	sealSSETail128LoopA()
	sealSSETail128LoopB()

	// ----------------------------------------------------------------------------
	// Special optimization for the last 192 bytes of plaintext
	sealSSETail192()
	sealSSETail192LoopA()
	sealSSETail192LoopB()

	// ----------------------------------------------------------------------------
	// Special seal optimization for buffers smaller than 129 bytes
	sealSSE128()
	sealSSE128SealHash()
	sealSSE128Seal()
	sealSSETail()
	sealSSETailLoadLoop()
	sealSSEFinalize()

	// ----------------------------------------------------------------------------
	// ------------------------- AVX2 Code ----------------------------------------
	chacha20Poly1305Seal_AVX2()
	sealAVX2IntroLoop()
	sealAVX2MainLoop()
	sealAVX2InternalLoop()
	sealAVX2InternalLoopStart()

	// ----------------------------------------------------------------------------
	// Special optimization for buffers smaller than 193 bytes
	seal192AVX2()
	sealAVX2192InnerCipherLoop()
	sealAVX2ShortSeal()
	sealAVX2SealHash()
	sealAVX2ShortSealLoop()
	sealAVX2ShortTail32()
	sealAVX2ShortDone()

	// ----------------------------------------------------------------------------
	// Special optimization for buffers smaller than 321 bytes
	seal320AVX2()
	sealAVX2320InnerCipherLoop()

	// ----------------------------------------------------------------------------
	// Special optimization for the last 128 bytes of ciphertext
	sealAVX2Tail128()
	sealAVX2Tail128LoopA()
	sealAVX2Tail128LoopB()

	// ----------------------------------------------------------------------------
	// Special optimization for the last 256 bytes of ciphertext
	sealAVX2Tail256()
	sealAVX2Tail256LoopA()
	sealAVX2Tail256LoopB()

	// ----------------------------------------------------------------------------
	// Special optimization for the last 384 bytes of ciphertext
	sealAVX2Tail384()
	sealAVX2Tail384LoopA()
	sealAVX2Tail384LoopB()

	// ----------------------------------------------------------------------------
	// Special optimization for the last 512 bytes of ciphertext
	sealAVX2Tail512()
	sealAVX2Tail512LoopA()
	sealAVX2Tail512LoopB()
}

func sealSSEIntroLoop() {
	Label("sealSSEIntroLoop")
	MOVO(C3, tmpStore)
	chachaQR(A0, B0, C0, D0, C3)
	chachaQR(A1, B1, C1, D1, C3)
	chachaQR(A2, B2, C2, D2, C3)
	MOVO(tmpStore, C3)
	MOVO(C1, tmpStore)
	chachaQR(A3, B3, C3, D3, C1)
	MOVO(tmpStore, C1)
	shiftB0Left()
	shiftB1Left()
	shiftB2Left()
	shiftB3Left()
	shiftC0Left()
	shiftC1Left()
	shiftC2Left()
	shiftC3Left()
	shiftD0Left()
	shiftD1Left()
	shiftD2Left()
	shiftD3Left()

	MOVO(C3, tmpStore)
	chachaQR(A0, B0, C0, D0, C3)
	chachaQR(A1, B1, C1, D1, C3)
	chachaQR(A2, B2, C2, D2, C3)
	MOVO(tmpStore, C3)
	MOVO(C1, tmpStore)
	chachaQR(A3, B3, C3, D3, C1)
	MOVO(tmpStore, C1)
	shiftB0Right()
	shiftB1Right()
	shiftB2Right()
	shiftB3Right()
	shiftC0Right()
	shiftC1Right()
	shiftC2Right()
	shiftC3Right()
	shiftD0Right()
	shiftD1Right()
	shiftD2Right()
	shiftD3Right()
	DECQ(itr2)
	JNE(LabelRef("sealSSEIntroLoop"))

	Comment("Add in the state")
	chacha20Constants := chacha20Constants_DATA()
	PADDD(chacha20Constants, A0)
	PADDD(chacha20Constants, A1)
	PADDD(chacha20Constants, A2)
	PADDD(chacha20Constants, A3)
	PADDD(state1Store, B0)
	PADDD(state1Store, B1)
	PADDD(state1Store, B2)
	PADDD(state1Store, B3)
	PADDD(state2Store, C1)
	PADDD(state2Store, C2)
	PADDD(state2Store, C3)
	PADDD(ctr1Store, D1)
	PADDD(ctr2Store, D2)
	PADDD(ctr3Store, D3)

	Comment("Clamp and store the key")
	polyClampMask := polyClampMask_DATA()
	PAND(polyClampMask, A0)
	MOVO(A0, rStore)
	MOVO(B0, sStore)

	Comment("Hash AAD")
	MOVQ(NewParamAddr("ad_len", 80), itr2)
	CALL(LabelRef("polyHashADInternal<>(SB)"))

	MOVOU(Mem{Base: inp}.Offset(0*16), A0)
	MOVOU(Mem{Base: inp}.Offset(1*16), B0)
	MOVOU(Mem{Base: inp}.Offset(2*16), C0)
	MOVOU(Mem{Base: inp}.Offset(3*16), D0)
	PXOR(A0, A1)
	PXOR(B0, B1)
	PXOR(C0, C1)
	PXOR(D0, D1)
	MOVOU(A1, Mem{Base: oup}.Offset(0*16))
	MOVOU(B1, Mem{Base: oup}.Offset(1*16))
	MOVOU(C1, Mem{Base: oup}.Offset(2*16))
	MOVOU(D1, Mem{Base: oup}.Offset(3*16))
	MOVOU(Mem{Base: inp}.Offset(4*16), A0)
	MOVOU(Mem{Base: inp}.Offset(5*16), B0)
	MOVOU(Mem{Base: inp}.Offset(6*16), C0)
	MOVOU(Mem{Base: inp}.Offset(7*16), D0)
	PXOR(A0, A2)
	PXOR(B0, B2)
	PXOR(C0, C2)
	PXOR(D0, D2)
	MOVOU(A2, Mem{Base: oup}.Offset(4*16))
	MOVOU(B2, Mem{Base: oup}.Offset(5*16))
	MOVOU(C2, Mem{Base: oup}.Offset(6*16))
	MOVOU(D2, Mem{Base: oup}.Offset(7*16))

	MOVQ(U32(128), itr1)
	SUBQ(Imm(128), inl)
	LEAQ(Mem{Base: inp}.Offset(128), inp)

	MOVO(A3, A1)
	MOVO(B3, B1)
	MOVO(C3, C1)
	MOVO(D3, D1)

	CMPQ(inl, Imm(64))
	JBE(LabelRef("sealSSE128SealHash"))

	MOVOU(Mem{Base: inp}.Offset(0*16), A0)
	MOVOU(Mem{Base: inp}.Offset(1*16), B0)
	MOVOU(Mem{Base: inp}.Offset(2*16), C0)
	MOVOU(Mem{Base: inp}.Offset(3*16), D0)
	PXOR(A0, A3)
	PXOR(B0, B3)
	PXOR(C0, C3)
	PXOR(D0, D3)
	MOVOU(A3, Mem{Base: oup}.Offset(8*16))
	MOVOU(B3, Mem{Base: oup}.Offset(9*16))
	MOVOU(C3, Mem{Base: oup}.Offset(10*16))
	MOVOU(D3, Mem{Base: oup}.Offset(11*16))

	ADDQ(Imm(64), itr1)
	SUBQ(Imm(64), inl)
	LEAQ(Mem{Base: inp}.Offset(64), inp)

	MOVQ(U32(2), itr1)
	MOVQ(U32(8), itr2)

	CMPQ(inl, Imm(64))
	JBE(LabelRef("sealSSETail64"))
	CMPQ(inl, Imm(128))
	JBE(LabelRef("sealSSETail128"))
	CMPQ(inl, Imm(192))
	JBE(LabelRef("sealSSETail192"))
}

func sealSSEMainLoop() {
	Label("sealSSEMainLoop")
	Comment("Load state, increment counter blocks")
	chacha20Constants := chacha20Constants_DATA()
	MOVO(chacha20Constants, A0)
	MOVO(state1Store, B0)
	MOVO(state2Store, C0)
	MOVO(ctr3Store, D0)
	sseIncMask := sseIncMask_DATA()
	PADDL(sseIncMask, D0)
	MOVO(A0, A1)
	MOVO(B0, B1)
	MOVO(C0, C1)
	MOVO(D0, D1)
	PADDL(sseIncMask, D1)
	MOVO(A1, A2)
	MOVO(B1, B2)
	MOVO(C1, C2)
	MOVO(D1, D2)
	PADDL(sseIncMask, D2)
	MOVO(A2, A3)
	MOVO(B2, B3)
	MOVO(C2, C3)
	MOVO(D2, D3)
	PADDL(sseIncMask, D3)

	Comment("Store counters")
	MOVO(D0, ctr0Store)
	MOVO(D1, ctr1Store)
	MOVO(D2, ctr2Store)
	MOVO(D3, ctr3Store)

	Label("sealSSEInnerLoop")
	MOVO(C3, tmpStore)
	chachaQR(A0, B0, C0, D0, C3)
	chachaQR(A1, B1, C1, D1, C3)
	chachaQR(A2, B2, C2, D2, C3)
	MOVO(tmpStore, C3)
	MOVO(C1, tmpStore)
	chachaQR(A3, B3, C3, D3, C1)
	MOVO(tmpStore, C1)
	polyAdd(Mem{Base: oup}.Offset(0))
	shiftB0Left()
	shiftB1Left()
	shiftB2Left()
	shiftB3Left()
	shiftC0Left()
	shiftC1Left()
	shiftC2Left()
	shiftC3Left()
	shiftD0Left()
	shiftD1Left()
	shiftD2Left()
	shiftD3Left()
	polyMulStage1()
	polyMulStage2()
	LEAQ(Mem{Base: oup}.Offset(2*8), oup)
	MOVO(C3, tmpStore)
	chachaQR(A0, B0, C0, D0, C3)
	chachaQR(A1, B1, C1, D1, C3)
	chachaQR(A2, B2, C2, D2, C3)
	MOVO(tmpStore, C3)
	MOVO(C1, tmpStore)
	polyMulStage3()
	chachaQR(A3, B3, C3, D3, C1)
	MOVO(tmpStore, C1)
	polyMulReduceStage()
	shiftB0Right()
	shiftB1Right()
	shiftB2Right()
	shiftB3Right()
	shiftC0Right()
	shiftC1Right()
	shiftC2Right()
	shiftC3Right()
	shiftD0Right()
	shiftD1Right()
	shiftD2Right()
	shiftD3Right()
	DECQ(itr2)
	JGE(LabelRef("sealSSEInnerLoop"))
	polyAdd(Mem{Base: oup}.Offset(0))
	polyMul()
	LEAQ(Mem{Base: oup}.Offset(2*8), oup)
	DECQ(itr1)
	JG(LabelRef("sealSSEInnerLoop"))

	Comment("Add in the state")
	PADDD(chacha20Constants, A0)
	PADDD(chacha20Constants, A1)
	PADDD(chacha20Constants, A2)
	PADDD(chacha20Constants, A3)
	PADDD(state1Store, B0)
	PADDD(state1Store, B1)
	PADDD(state1Store, B2)
	PADDD(state1Store, B3)
	PADDD(state2Store, C0)
	PADDD(state2Store, C1)
	PADDD(state2Store, C2)
	PADDD(state2Store, C3)
	PADDD(ctr0Store, D0)
	PADDD(ctr1Store, D1)
	PADDD(ctr2Store, D2)
	PADDD(ctr3Store, D3)
	MOVO(D3, tmpStore)

	Comment("Load - xor - store")
	MOVOU(Mem{Base: inp}.Offset(0*16), D3)
	PXOR(D3, A0)
	MOVOU(Mem{Base: inp}.Offset(1*16), D3)
	PXOR(D3, B0)
	MOVOU(Mem{Base: inp}.Offset(2*16), D3)
	PXOR(D3, C0)
	MOVOU(Mem{Base: inp}.Offset(3*16), D3)
	PXOR(D3, D0)
	MOVOU(A0, Mem{Base: oup}.Offset(0*16))
	MOVOU(B0, Mem{Base: oup}.Offset(1*16))
	MOVOU(C0, Mem{Base: oup}.Offset(2*16))
	MOVOU(D0, Mem{Base: oup}.Offset(3*16))
	MOVO(tmpStore, D3)

	MOVOU(Mem{Base: inp}.Offset(4*16), A0)
	MOVOU(Mem{Base: inp}.Offset(5*16), B0)
	MOVOU(Mem{Base: inp}.Offset(6*16), C0)
	MOVOU(Mem{Base: inp}.Offset(7*16), D0)
	PXOR(A0, A1)
	PXOR(B0, B1)
	PXOR(C0, C1)
	PXOR(D0, D1)
	MOVOU(A1, Mem{Base: oup}.Offset(4*16))
	MOVOU(B1, Mem{Base: oup}.Offset(5*16))
	MOVOU(C1, Mem{Base: oup}.Offset(6*16))
	MOVOU(D1, Mem{Base: oup}.Offset(7*16))
	MOVOU(Mem{Base: inp}.Offset(8*16), A0)
	MOVOU(Mem{Base: inp}.Offset(9*16), B0)
	MOVOU(Mem{Base: inp}.Offset(10*16), C0)
	MOVOU(Mem{Base: inp}.Offset(11*16), D0)
	PXOR(A0, A2)
	PXOR(B0, B2)
	PXOR(C0, C2)
	PXOR(D0, D2)
	MOVOU(A2, Mem{Base: oup}.Offset(8*16))
	MOVOU(B2, Mem{Base: oup}.Offset(9*16))
	MOVOU(C2, Mem{Base: oup}.Offset(10*16))
	MOVOU(D2, Mem{Base: oup}.Offset(11*16))
	ADDQ(Imm(192), inp)
	MOVQ(U32(192), itr1)
	SUBQ(Imm(192), inl)
	MOVO(A3, A1)
	MOVO(B3, B1)
	MOVO(C3, C1)
	MOVO(D3, D1)
	CMPQ(inl, Imm(64))
	JBE(LabelRef("sealSSE128SealHash"))
	MOVOU(Mem{Base: inp}.Offset(0*16), A0)
	MOVOU(Mem{Base: inp}.Offset(1*16), B0)
	MOVOU(Mem{Base: inp}.Offset(2*16), C0)
	MOVOU(Mem{Base: inp}.Offset(3*16), D0)
	PXOR(A0, A3)
	PXOR(B0, B3)
	PXOR(C0, C3)
	PXOR(D0, D3)
	MOVOU(A3, Mem{Base: oup}.Offset(12*16))
	MOVOU(B3, Mem{Base: oup}.Offset(13*16))
	MOVOU(C3, Mem{Base: oup}.Offset(14*16))
	MOVOU(D3, Mem{Base: oup}.Offset(15*16))
	LEAQ(Mem{Base: inp}.Offset(64), inp)
	SUBQ(Imm(64), inl)
	MOVQ(U32(6), itr1)
	MOVQ(U32(4), itr2)
	CMPQ(inl, Imm(192))
	JG(LabelRef("sealSSEMainLoop"))

	MOVQ(inl, itr1)
	TESTQ(inl, inl)
	JE(LabelRef("sealSSE128SealHash"))
	MOVQ(U32(6), itr1)
	CMPQ(inl, Imm(64))
	JBE(LabelRef("sealSSETail64"))
	CMPQ(inl, Imm(128))
	JBE(LabelRef("sealSSETail128"))
	JMP(LabelRef("sealSSETail192"))
}

// ----------------------------------------------------------------------------
// Special optimization for the last 64 bytes of plaintext

// Need to encrypt up to 64 bytes - prepare single block, hash 192 or 256 bytes
func sealSSETail64() {
	Label("sealSSETail64")
	chacha20Constants := chacha20Constants_DATA()
	MOVO(chacha20Constants, A1)
	MOVO(state1Store, B1)
	MOVO(state2Store, C1)
	MOVO(ctr3Store, D1)
	sseIncMask := sseIncMask_DATA()
	PADDL(sseIncMask, D1)
	MOVO(D1, ctr0Store)
}

// Perform ChaCha rounds, while hashing the previously encrypted ciphertext
func sealSSETail64LoopA() {
	Label("sealSSETail64LoopA")
	polyAdd(Mem{Base: oup}.Offset(0))
	polyMul()
	LEAQ(Mem{Base: oup}.Offset(16), oup)
}

func sealSSETail64LoopB() {
	Label("sealSSETail64LoopB")
	chachaQR(A1, B1, C1, D1, T1)
	shiftB1Left()
	shiftC1Left()
	shiftD1Left()
	chachaQR(A1, B1, C1, D1, T1)
	shiftB1Right()
	shiftC1Right()
	shiftD1Right()
	polyAdd(Mem{Base: oup}.Offset(0))
	polyMul()
	LEAQ(Mem{Base: oup}.Offset(16), oup)

	DECQ(itr1)
	JG(LabelRef("sealSSETail64LoopA"))

	DECQ(itr2)
	JGE(LabelRef("sealSSETail64LoopB"))
	chacha20Constants := chacha20Constants_DATA()
	PADDL(chacha20Constants, A1)
	PADDL(state1Store, B1)
	PADDL(state2Store, C1)
	PADDL(ctr0Store, D1)

	JMP(LabelRef("sealSSE128Seal"))
}

// ----------------------------------------------------------------------------
// Special optimization for the last 128 bytes of plaintext

// Need to encrypt up to 128 bytes - prepare two blocks, hash 192 or 256 bytes
func sealSSETail128() {
	Label("sealSSETail128")
	chacha20Constants := chacha20Constants_DATA()
	MOVO(chacha20Constants, A0)
	MOVO(state1Store, B0)
	MOVO(state2Store, C0)
	MOVO(ctr3Store, D0)
	sseIncMask := sseIncMask_DATA()
	PADDL(sseIncMask, D0)
	MOVO(D0, ctr0Store)
	MOVO(A0, A1)
	MOVO(B0, B1)
	MOVO(C0, C1)
	MOVO(D0, D1)
	PADDL(sseIncMask, D1)
	MOVO(D1, ctr1Store)
}

// Perform ChaCha rounds, while hashing the previously encrypted ciphertext
func sealSSETail128LoopA() {
	Label("sealSSETail128LoopA")
	polyAdd(Mem{Base: oup}.Offset(0))
	polyMul()
	LEAQ(Mem{Base: oup}.Offset(16), oup)
}

func sealSSETail128LoopB() {
	Label("sealSSETail128LoopB")
	chachaQR(A0, B0, C0, D0, T0)
	chachaQR(A1, B1, C1, D1, T0)
	shiftB0Left()
	shiftC0Left()
	shiftD0Left()
	shiftB1Left()
	shiftC1Left()
	shiftD1Left()
	polyAdd(Mem{Base: oup}.Offset(0))
	polyMul()
	LEAQ(Mem{Base: oup}.Offset(16), oup)
	chachaQR(A0, B0, C0, D0, T0)
	chachaQR(A1, B1, C1, D1, T0)
	shiftB0Right()
	shiftC0Right()
	shiftD0Right()
	shiftB1Right()
	shiftC1Right()
	shiftD1Right()

	DECQ(itr1)
	JG(LabelRef("sealSSETail128LoopA"))

	DECQ(itr2)
	JGE(LabelRef("sealSSETail128LoopB"))

	chacha20Constants := chacha20Constants_DATA()
	PADDL(chacha20Constants, A0)
	PADDL(chacha20Constants, A1)
	PADDL(state1Store, B0)
	PADDL(state1Store, B1)
	PADDL(state2Store, C0)
	PADDL(state2Store, C1)
	PADDL(ctr0Store, D0)
	PADDL(ctr1Store, D1)

	MOVOU(Mem{Base: inp}.Offset(0*16), T0)
	MOVOU(Mem{Base: inp}.Offset(1*16), T1)
	MOVOU(Mem{Base: inp}.Offset(2*16), T2)
	MOVOU(Mem{Base: inp}.Offset(3*16), T3)
	PXOR(T0, A0)
	PXOR(T1, B0)
	PXOR(T2, C0)
	PXOR(T3, D0)
	MOVOU(A0, Mem{Base: oup}.Offset(0*16))
	MOVOU(B0, Mem{Base: oup}.Offset(1*16))
	MOVOU(C0, Mem{Base: oup}.Offset(2*16))
	MOVOU(D0, Mem{Base: oup}.Offset(3*16))

	MOVQ(U32(64), itr1)
	LEAQ(Mem{Base: inp}.Offset(64), inp)
	SUBQ(Imm(64), inl)

	JMP(LabelRef("sealSSE128SealHash"))
}

// ----------------------------------------------------------------------------
// Special optimization for the last 192 bytes of plaintext

// Need to encrypt up to 192 bytes - prepare three blocks, hash 192 or 256 bytes
func sealSSETail192() {
	Label("sealSSETail192")
	chacha20Constants := chacha20Constants_DATA()
	MOVO(chacha20Constants, A0)
	MOVO(state1Store, B0)
	MOVO(state2Store, C0)
	MOVO(ctr3Store, D0)
	sseIncMask := sseIncMask_DATA()
	PADDL(sseIncMask, D0)
	MOVO(D0, ctr0Store)
	MOVO(A0, A1)
	MOVO(B0, B1)
	MOVO(C0, C1)
	MOVO(D0, D1)
	PADDL(sseIncMask, D1)
	MOVO(D1, ctr1Store)
	MOVO(A1, A2)
	MOVO(B1, B2)
	MOVO(C1, C2)
	MOVO(D1, D2)
	PADDL(sseIncMask, D2)
	MOVO(D2, ctr2Store)
}

// Perform ChaCha rounds, while hashing the previously encrypted ciphertext
func sealSSETail192LoopA() {
	Label("sealSSETail192LoopA")
	polyAdd(Mem{Base: oup}.Offset(0))
	polyMul()
	LEAQ(Mem{Base: oup}.Offset(16), oup)
}

func sealSSETail192LoopB() {
	Label("sealSSETail192LoopB")
	chachaQR(A0, B0, C0, D0, T0)
	chachaQR(A1, B1, C1, D1, T0)
	chachaQR(A2, B2, C2, D2, T0)
	shiftB0Left()
	shiftC0Left()
	shiftD0Left()
	shiftB1Left()
	shiftC1Left()
	shiftD1Left()
	shiftB2Left()
	shiftC2Left()
	shiftD2Left()

	polyAdd(Mem{Base: oup}.Offset(0))
	polyMul()
	LEAQ(Mem{Base: oup}.Offset(16), oup)

	chachaQR(A0, B0, C0, D0, T0)
	chachaQR(A1, B1, C1, D1, T0)
	chachaQR(A2, B2, C2, D2, T0)
	shiftB0Right()
	shiftC0Right()
	shiftD0Right()
	shiftB1Right()
	shiftC1Right()
	shiftD1Right()
	shiftB2Right()
	shiftC2Right()
	shiftD2Right()

	DECQ(itr1)
	JG(LabelRef("sealSSETail192LoopA"))

	DECQ(itr2)
	JGE(LabelRef("sealSSETail192LoopB"))

	chacha20Constants := chacha20Constants_DATA()
	PADDL(chacha20Constants, A0)
	PADDL(chacha20Constants, A1)
	PADDL(chacha20Constants, A2)
	PADDL(state1Store, B0)
	PADDL(state1Store, B1)
	PADDL(state1Store, B2)
	PADDL(state2Store, C0)
	PADDL(state2Store, C1)
	PADDL(state2Store, C2)
	PADDL(ctr0Store, D0)
	PADDL(ctr1Store, D1)
	PADDL(ctr2Store, D2)

	MOVOU(Mem{Base: inp}.Offset(0*16), T0)
	MOVOU(Mem{Base: inp}.Offset(1*16), T1)
	MOVOU(Mem{Base: inp}.Offset(2*16), T2)
	MOVOU(Mem{Base: inp}.Offset(3*16), T3)
	PXOR(T0, A0)
	PXOR(T1, B0)
	PXOR(T2, C0)
	PXOR(T3, D0)
	MOVOU(A0, Mem{Base: oup}.Offset(0*16))
	MOVOU(B0, Mem{Base: oup}.Offset(1*16))
	MOVOU(C0, Mem{Base: oup}.Offset(2*16))
	MOVOU(D0, Mem{Base: oup}.Offset(3*16))
	MOVOU(Mem{Base: inp}.Offset(4*16), T0)
	MOVOU(Mem{Base: inp}.Offset(5*16), T1)
	MOVOU(Mem{Base: inp}.Offset(6*16), T2)
	MOVOU(Mem{Base: inp}.Offset(7*16), T3)
	PXOR(T0, A1)
	PXOR(T1, B1)
	PXOR(T2, C1)
	PXOR(T3, D1)
	MOVOU(A1, Mem{Base: oup}.Offset(4*16))
	MOVOU(B1, Mem{Base: oup}.Offset(5*16))
	MOVOU(C1, Mem{Base: oup}.Offset(6*16))
	MOVOU(D1, Mem{Base: oup}.Offset(7*16))

	MOVO(A2, A1)
	MOVO(B2, B1)
	MOVO(C2, C1)
	MOVO(D2, D1)
	MOVQ(U32(128), itr1)
	LEAQ(Mem{Base: inp}.Offset(128), inp)
	SUBQ(Imm(128), inl)

	JMP(LabelRef("sealSSE128SealHash"))
}

// ----------------------------------------------------------------------------
// Special seal optimization for buffers smaller than 129 bytes

// For up to 128 bytes of ciphertext and 64 bytes for the poly key, we require to process three blocks
func sealSSE128() {
	Label("sealSSE128")
	chacha20Constants := chacha20Constants_DATA()
	MOVOU(chacha20Constants, A0)
	MOVOU(Mem{Base: keyp}.Offset(1*16), B0)
	MOVOU(Mem{Base: keyp}.Offset(2*16), C0)
	MOVOU(Mem{Base: keyp}.Offset(3*16), D0)
	MOVO(A0, A1)
	MOVO(B0, B1)
	MOVO(C0, C1)
	MOVO(D0, D1)
	sseIncMask := sseIncMask_DATA()
	PADDL(sseIncMask, D1)
	MOVO(A1, A2)
	MOVO(B1, B2)
	MOVO(C1, C2)
	MOVO(D1, D2)
	PADDL(sseIncMask, D2)
	MOVO(B0, T1)
	MOVO(C0, T2)
	MOVO(D1, T3)
	MOVQ(U32(10), itr2)

	Label("sealSSE128InnerCipherLoop")
	chachaQR(A0, B0, C0, D0, T0)
	chachaQR(A1, B1, C1, D1, T0)
	chachaQR(A2, B2, C2, D2, T0)
	shiftB0Left()
	shiftB1Left()
	shiftB2Left()
	shiftC0Left()
	shiftC1Left()
	shiftC2Left()
	shiftD0Left()
	shiftD1Left()
	shiftD2Left()
	chachaQR(A0, B0, C0, D0, T0)
	chachaQR(A1, B1, C1, D1, T0)
	chachaQR(A2, B2, C2, D2, T0)
	shiftB0Right()
	shiftB1Right()
	shiftB2Right()
	shiftC0Right()
	shiftC1Right()
	shiftC2Right()
	shiftD0Right()
	shiftD1Right()
	shiftD2Right()
	DECQ(itr2)
	JNE(LabelRef("sealSSE128InnerCipherLoop"))

	Comment("A0|B0 hold the Poly1305 32-byte key, C0,D0 can be discarded")
	PADDL(chacha20Constants, A0)
	PADDL(chacha20Constants, A1)
	PADDL(chacha20Constants, A2)
	PADDL(T1, B0)
	PADDL(T1, B1)
	PADDL(T1, B2)
	PADDL(T2, C1)
	PADDL(T2, C2)
	PADDL(T3, D1)
	PADDL(sseIncMask, T3)
	PADDL(T3, D2)
	polyClampMask := polyClampMask_DATA()
	PAND(polyClampMask, A0)
	MOVOU(A0, rStore)
	MOVOU(B0, sStore)

	Comment("Hash")
	MOVQ(NewParamAddr("ad_len", 80), itr2)
	CALL(LabelRef("polyHashADInternal<>(SB)"))
	XORQ(itr1, itr1)
}

// itr1 holds the number of bytes encrypted but not yet hashed
func sealSSE128SealHash() {
	Label("sealSSE128SealHash")
	CMPQ(itr1, Imm(16))
	JB(LabelRef("sealSSE128Seal"))
	polyAdd(Mem{Base: oup}.Offset(0))
	polyMul()

	SUBQ(Imm(16), itr1)
	ADDQ(Imm(16), oup)

	JMP(LabelRef("sealSSE128SealHash"))
}

func sealSSE128Seal() {
	Label("sealSSE128Seal")
	CMPQ(inl, Imm(16))
	JB(LabelRef("sealSSETail"))
	SUBQ(Imm(16), inl)

	Comment("Load for decryption")
	MOVOU(Mem{Base: inp}, T0)
	PXOR(T0, A1)
	MOVOU(A1, Mem{Base: oup})
	LEAQ(Mem{Base: inp}.Offset(1*16), inp)
	LEAQ(Mem{Base: oup}.Offset(1*16), oup)

	Comment("Extract for hashing")
	MOVQ(A1, t0)
	PSRLDQ(Imm(8), A1)
	MOVQ(A1, t1)
	ADDQ(t0, acc0)
	ADCQ(t1, acc1)
	ADCQ(Imm(1), acc2)
	polyMul()

	Comment("Shift the stream \"left\"")
	MOVO(B1, A1)
	MOVO(C1, B1)
	MOVO(D1, C1)
	MOVO(A2, D1)
	MOVO(B2, A2)
	MOVO(C2, B2)
	MOVO(D2, C2)
	JMP(LabelRef("sealSSE128Seal"))
}

func sealSSETail() {
	Label("sealSSETail")
	TESTQ(inl, inl)
	JE(LabelRef("sealSSEFinalize"))

	Comment("We can only load the PT one byte at a time to avoid read after end of buffer")
	MOVQ(inl, itr2)
	SHLQ(Imm(4), itr2)
	andMask := andMask_DATA()
	LEAQ(andMask, t0)
	MOVQ(inl, itr1)
	LEAQ(Mem{Base: inp, Index: inl, Scale: 1}.Offset(-1), inp)
	XORQ(t2, t2)
	XORQ(t3, t3)
	XORQ(RAX, RAX)
}

func sealSSETailLoadLoop() {
	Label("sealSSETailLoadLoop")
	SHLQ(Imm(8), t2, t3)
	SHLQ(Imm(8), t2)
	// Hack to get Avo to emit:
	// 	MOVB (inp), AX
	Instruction(&ir.Instruction{Opcode: "MOVB", Operands: []Op{Mem{Base: inp}, AX}})
	XORQ(RAX, t2)
	LEAQ(Mem{Base: inp}.Offset(-1), inp)
	DECQ(itr1)
	JNE(LabelRef("sealSSETailLoadLoop"))
	MOVQ(t2, tmpStore.Offset(0))
	MOVQ(t3, tmpStore.Offset(8))
	PXOR(tmpStore.Offset(0), A1)
	MOVOU(A1, Mem{Base: oup})
	MOVOU(Mem{Base: t0, Index: itr2, Scale: 1}.Offset(-16), T0)
	PAND(T0, A1)
	MOVQ(A1, t0)
	PSRLDQ(Imm(8), A1)
	MOVQ(A1, t1)
	ADDQ(t0, acc0)
	ADCQ(t1, acc1)
	ADCQ(Imm(1), acc2)
	polyMul()

	ADDQ(inl, oup)
}

func sealSSEFinalize() {
	Label("sealSSEFinalize")
	Comment("Hash in the buffer lengths")
	ADDQ(NewParamAddr("ad_len", 80), acc0)
	ADCQ(NewParamAddr("src_len", 56), acc1)
	ADCQ(Imm(1), acc2)
	polyMul()

	Comment("Final reduce")
	MOVQ(acc0, t0)
	MOVQ(acc1, t1)
	MOVQ(acc2, t2)
	SUBQ(I8(-5), acc0)
	SBBQ(I8(-1), acc1)
	SBBQ(Imm(3), acc2)
	CMOVQCS(t0, acc0)
	CMOVQCS(t1, acc1)
	CMOVQCS(t2, acc2)

	Comment("Add in the \"s\" part of the key")
	ADDQ(sStore.Offset(0), acc0)
	ADCQ(sStore.Offset(8), acc1)

	Comment("Finally store the tag at the end of the message")
	MOVQ(acc0, Mem{Base: oup}.Offset(0*8))
	MOVQ(acc1, Mem{Base: oup}.Offset(1*8))
	RET()
}

// ----------------------------------------------------------------------------
// ------------------------- AVX2 Code ----------------------------------------

func chacha20Poly1305Seal_AVX2() {
	Label("chacha20Poly1305Seal_AVX2")
	VZEROUPPER()
	chacha20Constants := chacha20Constants_DATA()
	VMOVDQU(chacha20Constants, AA0)
	VBROADCASTI128_16_R8_YMM14()
	VBROADCASTI128_32_R8_YMM12()
	VBROADCASTI128_48_R8_YMM4()
	avx2InitMask := avx2InitMask_DATA()
	VPADDD(avx2InitMask, DD0, DD0)

	Comment("Special optimizations, for very short buffers")
	CMPQ(inl, U32(192))
	JBE(LabelRef("seal192AVX2"))
	CMPQ(inl, U32(320))
	JBE(LabelRef("seal320AVX2"))

	Comment("For the general key prepare the key first - as a byproduct we have 64 bytes of cipher stream")
	VMOVDQA(AA0, AA1)
	VMOVDQA(AA0, AA2)
	VMOVDQA(AA0, AA3)
	VMOVDQA(BB0, BB1)
	VMOVDQA(BB0, BB2)
	VMOVDQA(BB0, BB3)
	VMOVDQA(BB0, state1StoreAVX2)
	VMOVDQA(CC0, CC1)
	VMOVDQA(CC0, CC2)
	VMOVDQA(CC0, CC3)
	VMOVDQA(CC0, state2StoreAVX2)
	avx2IncMask := avx2IncMask_DATA()
	VPADDD(avx2IncMask, DD0, DD1)
	VMOVDQA(DD0, ctr0StoreAVX2)
	VPADDD(avx2IncMask, DD1, DD2)
	VMOVDQA(DD1, ctr1StoreAVX2)
	VPADDD(avx2IncMask, DD2, DD3)
	VMOVDQA(DD2, ctr2StoreAVX2)
	VMOVDQA(DD3, ctr3StoreAVX2)
	MOVQ(U32(10), itr2)
}

func sealAVX2IntroLoop() {
	Label("sealAVX2IntroLoop")
	VMOVDQA(CC3, tmpStoreAVX2)
	chachaQR_AVX2(AA0, BB0, CC0, DD0, CC3)
	chachaQR_AVX2(AA1, BB1, CC1, DD1, CC3)
	chachaQR_AVX2(AA2, BB2, CC2, DD2, CC3)
	VMOVDQA(tmpStoreAVX2, CC3)
	VMOVDQA(CC1, tmpStoreAVX2)
	chachaQR_AVX2(AA3, BB3, CC3, DD3, CC1)
	VMOVDQA(tmpStoreAVX2, CC1)

	VPALIGNR(Imm(4), BB0, BB0, BB0)
	VPALIGNR(Imm(8), CC0, CC0, CC0)
	VPALIGNR(Imm(12), DD0, DD0, DD0)
	VPALIGNR(Imm(4), BB1, BB1, BB1)
	VPALIGNR(Imm(8), CC1, CC1, CC1)
	VPALIGNR(Imm(12), DD1, DD1, DD1)
	VPALIGNR(Imm(4), BB2, BB2, BB2)
	VPALIGNR(Imm(8), CC2, CC2, CC2)
	VPALIGNR(Imm(12), DD2, DD2, DD2)
	VPALIGNR(Imm(4), BB3, BB3, BB3)
	VPALIGNR(Imm(8), CC3, CC3, CC3)
	VPALIGNR(Imm(12), DD3, DD3, DD3)

	VMOVDQA(CC3, tmpStoreAVX2)
	chachaQR_AVX2(AA0, BB0, CC0, DD0, CC3)
	chachaQR_AVX2(AA1, BB1, CC1, DD1, CC3)
	chachaQR_AVX2(AA2, BB2, CC2, DD2, CC3)
	VMOVDQA(tmpStoreAVX2, CC3)
	VMOVDQA(CC1, tmpStoreAVX2)
	chachaQR_AVX2(AA3, BB3, CC3, DD3, CC1)
	VMOVDQA(tmpStoreAVX2, CC1)

	VPALIGNR(Imm(12), BB0, BB0, BB0)
	VPALIGNR(Imm(8), CC0, CC0, CC0)
	VPALIGNR(Imm(4), DD0, DD0, DD0)
	VPALIGNR(Imm(12), BB1, BB1, BB1)
	VPALIGNR(Imm(8), CC1, CC1, CC1)
	VPALIGNR(Imm(4), DD1, DD1, DD1)
	VPALIGNR(Imm(12), BB2, BB2, BB2)
	VPALIGNR(Imm(8), CC2, CC2, CC2)
	VPALIGNR(Imm(4), DD2, DD2, DD2)
	VPALIGNR(Imm(12), BB3, BB3, BB3)
	VPALIGNR(Imm(8), CC3, CC3, CC3)
	VPALIGNR(Imm(4), DD3, DD3, DD3)
	DECQ(itr2)
	JNE(LabelRef("sealAVX2IntroLoop"))

	chacha20Constants := chacha20Constants_DATA()
	VPADDD(chacha20Constants, AA0, AA0)
	VPADDD(chacha20Constants, AA1, AA1)
	VPADDD(chacha20Constants, AA2, AA2)
	VPADDD(chacha20Constants, AA3, AA3)
	VPADDD(state1StoreAVX2, BB0, BB0)
	VPADDD(state1StoreAVX2, BB1, BB1)
	VPADDD(state1StoreAVX2, BB2, BB2)
	VPADDD(state1StoreAVX2, BB3, BB3)
	VPADDD(state2StoreAVX2, CC0, CC0)
	VPADDD(state2StoreAVX2, CC1, CC1)
	VPADDD(state2StoreAVX2, CC2, CC2)
	VPADDD(state2StoreAVX2, CC3, CC3)
	VPADDD(ctr0StoreAVX2, DD0, DD0)
	VPADDD(ctr1StoreAVX2, DD1, DD1)
	VPADDD(ctr2StoreAVX2, DD2, DD2)
	VPADDD(ctr3StoreAVX2, DD3, DD3)

	VPERM2I128(Imm(0x13), CC0, DD0, CC0)
	VPERM2I128(Imm(0x02), AA0, BB0, DD0)
	VPERM2I128(Imm(0x13), AA0, BB0, AA0)

	Comment("Clamp and store poly key")
	polyClampMask := polyClampMask_DATA()
	VPAND(polyClampMask, DD0, DD0)
	VMOVDQA(DD0, rsStoreAVX2)

	Comment("Hash AD")
	MOVQ(NewParamAddr("ad_len", 80), itr2)
	CALL(LabelRef("polyHashADInternal<>(SB)"))

	Comment("Can store at least 320 bytes")
	VPXOR(Mem{Base: inp}.Offset(0*32), AA0, AA0)
	VPXOR(Mem{Base: inp}.Offset(1*32), CC0, CC0)
	VMOVDQU(AA0, Mem{Base: oup}.Offset(0*32))
	VMOVDQU(CC0, Mem{Base: oup}.Offset(1*32))

	VPERM2I128(Imm(0x02), AA1, BB1, AA0)
	VPERM2I128(Imm(0x02), CC1, DD1, BB0)
	VPERM2I128(Imm(0x13), AA1, BB1, CC0)
	VPERM2I128(Imm(0x13), CC1, DD1, DD0)
	VPXOR(Mem{Base: inp}.Offset(2*32), AA0, AA0)
	VPXOR(Mem{Base: inp}.Offset(3*32), BB0, BB0)
	VPXOR(Mem{Base: inp}.Offset(4*32), CC0, CC0)
	VPXOR(Mem{Base: inp}.Offset(5*32), DD0, DD0)
	VMOVDQU(AA0, Mem{Base: oup}.Offset(2*32))
	VMOVDQU(BB0, Mem{Base: oup}.Offset(3*32))
	VMOVDQU(CC0, Mem{Base: oup}.Offset(4*32))
	VMOVDQU(DD0, Mem{Base: oup}.Offset(5*32))
	VPERM2I128(Imm(0x02), AA2, BB2, AA0)
	VPERM2I128(Imm(0x02), CC2, DD2, BB0)
	VPERM2I128(Imm(0x13), AA2, BB2, CC0)
	VPERM2I128(Imm(0x13), CC2, DD2, DD0)
	VPXOR(Mem{Base: inp}.Offset(6*32), AA0, AA0)
	VPXOR(Mem{Base: inp}.Offset(7*32), BB0, BB0)
	VPXOR(Mem{Base: inp}.Offset(8*32), CC0, CC0)
	VPXOR(Mem{Base: inp}.Offset(9*32), DD0, DD0)
	VMOVDQU(AA0, Mem{Base: oup}.Offset(6*32))
	VMOVDQU(BB0, Mem{Base: oup}.Offset(7*32))
	VMOVDQU(CC0, Mem{Base: oup}.Offset(8*32))
	VMOVDQU(DD0, Mem{Base: oup}.Offset(9*32))

	MOVQ(U32(320), itr1)
	SUBQ(U32(320), inl)
	LEAQ(Mem{Base: inp}.Offset(320), inp)

	VPERM2I128(Imm(0x02), AA3, BB3, AA0)
	VPERM2I128(Imm(0x02), CC3, DD3, BB0)
	VPERM2I128(Imm(0x13), AA3, BB3, CC0)
	VPERM2I128(Imm(0x13), CC3, DD3, DD0)
	CMPQ(inl, Imm(128))
	JBE(LabelRef("sealAVX2SealHash"))

	VPXOR(Mem{Base: inp}.Offset(0*32), AA0, AA0)
	VPXOR(Mem{Base: inp}.Offset(1*32), BB0, BB0)
	VPXOR(Mem{Base: inp}.Offset(2*32), CC0, CC0)
	VPXOR(Mem{Base: inp}.Offset(3*32), DD0, DD0)
	VMOVDQU(AA0, Mem{Base: oup}.Offset(10*32))
	VMOVDQU(BB0, Mem{Base: oup}.Offset(11*32))
	VMOVDQU(CC0, Mem{Base: oup}.Offset(12*32))
	VMOVDQU(DD0, Mem{Base: oup}.Offset(13*32))
	SUBQ(Imm(128), inl)
	LEAQ(Mem{Base: inp}.Offset(128), inp)

	MOVQ(U32(8), itr1)
	MOVQ(U32(2), itr2)

	CMPQ(inl, Imm(128))
	JBE(LabelRef("sealAVX2Tail128"))
	CMPQ(inl, U32(256))
	JBE(LabelRef("sealAVX2Tail256"))
	CMPQ(inl, U32(384))
	JBE(LabelRef("sealAVX2Tail384"))
	CMPQ(inl, U32(512))
	JBE(LabelRef("sealAVX2Tail512"))

	Comment("We have 448 bytes to hash, but main loop hashes 512 bytes at a time - perform some rounds, before the main loop")
	VMOVDQA(chacha20Constants, AA0)
	VMOVDQA(AA0, AA1)
	VMOVDQA(AA0, AA2)
	VMOVDQA(AA0, AA3)
	VMOVDQA(state1StoreAVX2, BB0)
	VMOVDQA(BB0, BB1)
	VMOVDQA(BB0, BB2)
	VMOVDQA(BB0, BB3)
	VMOVDQA(state2StoreAVX2, CC0)
	VMOVDQA(CC0, CC1)
	VMOVDQA(CC0, CC2)
	VMOVDQA(CC0, CC3)
	VMOVDQA(ctr3StoreAVX2, DD0)
	avx2IncMask := avx2IncMask_DATA()
	VPADDD(avx2IncMask, DD0, DD0)
	VPADDD(avx2IncMask, DD0, DD1)
	VPADDD(avx2IncMask, DD1, DD2)
	VPADDD(avx2IncMask, DD2, DD3)
	VMOVDQA(DD0, ctr0StoreAVX2)
	VMOVDQA(DD1, ctr1StoreAVX2)
	VMOVDQA(DD2, ctr2StoreAVX2)
	VMOVDQA(DD3, ctr3StoreAVX2)

	VMOVDQA(CC3, tmpStoreAVX2)
	chachaQR_AVX2(AA0, BB0, CC0, DD0, CC3)
	chachaQR_AVX2(AA1, BB1, CC1, DD1, CC3)
	chachaQR_AVX2(AA2, BB2, CC2, DD2, CC3)
	VMOVDQA(tmpStoreAVX2, CC3)
	VMOVDQA(CC1, tmpStoreAVX2)
	chachaQR_AVX2(AA3, BB3, CC3, DD3, CC1)
	VMOVDQA(tmpStoreAVX2, CC1)

	VPALIGNR(Imm(4), BB0, BB0, BB0)
	VPALIGNR(Imm(8), CC0, CC0, CC0)
	VPALIGNR(Imm(12), DD0, DD0, DD0)
	VPALIGNR(Imm(4), BB1, BB1, BB1)
	VPALIGNR(Imm(8), CC1, CC1, CC1)
	VPALIGNR(Imm(12), DD1, DD1, DD1)
	VPALIGNR(Imm(4), BB2, BB2, BB2)
	VPALIGNR(Imm(8), CC2, CC2, CC2)
	VPALIGNR(Imm(12), DD2, DD2, DD2)
	VPALIGNR(Imm(4), BB3, BB3, BB3)
	VPALIGNR(Imm(8), CC3, CC3, CC3)
	VPALIGNR(Imm(12), DD3, DD3, DD3)

	VMOVDQA(CC3, tmpStoreAVX2)
	chachaQR_AVX2(AA0, BB0, CC0, DD0, CC3)
	chachaQR_AVX2(AA1, BB1, CC1, DD1, CC3)
	chachaQR_AVX2(AA2, BB2, CC2, DD2, CC3)
	VMOVDQA(tmpStoreAVX2, CC3)
	VMOVDQA(CC1, tmpStoreAVX2)
	chachaQR_AVX2(AA3, BB3, CC3, DD3, CC1)
	VMOVDQA(tmpStoreAVX2, CC1)

	VPALIGNR(Imm(12), BB0, BB0, BB0)
	VPALIGNR(Imm(8), CC0, CC0, CC0)
	VPALIGNR(Imm(4), DD0, DD0, DD0)
	VPALIGNR(Imm(12), BB1, BB1, BB1)
	VPALIGNR(Imm(8), CC1, CC1, CC1)
	VPALIGNR(Imm(4), DD1, DD1, DD1)
	VPALIGNR(Imm(12), BB2, BB2, BB2)
	VPALIGNR(Imm(8), CC2, CC2, CC2)
	VPALIGNR(Imm(4), DD2, DD2, DD2)
	VPALIGNR(Imm(12), BB3, BB3, BB3)
	VPALIGNR(Imm(8), CC3, CC3, CC3)
	VPALIGNR(Imm(4), DD3, DD3, DD3)
	VPADDD(BB0, AA0, AA0)
	VPADDD(BB1, AA1, AA1)
	VPADDD(BB2, AA2, AA2)
	VPADDD(BB3, AA3, AA3)
	VPXOR(AA0, DD0, DD0)
	VPXOR(AA1, DD1, DD1)
	VPXOR(AA2, DD2, DD2)
	VPXOR(AA3, DD3, DD3)
	rol16 := rol16_DATA()
	VPSHUFB(rol16, DD0, DD0)
	VPSHUFB(rol16, DD1, DD1)
	VPSHUFB(rol16, DD2, DD2)
	VPSHUFB(rol16, DD3, DD3)
	VPADDD(DD0, CC0, CC0)
	VPADDD(DD1, CC1, CC1)
	VPADDD(DD2, CC2, CC2)
	VPADDD(DD3, CC3, CC3)
	VPXOR(CC0, BB0, BB0)
	VPXOR(CC1, BB1, BB1)
	VPXOR(CC2, BB2, BB2)
	VPXOR(CC3, BB3, BB3)
	VMOVDQA(CC3, tmpStoreAVX2)
	VPSLLD(Imm(12), BB0, CC3)
	VPSRLD(Imm(20), BB0, BB0)
	VPXOR(CC3, BB0, BB0)
	VPSLLD(Imm(12), BB1, CC3)
	VPSRLD(Imm(20), BB1, BB1)
	VPXOR(CC3, BB1, BB1)
	VPSLLD(Imm(12), BB2, CC3)
	VPSRLD(Imm(20), BB2, BB2)
	VPXOR(CC3, BB2, BB2)
	VPSLLD(Imm(12), BB3, CC3)
	VPSRLD(Imm(20), BB3, BB3)
	VPXOR(CC3, BB3, BB3)
	VMOVDQA(tmpStoreAVX2, CC3)

	SUBQ(Imm(16), oup) // Adjust the pointer
	MOVQ(U32(9), itr1)
	JMP(LabelRef("sealAVX2InternalLoopStart"))
}

// Load state, increment counter blocks, store the incremented counters
func sealAVX2MainLoop() {
	Label("sealAVX2MainLoop")
	chacha20Constants := chacha20Constants_DATA()
	VMOVDQU(chacha20Constants, AA0)
	VMOVDQA(AA0, AA1)
	VMOVDQA(AA0, AA2)
	VMOVDQA(AA0, AA3)
	VMOVDQA(state1StoreAVX2, BB0)
	VMOVDQA(BB0, BB1)
	VMOVDQA(BB0, BB2)
	VMOVDQA(BB0, BB3)
	VMOVDQA(state2StoreAVX2, CC0)
	VMOVDQA(CC0, CC1)
	VMOVDQA(CC0, CC2)
	VMOVDQA(CC0, CC3)
	VMOVDQA(ctr3StoreAVX2, DD0)
	avx2IncMask := avx2IncMask_DATA()
	VPADDD(avx2IncMask, DD0, DD0)
	VPADDD(avx2IncMask, DD0, DD1)
	VPADDD(avx2IncMask, DD1, DD2)
	VPADDD(avx2IncMask, DD2, DD3)
	VMOVDQA(DD0, ctr0StoreAVX2)
	VMOVDQA(DD1, ctr1StoreAVX2)
	VMOVDQA(DD2, ctr2StoreAVX2)
	VMOVDQA(DD3, ctr3StoreAVX2)
	MOVQ(U32(10), itr1)
}

func sealAVX2InternalLoop() {
	Label("sealAVX2InternalLoop")
	polyAdd(Mem{Base: oup}.Offset(0 * 8))
	VPADDD(BB0, AA0, AA0)
	VPADDD(BB1, AA1, AA1)
	VPADDD(BB2, AA2, AA2)
	VPADDD(BB3, AA3, AA3)
	polyMulStage1_AVX2()
	VPXOR(AA0, DD0, DD0)
	VPXOR(AA1, DD1, DD1)
	VPXOR(AA2, DD2, DD2)
	VPXOR(AA3, DD3, DD3)
	rol16 := rol16_DATA()
	VPSHUFB(rol16, DD0, DD0)
	VPSHUFB(rol16, DD1, DD1)
	VPSHUFB(rol16, DD2, DD2)
	VPSHUFB(rol16, DD3, DD3)
	polyMulStage2_AVX2()
	VPADDD(DD0, CC0, CC0)
	VPADDD(DD1, CC1, CC1)
	VPADDD(DD2, CC2, CC2)
	VPADDD(DD3, CC3, CC3)
	VPXOR(CC0, BB0, BB0)
	VPXOR(CC1, BB1, BB1)
	VPXOR(CC2, BB2, BB2)
	VPXOR(CC3, BB3, BB3)
	polyMulStage3_AVX2()
	VMOVDQA(CC3, tmpStoreAVX2)
	VPSLLD(Imm(12), BB0, CC3)
	VPSRLD(Imm(20), BB0, BB0)
	VPXOR(CC3, BB0, BB0)
	VPSLLD(Imm(12), BB1, CC3)
	VPSRLD(Imm(20), BB1, BB1)
	VPXOR(CC3, BB1, BB1)
	VPSLLD(Imm(12), BB2, CC3)
	VPSRLD(Imm(20), BB2, BB2)
	VPXOR(CC3, BB2, BB2)
	VPSLLD(Imm(12), BB3, CC3)
	VPSRLD(Imm(20), BB3, BB3)
	VPXOR(CC3, BB3, BB3)
	VMOVDQA(tmpStoreAVX2, CC3)
	polyMulReduceStage()
}

func sealAVX2InternalLoopStart() {
	Label("sealAVX2InternalLoopStart")
	VPADDD(BB0, AA0, AA0)
	VPADDD(BB1, AA1, AA1)
	VPADDD(BB2, AA2, AA2)
	VPADDD(BB3, AA3, AA3)
	VPXOR(AA0, DD0, DD0)
	VPXOR(AA1, DD1, DD1)
	VPXOR(AA2, DD2, DD2)
	VPXOR(AA3, DD3, DD3)
	rol8 := rol8_DATA()
	VPSHUFB(rol8, DD0, DD0)
	VPSHUFB(rol8, DD1, DD1)
	VPSHUFB(rol8, DD2, DD2)
	VPSHUFB(rol8, DD3, DD3)
	polyAdd(Mem{Base: oup}.Offset(2 * 8))
	VPADDD(DD0, CC0, CC0)
	VPADDD(DD1, CC1, CC1)
	VPADDD(DD2, CC2, CC2)
	VPADDD(DD3, CC3, CC3)
	polyMulStage1_AVX2()
	VPXOR(CC0, BB0, BB0)
	VPXOR(CC1, BB1, BB1)
	VPXOR(CC2, BB2, BB2)
	VPXOR(CC3, BB3, BB3)
	VMOVDQA(CC3, tmpStoreAVX2)
	VPSLLD(Imm(7), BB0, CC3)
	VPSRLD(Imm(25), BB0, BB0)
	VPXOR(CC3, BB0, BB0)
	VPSLLD(Imm(7), BB1, CC3)
	VPSRLD(Imm(25), BB1, BB1)
	VPXOR(CC3, BB1, BB1)
	VPSLLD(Imm(7), BB2, CC3)
	VPSRLD(Imm(25), BB2, BB2)
	VPXOR(CC3, BB2, BB2)
	VPSLLD(Imm(7), BB3, CC3)
	VPSRLD(Imm(25), BB3, BB3)
	VPXOR(CC3, BB3, BB3)
	VMOVDQA(tmpStoreAVX2, CC3)
	polyMulStage2_AVX2()
	VPALIGNR(Imm(4), BB0, BB0, BB0)
	VPALIGNR(Imm(4), BB1, BB1, BB1)
	VPALIGNR(Imm(4), BB2, BB2, BB2)
	VPALIGNR(Imm(4), BB3, BB3, BB3)
	VPALIGNR(Imm(8), CC0, CC0, CC0)
	VPALIGNR(Imm(8), CC1, CC1, CC1)
	VPALIGNR(Imm(8), CC2, CC2, CC2)
	VPALIGNR(Imm(8), CC3, CC3, CC3)
	VPALIGNR(Imm(12), DD0, DD0, DD0)
	VPALIGNR(Imm(12), DD1, DD1, DD1)
	VPALIGNR(Imm(12), DD2, DD2, DD2)
	VPALIGNR(Imm(12), DD3, DD3, DD3)
	VPADDD(BB0, AA0, AA0)
	VPADDD(BB1, AA1, AA1)
	VPADDD(BB2, AA2, AA2)
	VPADDD(BB3, AA3, AA3)
	polyMulStage3_AVX2()
	VPXOR(AA0, DD0, DD0)
	VPXOR(AA1, DD1, DD1)
	VPXOR(AA2, DD2, DD2)
	VPXOR(AA3, DD3, DD3)
	rol16 := rol16_DATA()
	VPSHUFB(rol16, DD0, DD0)
	VPSHUFB(rol16, DD1, DD1)
	VPSHUFB(rol16, DD2, DD2)
	VPSHUFB(rol16, DD3, DD3)
	polyMulReduceStage()
	VPADDD(DD0, CC0, CC0)
	VPADDD(DD1, CC1, CC1)
	VPADDD(DD2, CC2, CC2)
	VPADDD(DD3, CC3, CC3)
	VPXOR(CC0, BB0, BB0)
	VPXOR(CC1, BB1, BB1)
	VPXOR(CC2, BB2, BB2)
	VPXOR(CC3, BB3, BB3)
	polyAdd(Mem{Base: oup}.Offset(4 * 8))
	LEAQ(Mem{Base: oup}.Offset(6*8), oup)
	VMOVDQA(CC3, tmpStoreAVX2)
	VPSLLD(Imm(12), BB0, CC3)
	VPSRLD(Imm(20), BB0, BB0)
	VPXOR(CC3, BB0, BB0)
	VPSLLD(Imm(12), BB1, CC3)
	VPSRLD(Imm(20), BB1, BB1)
	VPXOR(CC3, BB1, BB1)
	VPSLLD(Imm(12), BB2, CC3)
	VPSRLD(Imm(20), BB2, BB2)
	VPXOR(CC3, BB2, BB2)
	VPSLLD(Imm(12), BB3, CC3)
	VPSRLD(Imm(20), BB3, BB3)
	VPXOR(CC3, BB3, BB3)
	VMOVDQA(tmpStoreAVX2, CC3)
	polyMulStage1_AVX2()
	VPADDD(BB0, AA0, AA0)
	VPADDD(BB1, AA1, AA1)
	VPADDD(BB2, AA2, AA2)
	VPADDD(BB3, AA3, AA3)
	VPXOR(AA0, DD0, DD0)
	VPXOR(AA1, DD1, DD1)
	VPXOR(AA2, DD2, DD2)
	VPXOR(AA3, DD3, DD3)
	polyMulStage2_AVX2()
	VPSHUFB(rol8, DD0, DD0)
	VPSHUFB(rol8, DD1, DD1)
	VPSHUFB(rol8, DD2, DD2)
	VPSHUFB(rol8, DD3, DD3)
	VPADDD(DD0, CC0, CC0)
	VPADDD(DD1, CC1, CC1)
	VPADDD(DD2, CC2, CC2)
	VPADDD(DD3, CC3, CC3)
	polyMulStage3_AVX2()
	VPXOR(CC0, BB0, BB0)
	VPXOR(CC1, BB1, BB1)
	VPXOR(CC2, BB2, BB2)
	VPXOR(CC3, BB3, BB3)
	VMOVDQA(CC3, tmpStoreAVX2)
	VPSLLD(Imm(7), BB0, CC3)
	VPSRLD(Imm(25), BB0, BB0)
	VPXOR(CC3, BB0, BB0)
	VPSLLD(Imm(7), BB1, CC3)
	VPSRLD(Imm(25), BB1, BB1)
	VPXOR(CC3, BB1, BB1)
	VPSLLD(Imm(7), BB2, CC3)
	VPSRLD(Imm(25), BB2, BB2)
	VPXOR(CC3, BB2, BB2)
	VPSLLD(Imm(7), BB3, CC3)
	VPSRLD(Imm(25), BB3, BB3)
	VPXOR(CC3, BB3, BB3)
	VMOVDQA(tmpStoreAVX2, CC3)
	polyMulReduceStage()
	VPALIGNR(Imm(12), BB0, BB0, BB0)
	VPALIGNR(Imm(12), BB1, BB1, BB1)
	VPALIGNR(Imm(12), BB2, BB2, BB2)
	VPALIGNR(Imm(12), BB3, BB3, BB3)
	VPALIGNR(Imm(8), CC0, CC0, CC0)
	VPALIGNR(Imm(8), CC1, CC1, CC1)
	VPALIGNR(Imm(8), CC2, CC2, CC2)
	VPALIGNR(Imm(8), CC3, CC3, CC3)
	VPALIGNR(Imm(4), DD0, DD0, DD0)
	VPALIGNR(Imm(4), DD1, DD1, DD1)
	VPALIGNR(Imm(4), DD2, DD2, DD2)
	VPALIGNR(Imm(4), DD3, DD3, DD3)
	DECQ(itr1)
	JNE(LabelRef("sealAVX2InternalLoop"))

	chacha20Constants := chacha20Constants_DATA()
	VPADDD(chacha20Constants, AA0, AA0)
	VPADDD(chacha20Constants, AA1, AA1)
	VPADDD(chacha20Constants, AA2, AA2)
	VPADDD(chacha20Constants, AA3, AA3)
	VPADDD(state1StoreAVX2, BB0, BB0)
	VPADDD(state1StoreAVX2, BB1, BB1)
	VPADDD(state1StoreAVX2, BB2, BB2)
	VPADDD(state1StoreAVX2, BB3, BB3)
	VPADDD(state2StoreAVX2, CC0, CC0)
	VPADDD(state2StoreAVX2, CC1, CC1)
	VPADDD(state2StoreAVX2, CC2, CC2)
	VPADDD(state2StoreAVX2, CC3, CC3)
	VPADDD(ctr0StoreAVX2, DD0, DD0)
	VPADDD(ctr1StoreAVX2, DD1, DD1)
	VPADDD(ctr2StoreAVX2, DD2, DD2)
	VPADDD(ctr3StoreAVX2, DD3, DD3)
	VMOVDQA(CC3, tmpStoreAVX2)

	Comment("We only hashed 480 of the 512 bytes available - hash the remaining 32 here")
	polyAdd(Mem{Base: oup}.Offset(0 * 8))
	polyMulAVX2()
	LEAQ(Mem{Base: oup}.Offset(4*8), oup)
	VPERM2I128(Imm(0x02), AA0, BB0, CC3)
	VPERM2I128(Imm(0x13), AA0, BB0, BB0)
	VPERM2I128(Imm(0x02), CC0, DD0, AA0)
	VPERM2I128(Imm(0x13), CC0, DD0, CC0)
	VPXOR(Mem{Base: inp}.Offset(0*32), CC3, CC3)
	VPXOR(Mem{Base: inp}.Offset(1*32), AA0, AA0)
	VPXOR(Mem{Base: inp}.Offset(2*32), BB0, BB0)
	VPXOR(Mem{Base: inp}.Offset(3*32), CC0, CC0)
	VMOVDQU(CC3, Mem{Base: oup}.Offset(0*32))
	VMOVDQU(AA0, Mem{Base: oup}.Offset(1*32))
	VMOVDQU(BB0, Mem{Base: oup}.Offset(2*32))
	VMOVDQU(CC0, Mem{Base: oup}.Offset(3*32))
	VPERM2I128(Imm(0x02), AA1, BB1, AA0)
	VPERM2I128(Imm(0x02), CC1, DD1, BB0)
	VPERM2I128(Imm(0x13), AA1, BB1, CC0)
	VPERM2I128(Imm(0x13), CC1, DD1, DD0)
	VPXOR(Mem{Base: inp}.Offset(4*32), AA0, AA0)
	VPXOR(Mem{Base: inp}.Offset(5*32), BB0, BB0)
	VPXOR(Mem{Base: inp}.Offset(6*32), CC0, CC0)
	VPXOR(Mem{Base: inp}.Offset(7*32), DD0, DD0)
	VMOVDQU(AA0, Mem{Base: oup}.Offset(4*32))
	VMOVDQU(BB0, Mem{Base: oup}.Offset(5*32))
	VMOVDQU(CC0, Mem{Base: oup}.Offset(6*32))
	VMOVDQU(DD0, Mem{Base: oup}.Offset(7*32))

	Comment("and here")
	polyAdd(Mem{Base: oup}.Offset(-2 * 8))
	polyMulAVX2()
	VPERM2I128(Imm(0x02), AA2, BB2, AA0)
	VPERM2I128(Imm(0x02), CC2, DD2, BB0)
	VPERM2I128(Imm(0x13), AA2, BB2, CC0)
	VPERM2I128(Imm(0x13), CC2, DD2, DD0)
	VPXOR(Mem{Base: inp}.Offset(8*32), AA0, AA0)
	VPXOR(Mem{Base: inp}.Offset(9*32), BB0, BB0)
	VPXOR(Mem{Base: inp}.Offset(10*32), CC0, CC0)
	VPXOR(Mem{Base: inp}.Offset(11*32), DD0, DD0)
	VMOVDQU(AA0, Mem{Base: oup}.Offset(8*32))
	VMOVDQU(BB0, Mem{Base: oup}.Offset(9*32))
	VMOVDQU(CC0, Mem{Base: oup}.Offset(10*32))
	VMOVDQU(DD0, Mem{Base: oup}.Offset(11*32))
	VPERM2I128(Imm(0x02), AA3, BB3, AA0)
	VPERM2I128(Imm(0x02), tmpStoreAVX2, DD3, BB0)
	VPERM2I128(Imm(0x13), AA3, BB3, CC0)
	VPERM2I128(Imm(0x13), tmpStoreAVX2, DD3, DD0)
	VPXOR(Mem{Base: inp}.Offset(12*32), AA0, AA0)
	VPXOR(Mem{Base: inp}.Offset(13*32), BB0, BB0)
	VPXOR(Mem{Base: inp}.Offset(14*32), CC0, CC0)
	VPXOR(Mem{Base: inp}.Offset(15*32), DD0, DD0)
	VMOVDQU(AA0, Mem{Base: oup}.Offset(12*32))
	VMOVDQU(BB0, Mem{Base: oup}.Offset(13*32))
	VMOVDQU(CC0, Mem{Base: oup}.Offset(14*32))
	VMOVDQU(DD0, Mem{Base: oup}.Offset(15*32))
	LEAQ(Mem{Base: inp}.Offset(32*16), inp)
	SUBQ(U32(32*16), inl)
	CMPQ(inl, U32(512))
	JG(LabelRef("sealAVX2MainLoop"))

	Comment("Tail can only hash 480 bytes")
	polyAdd(Mem{Base: oup}.Offset(0 * 8))
	polyMulAVX2()
	polyAdd(Mem{Base: oup}.Offset(2 * 8))
	polyMulAVX2()
	LEAQ(Mem{Base: oup}.Offset(32), oup)

	MOVQ(U32(10), itr1)
	MOVQ(U32(0), itr2)
	CMPQ(inl, Imm(128))
	JBE(LabelRef("sealAVX2Tail128"))
	CMPQ(inl, U32(256))
	JBE(LabelRef("sealAVX2Tail256"))
	CMPQ(inl, U32(384))
	JBE(LabelRef("sealAVX2Tail384"))
	JMP(LabelRef("sealAVX2Tail512"))
}

// ----------------------------------------------------------------------------
// Special optimization for buffers smaller than 193 bytes

// For up to 192 bytes of ciphertext and 64 bytes for the poly key, we process four blocks
func seal192AVX2() {
	Label("seal192AVX2")
	VMOVDQA(AA0, AA1)
	VMOVDQA(BB0, BB1)
	VMOVDQA(CC0, CC1)
	avx2IncMask := avx2IncMask_DATA()
	VPADDD(avx2IncMask, DD0, DD1)
	VMOVDQA(AA0, AA2)
	VMOVDQA(BB0, BB2)
	VMOVDQA(CC0, CC2)
	VMOVDQA(DD0, DD2)
	VMOVDQA(DD1, TT3)
	MOVQ(U32(10), itr2)
}

func sealAVX2192InnerCipherLoop() {
	Label("sealAVX2192InnerCipherLoop")
	chachaQR_AVX2(AA0, BB0, CC0, DD0, TT0)
	chachaQR_AVX2(AA1, BB1, CC1, DD1, TT0)
	VPALIGNR(Imm(4), BB0, BB0, BB0)
	VPALIGNR(Imm(4), BB1, BB1, BB1)
	VPALIGNR(Imm(8), CC0, CC0, CC0)
	VPALIGNR(Imm(8), CC1, CC1, CC1)
	VPALIGNR(Imm(12), DD0, DD0, DD0)
	VPALIGNR(Imm(12), DD1, DD1, DD1)
	chachaQR_AVX2(AA0, BB0, CC0, DD0, TT0)
	chachaQR_AVX2(AA1, BB1, CC1, DD1, TT0)
	VPALIGNR(Imm(12), BB0, BB0, BB0)
	VPALIGNR(Imm(12), BB1, BB1, BB1)
	VPALIGNR(Imm(8), CC0, CC0, CC0)
	VPALIGNR(Imm(8), CC1, CC1, CC1)
	VPALIGNR(Imm(4), DD0, DD0, DD0)
	VPALIGNR(Imm(4), DD1, DD1, DD1)
	DECQ(itr2)
	JNE(LabelRef("sealAVX2192InnerCipherLoop"))
	VPADDD(AA2, AA0, AA0)
	VPADDD(AA2, AA1, AA1)
	VPADDD(BB2, BB0, BB0)
	VPADDD(BB2, BB1, BB1)
	VPADDD(CC2, CC0, CC0)
	VPADDD(CC2, CC1, CC1)
	VPADDD(DD2, DD0, DD0)
	VPADDD(TT3, DD1, DD1)
	VPERM2I128(Imm(0x02), AA0, BB0, TT0)

	Comment("Clamp and store poly key")
	polyClampMask := polyClampMask_DATA()
	VPAND(polyClampMask, TT0, TT0)
	VMOVDQA(TT0, rsStoreAVX2)

	Comment("Stream for up to 192 bytes")
	VPERM2I128(Imm(0x13), AA0, BB0, AA0)
	VPERM2I128(Imm(0x13), CC0, DD0, BB0)
	VPERM2I128(Imm(0x02), AA1, BB1, CC0)
	VPERM2I128(Imm(0x02), CC1, DD1, DD0)
	VPERM2I128(Imm(0x13), AA1, BB1, AA1)
	VPERM2I128(Imm(0x13), CC1, DD1, BB1)
}

func sealAVX2ShortSeal() {
	Label("sealAVX2ShortSeal")
	Comment("Hash aad")
	MOVQ(NewParamAddr("ad_len", 80), itr2)
	CALL(LabelRef("polyHashADInternal<>(SB)"))
	XORQ(itr1, itr1)
}

func sealAVX2SealHash() {
	Label("sealAVX2SealHash")
	Comment("itr1 holds the number of bytes encrypted but not yet hashed")
	CMPQ(itr1, Imm(16))
	JB(LabelRef("sealAVX2ShortSealLoop"))
	polyAdd(Mem{Base: oup}.Offset(0))
	polyMul()
	SUBQ(Imm(16), itr1)
	ADDQ(Imm(16), oup)
	JMP(LabelRef("sealAVX2SealHash"))
}

func sealAVX2ShortSealLoop() {
	Label("sealAVX2ShortSealLoop")
	CMPQ(inl, Imm(32))
	JB(LabelRef("sealAVX2ShortTail32"))
	SUBQ(Imm(32), inl)

	Comment("Load for encryption")
	VPXOR(Mem{Base: inp}, AA0, AA0)
	VMOVDQU(AA0, Mem{Base: oup})
	LEAQ(Mem{Base: inp}.Offset(1*32), inp)

	Comment("Now can hash")
	polyAdd(Mem{Base: oup}.Offset(0 * 8))
	polyMulAVX2()
	polyAdd(Mem{Base: oup}.Offset(2 * 8))
	polyMulAVX2()
	LEAQ(Mem{Base: oup}.Offset(1*32), oup)

	Comment("Shift stream left")
	VMOVDQA(BB0, AA0)
	VMOVDQA(CC0, BB0)
	VMOVDQA(DD0, CC0)
	VMOVDQA(AA1, DD0)
	VMOVDQA(BB1, AA1)
	VMOVDQA(CC1, BB1)
	VMOVDQA(DD1, CC1)
	VMOVDQA(AA2, DD1)
	VMOVDQA(BB2, AA2)
	JMP(LabelRef("sealAVX2ShortSealLoop"))
}

func sealAVX2ShortTail32() {
	Label("sealAVX2ShortTail32")
	CMPQ(inl, Imm(16))
	VMOVDQA(A0, A1)
	JB(LabelRef("sealAVX2ShortDone"))

	SUBQ(Imm(16), inl)

	Comment("Load for encryption")
	VPXOR(Mem{Base: inp}, A0, T0)
	VMOVDQU(T0, Mem{Base: oup})
	LEAQ(Mem{Base: inp}.Offset(1*16), inp)

	Comment("Hash")
	polyAdd(Mem{Base: oup}.Offset(0 * 8))
	polyMulAVX2()
	LEAQ(Mem{Base: oup}.Offset(1*16), oup)
	VPERM2I128(Imm(0x11), AA0, AA0, AA0)
	VMOVDQA(A0, A1)
}

func sealAVX2ShortDone() {
	Label("sealAVX2ShortDone")
	VZEROUPPER()
	JMP(LabelRef("sealSSETail"))
}

// ----------------------------------------------------------------------------
// Special optimization for buffers smaller than 321 bytes

// For up to 320 bytes of ciphertext and 64 bytes for the poly key, we process six blocks
func seal320AVX2() {
	Label("seal320AVX2")
	VMOVDQA(AA0, AA1)
	VMOVDQA(BB0, BB1)
	VMOVDQA(CC0, CC1)
	avx2IncMask := avx2IncMask_DATA()
	VPADDD(avx2IncMask, DD0, DD1)
	VMOVDQA(AA0, AA2)
	VMOVDQA(BB0, BB2)
	VMOVDQA(CC0, CC2)
	VPADDD(avx2IncMask, DD1, DD2)
	VMOVDQA(BB0, TT1)
	VMOVDQA(CC0, TT2)
	VMOVDQA(DD0, TT3)
	MOVQ(U32(10), itr2)
}

func sealAVX2320InnerCipherLoop() {
	Label("sealAVX2320InnerCipherLoop")
	chachaQR_AVX2(AA0, BB0, CC0, DD0, TT0)
	chachaQR_AVX2(AA1, BB1, CC1, DD1, TT0)
	chachaQR_AVX2(AA2, BB2, CC2, DD2, TT0)
	VPALIGNR(Imm(4), BB0, BB0, BB0)
	VPALIGNR(Imm(4), BB1, BB1, BB1)
	VPALIGNR(Imm(4), BB2, BB2, BB2)
	VPALIGNR(Imm(8), CC0, CC0, CC0)
	VPALIGNR(Imm(8), CC1, CC1, CC1)
	VPALIGNR(Imm(8), CC2, CC2, CC2)
	VPALIGNR(Imm(12), DD0, DD0, DD0)
	VPALIGNR(Imm(12), DD1, DD1, DD1)
	VPALIGNR(Imm(12), DD2, DD2, DD2)
	chachaQR_AVX2(AA0, BB0, CC0, DD0, TT0)
	chachaQR_AVX2(AA1, BB1, CC1, DD1, TT0)
	chachaQR_AVX2(AA2, BB2, CC2, DD2, TT0)
	VPALIGNR(Imm(12), BB0, BB0, BB0)
	VPALIGNR(Imm(12), BB1, BB1, BB1)
	VPALIGNR(Imm(12), BB2, BB2, BB2)
	VPALIGNR(Imm(8), CC0, CC0, CC0)
	VPALIGNR(Imm(8), CC1, CC1, CC1)
	VPALIGNR(Imm(8), CC2, CC2, CC2)
	VPALIGNR(Imm(4), DD0, DD0, DD0)
	VPALIGNR(Imm(4), DD1, DD1, DD1)
	VPALIGNR(Imm(4), DD2, DD2, DD2)
	DECQ(itr2)
	JNE(LabelRef("sealAVX2320InnerCipherLoop"))

	chacha20Constants := chacha20Constants_DATA()
	VMOVDQA(chacha20Constants, TT0)
	VPADDD(TT0, AA0, AA0)
	VPADDD(TT0, AA1, AA1)
	VPADDD(TT0, AA2, AA2)
	VPADDD(TT1, BB0, BB0)
	VPADDD(TT1, BB1, BB1)
	VPADDD(TT1, BB2, BB2)
	VPADDD(TT2, CC0, CC0)
	VPADDD(TT2, CC1, CC1)
	VPADDD(TT2, CC2, CC2)
	avx2IncMask := avx2IncMask_DATA()
	VMOVDQA(avx2IncMask, TT0)
	VPADDD(TT3, DD0, DD0)
	VPADDD(TT0, TT3, TT3)
	VPADDD(TT3, DD1, DD1)
	VPADDD(TT0, TT3, TT3)
	VPADDD(TT3, DD2, DD2)

	Comment("Clamp and store poly key")
	VPERM2I128(Imm(0x02), AA0, BB0, TT0)
	polyClampMask := polyClampMask_DATA()
	VPAND(polyClampMask, TT0, TT0)
	VMOVDQA(TT0, rsStoreAVX2)

	Comment("Stream for up to 320 bytes")
	VPERM2I128(Imm(0x13), AA0, BB0, AA0)
	VPERM2I128(Imm(0x13), CC0, DD0, BB0)
	VPERM2I128(Imm(0x02), AA1, BB1, CC0)
	VPERM2I128(Imm(0x02), CC1, DD1, DD0)
	VPERM2I128(Imm(0x13), AA1, BB1, AA1)
	VPERM2I128(Imm(0x13), CC1, DD1, BB1)
	VPERM2I128(Imm(0x02), AA2, BB2, CC1)
	VPERM2I128(Imm(0x02), CC2, DD2, DD1)
	VPERM2I128(Imm(0x13), AA2, BB2, AA2)
	VPERM2I128(Imm(0x13), CC2, DD2, BB2)
	JMP(LabelRef("sealAVX2ShortSeal"))
}

// Need to decrypt up to 128 bytes - prepare two blocks:
//   - If we got here after the main loop - there are 512 encrypted bytes waiting to be hashed.
//   - If we got here before the main loop - there are 448 encrpyred bytes waiting to be hashed.
func sealAVX2Tail128() {
	Label("sealAVX2Tail128")
	chacha20Constants := chacha20Constants_DATA()
	VMOVDQA(chacha20Constants, AA0)
	VMOVDQA(state1StoreAVX2, BB0)
	VMOVDQA(state2StoreAVX2, CC0)
	VMOVDQA(ctr3StoreAVX2, DD0)
	avx2IncMask := avx2IncMask_DATA()
	VPADDD(avx2IncMask, DD0, DD0)
	VMOVDQA(DD0, DD1)
}

func sealAVX2Tail128LoopA() {
	Label("sealAVX2Tail128LoopA")
	polyAdd(Mem{Base: oup}.Offset(0))
	polyMul()
	LEAQ(Mem{Base: oup}.Offset(16), oup)
}

func sealAVX2Tail128LoopB() {
	Label("sealAVX2Tail128LoopB")
	chachaQR_AVX2(AA0, BB0, CC0, DD0, TT0)
	polyAdd(Mem{Base: oup}.Offset(0))
	polyMul()
	VPALIGNR(Imm(4), BB0, BB0, BB0)
	VPALIGNR(Imm(8), CC0, CC0, CC0)
	VPALIGNR(Imm(12), DD0, DD0, DD0)
	chachaQR_AVX2(AA0, BB0, CC0, DD0, TT0)
	polyAdd(Mem{Base: oup}.Offset(16))
	polyMul()
	LEAQ(Mem{Base: oup}.Offset(32), oup)
	VPALIGNR(Imm(12), BB0, BB0, BB0)
	VPALIGNR(Imm(8), CC0, CC0, CC0)
	VPALIGNR(Imm(4), DD0, DD0, DD0)
	DECQ(itr1)
	JG(LabelRef("sealAVX2Tail128LoopA"))
	DECQ(itr2)
	JGE(LabelRef("sealAVX2Tail128LoopB"))

	chacha20Constants := chacha20Constants_DATA()
	VPADDD(chacha20Constants, AA0, AA1)
	VPADDD(state1StoreAVX2, BB0, BB1)
	VPADDD(state2StoreAVX2, CC0, CC1)
	VPADDD(DD1, DD0, DD1)

	VPERM2I128(Imm(0x02), AA1, BB1, AA0)
	VPERM2I128(Imm(0x02), CC1, DD1, BB0)
	VPERM2I128(Imm(0x13), AA1, BB1, CC0)
	VPERM2I128(Imm(0x13), CC1, DD1, DD0)
	JMP(LabelRef("sealAVX2ShortSealLoop"))
}

// ----------------------------------------------------------------------------
// Special optimization for the last 256 bytes of ciphertext

// Need to decrypt up to 256 bytes - prepare two blocks
//   - If we got here after the main loop - there are 512 encrypted bytes waiting to be hashed
//   - If we got here before the main loop - there are 448 encrpyred bytes waiting to be hashed
func sealAVX2Tail256() {
	Label("sealAVX2Tail256")
	chacha20Constants := chacha20Constants_DATA()
	VMOVDQA(chacha20Constants, AA0)
	VMOVDQA(chacha20Constants, AA1)
	VMOVDQA(state1StoreAVX2, BB0)
	VMOVDQA(state1StoreAVX2, BB1)
	VMOVDQA(state2StoreAVX2, CC0)
	VMOVDQA(state2StoreAVX2, CC1)
	VMOVDQA(ctr3StoreAVX2, DD0)
	avx2IncMask := avx2IncMask_DATA()
	VPADDD(avx2IncMask, DD0, DD0)
	VPADDD(avx2IncMask, DD0, DD1)
	VMOVDQA(DD0, TT1)
	VMOVDQA(DD1, TT2)
}

func sealAVX2Tail256LoopA() {
	Label("sealAVX2Tail256LoopA")
	polyAdd(Mem{Base: oup}.Offset(0))
	polyMul()
	LEAQ(Mem{Base: oup}.Offset(16), oup)
}

// LIne 2493
func sealAVX2Tail256LoopB() {
	Label("sealAVX2Tail256LoopB")
	chachaQR_AVX2(AA0, BB0, CC0, DD0, TT0)
	chachaQR_AVX2(AA1, BB1, CC1, DD1, TT0)
	polyAdd(Mem{Base: oup}.Offset(0))
	polyMul()
	VPALIGNR(Imm(4), BB0, BB0, BB0)
	VPALIGNR(Imm(4), BB1, BB1, BB1)
	VPALIGNR(Imm(8), CC0, CC0, CC0)
	VPALIGNR(Imm(8), CC1, CC1, CC1)
	VPALIGNR(Imm(12), DD0, DD0, DD0)
	VPALIGNR(Imm(12), DD1, DD1, DD1)
	chachaQR_AVX2(AA0, BB0, CC0, DD0, TT0)
	chachaQR_AVX2(AA1, BB1, CC1, DD1, TT0)
	polyAdd(Mem{Base: oup}.Offset(16))
	polyMul()
	LEAQ(Mem{Base: oup}.Offset(32), oup)
	VPALIGNR(Imm(12), BB0, BB0, BB0)
	VPALIGNR(Imm(12), BB1, BB1, BB1)
	VPALIGNR(Imm(8), CC0, CC0, CC0)
	VPALIGNR(Imm(8), CC1, CC1, CC1)
	VPALIGNR(Imm(4), DD0, DD0, DD0)
	VPALIGNR(Imm(4), DD1, DD1, DD1)
	DECQ(itr1)
	JG(LabelRef("sealAVX2Tail256LoopA"))
	DECQ(itr2)
	JGE(LabelRef("sealAVX2Tail256LoopB"))

	chacha20Constants := chacha20Constants_DATA()
	VPADDD(chacha20Constants, AA0, AA0)
	VPADDD(chacha20Constants, AA1, AA1)
	VPADDD(state1StoreAVX2, BB0, BB0)
	VPADDD(state1StoreAVX2, BB1, BB1)
	VPADDD(state2StoreAVX2, CC0, CC0)
	VPADDD(state2StoreAVX2, CC1, CC1)
	VPADDD(TT1, DD0, DD0)
	VPADDD(TT2, DD1, DD1)
	VPERM2I128(Imm(0x02), AA0, BB0, TT0)
	VPERM2I128(Imm(0x02), CC0, DD0, TT1)
	VPERM2I128(Imm(0x13), AA0, BB0, TT2)
	VPERM2I128(Imm(0x13), CC0, DD0, TT3)
	VPXOR(Mem{Base: inp}.Offset(0*32), TT0, TT0)
	VPXOR(Mem{Base: inp}.Offset(1*32), TT1, TT1)
	VPXOR(Mem{Base: inp}.Offset(2*32), TT2, TT2)
	VPXOR(Mem{Base: inp}.Offset(3*32), TT3, TT3)
	VMOVDQU(TT0, Mem{Base: oup}.Offset(0*32))
	VMOVDQU(TT1, Mem{Base: oup}.Offset(1*32))
	VMOVDQU(TT2, Mem{Base: oup}.Offset(2*32))
	VMOVDQU(TT3, Mem{Base: oup}.Offset(3*32))
	MOVQ(U32(128), itr1)
	LEAQ(Mem{Base: inp}.Offset(128), inp)
	SUBQ(Imm(128), inl)
	VPERM2I128(Imm(0x02), AA1, BB1, AA0)
	VPERM2I128(Imm(0x02), CC1, DD1, BB0)
	VPERM2I128(Imm(0x13), AA1, BB1, CC0)
	VPERM2I128(Imm(0x13), CC1, DD1, DD0)

	JMP(LabelRef("sealAVX2SealHash"))
}

// ----------------------------------------------------------------------------
// Special optimization for the last 384 bytes of ciphertext

// Need to decrypt up to 384 bytes - prepare two blocks
//   - If we got here after the main loop - there are 512 encrypted bytes waiting to be hashed
//   - If we got here before the main loop - there are 448 encrpyred bytes waiting to be hashed
func sealAVX2Tail384() {
	Label("sealAVX2Tail384")
	chacha20Constants := chacha20Constants_DATA()
	VMOVDQA(chacha20Constants, AA0)
	VMOVDQA(AA0, AA1)
	VMOVDQA(AA0, AA2)
	VMOVDQA(state1StoreAVX2, BB0)
	VMOVDQA(BB0, BB1)
	VMOVDQA(BB0, BB2)
	VMOVDQA(state2StoreAVX2, CC0)
	VMOVDQA(CC0, CC1)
	VMOVDQA(CC0, CC2)
	VMOVDQA(ctr3StoreAVX2, DD0)
	avx2IncMask := avx2IncMask_DATA()
	VPADDD(avx2IncMask, DD0, DD0)
	VPADDD(avx2IncMask, DD0, DD1)
	VPADDD(avx2IncMask, DD1, DD2)
	VMOVDQA(DD0, TT1)
	VMOVDQA(DD1, TT2)
	VMOVDQA(DD2, TT3)
}

func sealAVX2Tail384LoopA() {
	Label("sealAVX2Tail384LoopA")
	polyAdd(Mem{Base: oup}.Offset(0))
	polyMul()
	LEAQ(Mem{Base: oup}.Offset(16), oup)
}

func sealAVX2Tail384LoopB() {
	Label("sealAVX2Tail384LoopB")
	chachaQR_AVX2(AA0, BB0, CC0, DD0, TT0)
	chachaQR_AVX2(AA1, BB1, CC1, DD1, TT0)
	chachaQR_AVX2(AA2, BB2, CC2, DD2, TT0)
	polyAdd(Mem{Base: oup}.Offset(0))
	polyMul()
	VPALIGNR(Imm(4), BB0, BB0, BB0)
	VPALIGNR(Imm(4), BB1, BB1, BB1)
	VPALIGNR(Imm(4), BB2, BB2, BB2)
	VPALIGNR(Imm(8), CC0, CC0, CC0)
	VPALIGNR(Imm(8), CC1, CC1, CC1)
	VPALIGNR(Imm(8), CC2, CC2, CC2)
	VPALIGNR(Imm(12), DD0, DD0, DD0)
	VPALIGNR(Imm(12), DD1, DD1, DD1)
	VPALIGNR(Imm(12), DD2, DD2, DD2)
	chachaQR_AVX2(AA0, BB0, CC0, DD0, TT0)
	chachaQR_AVX2(AA1, BB1, CC1, DD1, TT0)
	chachaQR_AVX2(AA2, BB2, CC2, DD2, TT0)
	polyAdd(Mem{Base: oup}.Offset(16))
	polyMul()
	LEAQ(Mem{Base: oup}.Offset(32), oup)
	VPALIGNR(Imm(12), BB0, BB0, BB0)
	VPALIGNR(Imm(12), BB1, BB1, BB1)
	VPALIGNR(Imm(12), BB2, BB2, BB2)
	VPALIGNR(Imm(8), CC0, CC0, CC0)
	VPALIGNR(Imm(8), CC1, CC1, CC1)
	VPALIGNR(Imm(8), CC2, CC2, CC2)
	VPALIGNR(Imm(4), DD0, DD0, DD0)
	VPALIGNR(Imm(4), DD1, DD1, DD1)
	VPALIGNR(Imm(4), DD2, DD2, DD2)
	DECQ(itr1)
	JG(LabelRef("sealAVX2Tail384LoopA"))
	DECQ(itr2)
	JGE(LabelRef("sealAVX2Tail384LoopB"))

	chacha20Constants := chacha20Constants_DATA()
	VPADDD(chacha20Constants, AA0, AA0)
	VPADDD(chacha20Constants, AA1, AA1)
	VPADDD(chacha20Constants, AA2, AA2)
	VPADDD(state1StoreAVX2, BB0, BB0)
	VPADDD(state1StoreAVX2, BB1, BB1)
	VPADDD(state1StoreAVX2, BB2, BB2)
	VPADDD(state2StoreAVX2, CC0, CC0)
	VPADDD(state2StoreAVX2, CC1, CC1)
	VPADDD(state2StoreAVX2, CC2, CC2)
	VPADDD(TT1, DD0, DD0)
	VPADDD(TT2, DD1, DD1)
	VPADDD(TT3, DD2, DD2)
	VPERM2I128(Imm(0x02), AA0, BB0, TT0)
	VPERM2I128(Imm(0x02), CC0, DD0, TT1)
	VPERM2I128(Imm(0x13), AA0, BB0, TT2)
	VPERM2I128(Imm(0x13), CC0, DD0, TT3)
	VPXOR(Mem{Base: inp}.Offset(0*32), TT0, TT0)
	VPXOR(Mem{Base: inp}.Offset(1*32), TT1, TT1)
	VPXOR(Mem{Base: inp}.Offset(2*32), TT2, TT2)
	VPXOR(Mem{Base: inp}.Offset(3*32), TT3, TT3)
	VMOVDQU(TT0, Mem{Base: oup}.Offset(0*32))
	VMOVDQU(TT1, Mem{Base: oup}.Offset(1*32))
	VMOVDQU(TT2, Mem{Base: oup}.Offset(2*32))
	VMOVDQU(TT3, Mem{Base: oup}.Offset(3*32))
	VPERM2I128(Imm(0x02), AA1, BB1, TT0)
	VPERM2I128(Imm(0x02), CC1, DD1, TT1)
	VPERM2I128(Imm(0x13), AA1, BB1, TT2)
	VPERM2I128(Imm(0x13), CC1, DD1, TT3)
	VPXOR(Mem{Base: inp}.Offset(4*32), TT0, TT0)
	VPXOR(Mem{Base: inp}.Offset(5*32), TT1, TT1)
	VPXOR(Mem{Base: inp}.Offset(6*32), TT2, TT2)
	VPXOR(Mem{Base: inp}.Offset(7*32), TT3, TT3)
	VMOVDQU(TT0, Mem{Base: oup}.Offset(4*32))
	VMOVDQU(TT1, Mem{Base: oup}.Offset(5*32))
	VMOVDQU(TT2, Mem{Base: oup}.Offset(6*32))
	VMOVDQU(TT3, Mem{Base: oup}.Offset(7*32))
	MOVQ(U32(256), itr1)
	LEAQ(Mem{Base: inp}.Offset(256), inp)
	SUBQ(U32(256), inl)
	VPERM2I128(Imm(0x02), AA2, BB2, AA0)
	VPERM2I128(Imm(0x02), CC2, DD2, BB0)
	VPERM2I128(Imm(0x13), AA2, BB2, CC0)
	VPERM2I128(Imm(0x13), CC2, DD2, DD0)

	JMP(LabelRef("sealAVX2SealHash"))
}

// ----------------------------------------------------------------------------
// Special optimization for the last 512 bytes of ciphertext

// Need to decrypt up to 512 bytes - prepare two blocks
//   - If we got here after the main loop - there are 512 encrypted bytes waiting to be hashed
//   - If we got here before the main loop - there are 448 encrpyred bytes waiting to be hashed
func sealAVX2Tail512() {
	Label("sealAVX2Tail512")
	chacha20Constants := chacha20Constants_DATA()
	VMOVDQA(chacha20Constants, AA0)
	VMOVDQA(AA0, AA1)
	VMOVDQA(AA0, AA2)
	VMOVDQA(AA0, AA3)
	VMOVDQA(state1StoreAVX2, BB0)
	VMOVDQA(BB0, BB1)
	VMOVDQA(BB0, BB2)
	VMOVDQA(BB0, BB3)
	VMOVDQA(state2StoreAVX2, CC0)
	VMOVDQA(CC0, CC1)
	VMOVDQA(CC0, CC2)
	VMOVDQA(CC0, CC3)
	VMOVDQA(ctr3StoreAVX2, DD0)
	avx2IncMask := avx2IncMask_DATA()
	VPADDD(avx2IncMask, DD0, DD0)
	VPADDD(avx2IncMask, DD0, DD1)
	VPADDD(avx2IncMask, DD1, DD2)
	VPADDD(avx2IncMask, DD2, DD3)
	VMOVDQA(DD0, ctr0StoreAVX2)
	VMOVDQA(DD1, ctr1StoreAVX2)
	VMOVDQA(DD2, ctr2StoreAVX2)
	VMOVDQA(DD3, ctr3StoreAVX2)
}

func sealAVX2Tail512LoopA() {
	Label("sealAVX2Tail512LoopA")
	polyAdd(Mem{Base: oup}.Offset(0))
	polyMul()
	LEAQ(Mem{Base: oup}.Offset(16), oup)
}

func sealAVX2Tail512LoopB() {
	Label("sealAVX2Tail512LoopB")
	VPADDD(BB0, AA0, AA0)
	VPADDD(BB1, AA1, AA1)
	VPADDD(BB2, AA2, AA2)
	VPADDD(BB3, AA3, AA3)
	VPXOR(AA0, DD0, DD0)
	VPXOR(AA1, DD1, DD1)
	VPXOR(AA2, DD2, DD2)
	VPXOR(AA3, DD3, DD3)
	rol16 := rol16_DATA()
	VPSHUFB(rol16, DD0, DD0)
	VPSHUFB(rol16, DD1, DD1)
	VPSHUFB(rol16, DD2, DD2)
	VPSHUFB(rol16, DD3, DD3)
	VPADDD(DD0, CC0, CC0)
	VPADDD(DD1, CC1, CC1)
	VPADDD(DD2, CC2, CC2)
	VPADDD(DD3, CC3, CC3)
	VPXOR(CC0, BB0, BB0)
	VPXOR(CC1, BB1, BB1)
	VPXOR(CC2, BB2, BB2)
	VPXOR(CC3, BB3, BB3)
	VMOVDQA(CC3, tmpStoreAVX2)
	VPSLLD(Imm(12), BB0, CC3)
	VPSRLD(Imm(20), BB0, BB0)
	VPXOR(CC3, BB0, BB0)
	VPSLLD(Imm(12), BB1, CC3)
	VPSRLD(Imm(20), BB1, BB1)
	VPXOR(CC3, BB1, BB1)
	VPSLLD(Imm(12), BB2, CC3)
	VPSRLD(Imm(20), BB2, BB2)
	VPXOR(CC3, BB2, BB2)
	VPSLLD(Imm(12), BB3, CC3)
	VPSRLD(Imm(20), BB3, BB3)
	VPXOR(CC3, BB3, BB3)
	VMOVDQA(tmpStoreAVX2, CC3)
	polyAdd(Mem{Base: oup}.Offset(0 * 8))
	polyMulAVX2()
	VPADDD(BB0, AA0, AA0)
	VPADDD(BB1, AA1, AA1)
	VPADDD(BB2, AA2, AA2)
	VPADDD(BB3, AA3, AA3)
	VPXOR(AA0, DD0, DD0)
	VPXOR(AA1, DD1, DD1)
	VPXOR(AA2, DD2, DD2)
	VPXOR(AA3, DD3, DD3)
	rol8 := rol8_DATA()
	VPSHUFB(rol8, DD0, DD0)
	VPSHUFB(rol8, DD1, DD1)
	VPSHUFB(rol8, DD2, DD2)
	VPSHUFB(rol8, DD3, DD3)
	VPADDD(DD0, CC0, CC0)
	VPADDD(DD1, CC1, CC1)
	VPADDD(DD2, CC2, CC2)
	VPADDD(DD3, CC3, CC3)
	VPXOR(CC0, BB0, BB0)
	VPXOR(CC1, BB1, BB1)
	VPXOR(CC2, BB2, BB2)
	VPXOR(CC3, BB3, BB3)
	VMOVDQA(CC3, tmpStoreAVX2)
	VPSLLD(Imm(7), BB0, CC3)
	VPSRLD(Imm(25), BB0, BB0)
	VPXOR(CC3, BB0, BB0)
	VPSLLD(Imm(7), BB1, CC3)
	VPSRLD(Imm(25), BB1, BB1)
	VPXOR(CC3, BB1, BB1)
	VPSLLD(Imm(7), BB2, CC3)
	VPSRLD(Imm(25), BB2, BB2)
	VPXOR(CC3, BB2, BB2)
	VPSLLD(Imm(7), BB3, CC3)
	VPSRLD(Imm(25), BB3, BB3)
	VPXOR(CC3, BB3, BB3)
	VMOVDQA(tmpStoreAVX2, CC3)
	VPALIGNR(Imm(4), BB0, BB0, BB0)
	VPALIGNR(Imm(4), BB1, BB1, BB1)
	VPALIGNR(Imm(4), BB2, BB2, BB2)
	VPALIGNR(Imm(4), BB3, BB3, BB3)
	VPALIGNR(Imm(8), CC0, CC0, CC0)
	VPALIGNR(Imm(8), CC1, CC1, CC1)
	VPALIGNR(Imm(8), CC2, CC2, CC2)
	VPALIGNR(Imm(8), CC3, CC3, CC3)
	VPALIGNR(Imm(12), DD0, DD0, DD0)
	VPALIGNR(Imm(12), DD1, DD1, DD1)
	VPALIGNR(Imm(12), DD2, DD2, DD2)
	VPALIGNR(Imm(12), DD3, DD3, DD3)
	VPADDD(BB0, AA0, AA0)
	VPADDD(BB1, AA1, AA1)
	VPADDD(BB2, AA2, AA2)
	VPADDD(BB3, AA3, AA3)
	VPXOR(AA0, DD0, DD0)
	VPXOR(AA1, DD1, DD1)
	VPXOR(AA2, DD2, DD2)
	VPXOR(AA3, DD3, DD3)
	VPSHUFB(rol16, DD0, DD0)
	VPSHUFB(rol16, DD1, DD1)
	VPSHUFB(rol16, DD2, DD2)
	VPSHUFB(rol16, DD3, DD3)
	VPADDD(DD0, CC0, CC0)
	VPADDD(DD1, CC1, CC1)
	VPADDD(DD2, CC2, CC2)
	VPADDD(DD3, CC3, CC3)
	VPXOR(CC0, BB0, BB0)
	VPXOR(CC1, BB1, BB1)
	VPXOR(CC2, BB2, BB2)
	VPXOR(CC3, BB3, BB3)
	polyAdd(Mem{Base: oup}.Offset(2 * 8))
	polyMulAVX2()
	LEAQ(Mem{Base: oup}.Offset(4*8), oup)
	VMOVDQA(CC3, tmpStoreAVX2)
	VPSLLD(Imm(12), BB0, CC3)
	VPSRLD(Imm(20), BB0, BB0)
	VPXOR(CC3, BB0, BB0)
	VPSLLD(Imm(12), BB1, CC3)
	VPSRLD(Imm(20), BB1, BB1)
	VPXOR(CC3, BB1, BB1)
	VPSLLD(Imm(12), BB2, CC3)
	VPSRLD(Imm(20), BB2, BB2)
	VPXOR(CC3, BB2, BB2)
	VPSLLD(Imm(12), BB3, CC3)
	VPSRLD(Imm(20), BB3, BB3)
	VPXOR(CC3, BB3, BB3)
	VMOVDQA(tmpStoreAVX2, CC3)
	VPADDD(BB0, AA0, AA0)
	VPADDD(BB1, AA1, AA1)
	VPADDD(BB2, AA2, AA2)
	VPADDD(BB3, AA3, AA3)
	VPXOR(AA0, DD0, DD0)
	VPXOR(AA1, DD1, DD1)
	VPXOR(AA2, DD2, DD2)
	VPXOR(AA3, DD3, DD3)
	VPSHUFB(rol8, DD0, DD0)
	VPSHUFB(rol8, DD1, DD1)
	VPSHUFB(rol8, DD2, DD2)
	VPSHUFB(rol8, DD3, DD3)
	VPADDD(DD0, CC0, CC0)
	VPADDD(DD1, CC1, CC1)
	VPADDD(DD2, CC2, CC2)
	VPADDD(DD3, CC3, CC3)
	VPXOR(CC0, BB0, BB0)
	VPXOR(CC1, BB1, BB1)
	VPXOR(CC2, BB2, BB2)
	VPXOR(CC3, BB3, BB3)
	VMOVDQA(CC3, tmpStoreAVX2)
	VPSLLD(Imm(7), BB0, CC3)
	VPSRLD(Imm(25), BB0, BB0)
	VPXOR(CC3, BB0, BB0)
	VPSLLD(Imm(7), BB1, CC3)
	VPSRLD(Imm(25), BB1, BB1)
	VPXOR(CC3, BB1, BB1)
	VPSLLD(Imm(7), BB2, CC3)
	VPSRLD(Imm(25), BB2, BB2)
	VPXOR(CC3, BB2, BB2)
	VPSLLD(Imm(7), BB3, CC3)
	VPSRLD(Imm(25), BB3, BB3)
	VPXOR(CC3, BB3, BB3)
	VMOVDQA(tmpStoreAVX2, CC3)
	VPALIGNR(Imm(12), BB0, BB0, BB0)
	VPALIGNR(Imm(12), BB1, BB1, BB1)
	VPALIGNR(Imm(12), BB2, BB2, BB2)
	VPALIGNR(Imm(12), BB3, BB3, BB3)
	VPALIGNR(Imm(8), CC0, CC0, CC0)
	VPALIGNR(Imm(8), CC1, CC1, CC1)
	VPALIGNR(Imm(8), CC2, CC2, CC2)
	VPALIGNR(Imm(8), CC3, CC3, CC3)
	VPALIGNR(Imm(4), DD0, DD0, DD0)
	VPALIGNR(Imm(4), DD1, DD1, DD1)
	VPALIGNR(Imm(4), DD2, DD2, DD2)
	VPALIGNR(Imm(4), DD3, DD3, DD3)

	DECQ(itr1)
	JG(LabelRef("sealAVX2Tail512LoopA"))
	DECQ(itr2)
	JGE(LabelRef("sealAVX2Tail512LoopB"))

	chacha20Constants := chacha20Constants_DATA()
	VPADDD(chacha20Constants, AA0, AA0)
	VPADDD(chacha20Constants, AA1, AA1)
	VPADDD(chacha20Constants, AA2, AA2)
	VPADDD(chacha20Constants, AA3, AA3)
	VPADDD(state1StoreAVX2, BB0, BB0)
	VPADDD(state1StoreAVX2, BB1, BB1)
	VPADDD(state1StoreAVX2, BB2, BB2)
	VPADDD(state1StoreAVX2, BB3, BB3)
	VPADDD(state2StoreAVX2, CC0, CC0)
	VPADDD(state2StoreAVX2, CC1, CC1)
	VPADDD(state2StoreAVX2, CC2, CC2)
	VPADDD(state2StoreAVX2, CC3, CC3)
	VPADDD(ctr0StoreAVX2, DD0, DD0)
	VPADDD(ctr1StoreAVX2, DD1, DD1)
	VPADDD(ctr2StoreAVX2, DD2, DD2)
	VPADDD(ctr3StoreAVX2, DD3, DD3)
	VMOVDQA(CC3, tmpStoreAVX2)
	VPERM2I128(Imm(0x02), AA0, BB0, CC3)
	VPXOR(Mem{Base: inp}.Offset(0*32), CC3, CC3)
	VMOVDQU(CC3, Mem{Base: oup}.Offset(0*32))
	VPERM2I128(Imm(0x02), CC0, DD0, CC3)
	VPXOR(Mem{Base: inp}.Offset(1*32), CC3, CC3)
	VMOVDQU(CC3, Mem{Base: oup}.Offset(1*32))
	VPERM2I128(Imm(0x13), AA0, BB0, CC3)
	VPXOR(Mem{Base: inp}.Offset(2*32), CC3, CC3)
	VMOVDQU(CC3, Mem{Base: oup}.Offset(2*32))
	VPERM2I128(Imm(0x13), CC0, DD0, CC3)
	VPXOR(Mem{Base: inp}.Offset(3*32), CC3, CC3)
	VMOVDQU(CC3, Mem{Base: oup}.Offset(3*32))

	VPERM2I128(Imm(0x02), AA1, BB1, AA0)
	VPERM2I128(Imm(0x02), CC1, DD1, BB0)
	VPERM2I128(Imm(0x13), AA1, BB1, CC0)
	VPERM2I128(Imm(0x13), CC1, DD1, DD0)
	VPXOR(Mem{Base: inp}.Offset(4*32), AA0, AA0)
	VPXOR(Mem{Base: inp}.Offset(5*32), BB0, BB0)
	VPXOR(Mem{Base: inp}.Offset(6*32), CC0, CC0)
	VPXOR(Mem{Base: inp}.Offset(7*32), DD0, DD0)
	VMOVDQU(AA0, Mem{Base: oup}.Offset(4*32))
	VMOVDQU(BB0, Mem{Base: oup}.Offset(5*32))
	VMOVDQU(CC0, Mem{Base: oup}.Offset(6*32))
	VMOVDQU(DD0, Mem{Base: oup}.Offset(7*32))

	VPERM2I128(Imm(0x02), AA2, BB2, AA0)
	VPERM2I128(Imm(0x02), CC2, DD2, BB0)
	VPERM2I128(Imm(0x13), AA2, BB2, CC0)
	VPERM2I128(Imm(0x13), CC2, DD2, DD0)
	VPXOR(Mem{Base: inp}.Offset(8*32), AA0, AA0)
	VPXOR(Mem{Base: inp}.Offset(9*32), BB0, BB0)
	VPXOR(Mem{Base: inp}.Offset(10*32), CC0, CC0)
	VPXOR(Mem{Base: inp}.Offset(11*32), DD0, DD0)
	VMOVDQU(AA0, Mem{Base: oup}.Offset(8*32))
	VMOVDQU(BB0, Mem{Base: oup}.Offset(9*32))
	VMOVDQU(CC0, Mem{Base: oup}.Offset(10*32))
	VMOVDQU(DD0, Mem{Base: oup}.Offset(11*32))

	MOVQ(U32(384), itr1)
	LEAQ(Mem{Base: inp}.Offset(384), inp)
	SUBQ(U32(384), inl)
	VPERM2I128(Imm(0x02), AA3, BB3, AA0)
	VPERM2I128(Imm(0x02), tmpStoreAVX2, DD3, BB0)
	VPERM2I128(Imm(0x13), AA3, BB3, CC0)
	VPERM2I128(Imm(0x13), tmpStoreAVX2, DD3, DD0)

	JMP(LabelRef("sealAVX2SealHash"))
}

// ##~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~DATA SECTION~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~##

var (
	// Pointers for memoizing DATA section symbols
	chacha20Constants_DATA_ptr,
	rol16_DATA_ptr,
	rol8_DATA_ptr,
	sseIncMask_DATA_ptr,
	avx2IncMask_DATA_ptr,
	avx2InitMask_DATA_ptr,
	polyClampMask_DATA_ptr,
	andMask_DATA_ptr *Mem
)

var nothingUpMySleeve = [8]uint32{
	0x61707865,
	0x3320646e,
	0x79622d32,
	0x6b206574,
	0x61707865,
	0x3320646e,
	0x79622d32,
	0x6b206574,
}

// ChaCha20 constants
func chacha20Constants_DATA() Mem {
	if chacha20Constants_DATA_ptr != nil {
		return *chacha20Constants_DATA_ptr
	}

	chacha20Constants := GLOBL(ThatPeskyUnicodeDot+"chacha20Constants", NOPTR|RODATA)
	chacha20Constants_DATA_ptr = &chacha20Constants
	for i, v := range nothingUpMySleeve {
		DATA(i*4, U32(v))
	}
	return chacha20Constants
}

var rol16Consts = [4]uint64{
	0x0504070601000302,
	0x0D0C0F0E09080B0A,
	0x0504070601000302,
	0x0D0C0F0E09080B0A,
}

// <<< 16 with PSHUFB
func rol16_DATA() Mem {
	if rol16_DATA_ptr != nil {
		return *rol16_DATA_ptr
	}

	rol16 := GLOBL(ThatPeskyUnicodeDot+"rol16", NOPTR|RODATA)
	rol16_DATA_ptr = &rol16
	for i, v := range rol16Consts {
		DATA(i*8, U64(v))
	}
	return rol16
}

var rol8Consts = [4]uint64{
	0x0605040702010003,
	0x0E0D0C0F0A09080B,
	0x0605040702010003,
	0x0E0D0C0F0A09080B,
}

// <<< 8 with PSHUFB
func rol8_DATA() Mem {
	if rol8_DATA_ptr != nil {
		return *rol8_DATA_ptr
	}

	rol8 := GLOBL(ThatPeskyUnicodeDot+"rol8", NOPTR|RODATA)
	rol8_DATA_ptr = &rol8
	for i, v := range rol8Consts {
		DATA(i*8, U64(v))
	}
	return rol8
}

var avx2InitMaskConsts = [4]uint64{
	0x0,
	0x0,
	0x1,
	0x0,
}

func avx2InitMask_DATA() Mem {
	if avx2InitMask_DATA_ptr != nil {
		return *avx2InitMask_DATA_ptr
	}

	avx2InitMask := GLOBL(ThatPeskyUnicodeDot+"avx2InitMask", NOPTR|RODATA)
	avx2InitMask_DATA_ptr = &avx2InitMask
	for i, v := range avx2InitMaskConsts {
		DATA(i*8, U64(v))
	}
	return avx2InitMask
}

var avx2IncMaskConsts = [4]uint64{
	0x2,
	0x0,
	0x2,
	0x0,
}

func avx2IncMask_DATA() Mem {
	if avx2IncMask_DATA_ptr != nil {
		return *avx2IncMask_DATA_ptr
	}

	avx2IncMask := GLOBL(ThatPeskyUnicodeDot+"avx2IncMask", NOPTR|RODATA)
	avx2IncMask_DATA_ptr = &avx2IncMask
	for i, v := range avx2IncMaskConsts {
		DATA(i*8, U64(v))
	}
	return avx2IncMask
}

var polyClampMaskConsts = [4]uint64{
	0x0FFFFFFC0FFFFFFF,
	0x0FFFFFFC0FFFFFFC,
	0xFFFFFFFFFFFFFFFF,
	0xFFFFFFFFFFFFFFFF,
}

// Poly1305 key clamp
func polyClampMask_DATA() Mem {
	if polyClampMask_DATA_ptr != nil {
		return *polyClampMask_DATA_ptr
	}

	polyClampMask := GLOBL(ThatPeskyUnicodeDot+"polyClampMask", NOPTR|RODATA)
	polyClampMask_DATA_ptr = &polyClampMask
	for i, v := range polyClampMaskConsts {
		DATA(i*8, U64(v))
	}
	return polyClampMask
}

var sseIncMaskConsts = [2]uint64{
	0x1,
	0x0,
}

func sseIncMask_DATA() Mem {
	if sseIncMask_DATA_ptr != nil {
		return *sseIncMask_DATA_ptr
	}

	sseIncMask := GLOBL(ThatPeskyUnicodeDot+"sseIncMask", NOPTR|RODATA)
	sseIncMask_DATA_ptr = &sseIncMask
	for i, v := range sseIncMaskConsts {
		DATA(i*8, U64(v))
	}
	return sseIncMask
}

var andMaskConsts = [30]uint64{
	0x00000000000000ff,
	0x0000000000000000,
	0x000000000000ffff,
	0x0000000000000000,
	0x0000000000ffffff,
	0x0000000000000000,
	0x00000000ffffffff,
	0x0000000000000000,
	0x000000ffffffffff,
	0x0000000000000000,
	0x0000ffffffffffff,
	0x0000000000000000,
	0x00ffffffffffffff,
	0x0000000000000000,
	0xffffffffffffffff,
	0x0000000000000000,
	0xffffffffffffffff,
	0x00000000000000ff,
	0xffffffffffffffff,
	0x000000000000ffff,
	0xffffffffffffffff,
	0x0000000000ffffff,
	0xffffffffffffffff,
	0x00000000ffffffff,
	0xffffffffffffffff,
	0x000000ffffffffff,
	0xffffffffffffffff,
	0x0000ffffffffffff,
	0xffffffffffffffff,
	0x00ffffffffffffff,
}

func andMask_DATA() Mem {
	if andMask_DATA_ptr != nil {
		return *andMask_DATA_ptr
	}

	andMask := GLOBL(ThatPeskyUnicodeDot+"andMask", NOPTR|RODATA)
	andMask_DATA_ptr = &andMask
	for i, v := range andMaskConsts {
		DATA(i*8, U64(v))
	}
	return andMask
}

// removePeskyUnicodeDot strips the dot from the relevant TEXT directives such that they
// can exist as internal assembly functions
//
// Avo v0.6.0 does not support the generation of internal assembly functions. Go's unicode
// dot tells the compiler to link a TEXT symbol to a function in the current Go package
// (or another package if specified). Avo unconditionally prepends the unicode dot to all
// TEXT symbols, making it impossible to emit an internal function without this hack.
//
// There is a pending PR to add internal functions to Avo:
// https://github.com/mmcloughlin/avo/pull/443
//
// If merged it should allow the usage of InternalFunction("NAME") for the specified functions
func removePeskyUnicodeDot(internalFunctions []string, target string) {
	bytes, err := os.ReadFile(target)
	if err != nil {
		panic(err)
	}

	content := string(bytes)

	for _, from := range internalFunctions {
		to := strings.ReplaceAll(from, ThatPeskyUnicodeDot, "")
		content = strings.ReplaceAll(content, from, to)
	}

	err = os.WriteFile(target, []byte(content), 0644)
	if err != nil {
		panic(err)
	}
}
