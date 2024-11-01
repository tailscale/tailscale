// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	. "github.com/mmcloughlin/avo/build"
	"github.com/mmcloughlin/avo/ir"
	. "github.com/mmcloughlin/avo/operand"
	. "github.com/mmcloughlin/avo/reg"
	_ "golang.org/x/crypto/blake2b"
)

//go:generate go run . -out ../../blake2bAVX2_amd64.s -pkg blake2b

const ThatPeskyUnicodeDot = "\u00b7"

func main() {
	Package("golang.org/x/crypto/blake2b")
	ConstraintExpr("amd64,gc,!purego")
	hashBlocksAVX2()
	hashBlocksAVX()
	Generate()
}

// Utility function to emit a BYTE instruction
func BYTE(imm Op) {
	Instruction(&ir.Instruction{Opcode: "BYTE", Operands: []Op{imm}})
}

func VPERMQ_0x39_Y1_Y1() {
	BYTE(U8(0xc4))
	BYTE(U8(0xe3))
	BYTE(U8(0xfd))
	BYTE(U8(0x00))
	BYTE(U8(0xc9))
	BYTE(U8(0x39))
}

func VPERMQ_0x93_Y1_Y1() {
	BYTE(U8(0xc4))
	BYTE(U8(0xe3))
	BYTE(U8(0xfd))
	BYTE(U8(0x00))
	BYTE(U8(0xc9))
	BYTE(U8(0x93))
}

func VPERMQ_0x4E_Y2_Y2() {
	BYTE(U8(0xc4))
	BYTE(U8(0xe3))
	BYTE(U8(0xfd))
	BYTE(U8(0x00))
	BYTE(U8(0xd2))
	BYTE(U8(0x4e))
}

func VPERMQ_0x93_Y3_Y3() {
	BYTE(U8(0xc4))
	BYTE(U8(0xe3))
	BYTE(U8(0xfd))
	BYTE(U8(0x00))
	BYTE(U8(0xdb))
	BYTE(U8(0x93))
}

func VPERMQ_0x39_Y3_Y3() {
	BYTE(U8(0xc4))
	BYTE(U8(0xe3))
	BYTE(U8(0xfd))
	BYTE(U8(0x00))
	BYTE(U8(0xdb))
	BYTE(U8(0x39))
}

func ROUND_AVX2(m0, m1, m2, m3 Op, t, c40, c48 VecPhysical) {
	VPADDQ(m0, Y0, Y0)
	VPADDQ(Y1, Y0, Y0)
	VPXOR(Y0, Y3, Y3)
	VPSHUFD(I8(-79), Y3, Y3)
	VPADDQ(Y3, Y2, Y2)
	VPXOR(Y2, Y1, Y1)
	VPSHUFB(c40, Y1, Y1)
	VPADDQ(m1, Y0, Y0)
	VPADDQ(Y1, Y0, Y0)
	VPXOR(Y0, Y3, Y3)
	VPSHUFB(c48, Y3, Y3)
	VPADDQ(Y3, Y2, Y2)
	VPXOR(Y2, Y1, Y1)
	VPADDQ(Y1, Y1, t)
	VPSRLQ(Imm(63), Y1, Y1)
	VPXOR(t, Y1, Y1)
	VPERMQ_0x39_Y1_Y1()
	VPERMQ_0x4E_Y2_Y2()
	VPERMQ_0x93_Y3_Y3()
	VPADDQ(m2, Y0, Y0)
	VPADDQ(Y1, Y0, Y0)
	VPXOR(Y0, Y3, Y3)
	VPSHUFD(I8(-79), Y3, Y3)
	VPADDQ(Y3, Y2, Y2)
	VPXOR(Y2, Y1, Y1)
	VPSHUFB(c40, Y1, Y1)
	VPADDQ(m3, Y0, Y0)
	VPADDQ(Y1, Y0, Y0)
	VPXOR(Y0, Y3, Y3)
	VPSHUFB(c48, Y3, Y3)
	VPADDQ(Y3, Y2, Y2)
	VPXOR(Y2, Y1, Y1)
	VPADDQ(Y1, Y1, t)
	VPSRLQ(Imm(63), Y1, Y1)
	VPXOR(t, Y1, Y1)
	VPERMQ_0x39_Y3_Y3()
	VPERMQ_0x4E_Y2_Y2()
	VPERMQ_0x93_Y1_Y1()
}

func VMOVQ_SI_X11_0() {
	BYTE(U8(0xC5))
	BYTE(U8(0x7A))
	BYTE(U8(0x7E))
	BYTE(U8(0x1E))
}

func VMOVQ_SI_X12_0() {
	BYTE(U8(0xC5))
	BYTE(U8(0x7A))
	BYTE(U8(0x7E))
	BYTE(U8(0x26))
}

func VMOVQ_SI_X13_0() {
	BYTE(U8(0xC5))
	BYTE(U8(0x7A))
	BYTE(U8(0x7E))
	BYTE(U8(0x2E))
}

func VMOVQ_SI_X14_0() {
	BYTE(U8(0xC5))
	BYTE(U8(0x7A))
	BYTE(U8(0x7E))
	BYTE(U8(0x36))
}

func VMOVQ_SI_X15_0() {
	BYTE(U8(0xC5))
	BYTE(U8(0x7A))
	BYTE(U8(0x7E))
	BYTE(U8(0x3E))
}

func VMOVQ_SI_X11(n uint8) {
	BYTE(U8(0xC5))
	BYTE(U8(0x7A))
	BYTE(U8(0x7E))
	BYTE(U8(0x5E))
	BYTE(U8(n))
}

func VMOVQ_SI_X12(n uint8) {
	BYTE(U8(0xC5))
	BYTE(U8(0x7A))
	BYTE(U8(0x7E))
	BYTE(U8(0x66))
	BYTE(U8(n))
}

func VMOVQ_SI_X13(n uint8) {
	BYTE(U8(0xC5))
	BYTE(U8(0x7A))
	BYTE(U8(0x7E))
	BYTE(U8(0x6E))
	BYTE(U8(n))
}

func VMOVQ_SI_X14(n uint8) {
	BYTE(U8(0xC5))
	BYTE(U8(0x7A))
	BYTE(U8(0x7E))
	BYTE(U8(0x76))
	BYTE(U8(n))
}

func VMOVQ_SI_X15(n uint8) {
	BYTE(U8(0xC5))
	BYTE(U8(0x7A))
	BYTE(U8(0x7E))
	BYTE(U8(0x7E))
	BYTE(U8(n))
}

func VPINSRQ_1_SI_X11_0() {
	BYTE(U8(0xC4))
	BYTE(U8(0x63))
	BYTE(U8(0xA1))
	BYTE(U8(0x22))
	BYTE(U8(0x1E))
	BYTE(U8(0x01))
}

func VPINSRQ_1_SI_X12_0() {
	BYTE(U8(0xC4))
	BYTE(U8(0x63))
	BYTE(U8(0x99))
	BYTE(U8(0x22))
	BYTE(U8(0x26))
	BYTE(U8(0x01))
}

func VPINSRQ_1_SI_X13_0() {
	BYTE(U8(0xC4))
	BYTE(U8(0x63))
	BYTE(U8(0x91))
	BYTE(U8(0x22))
	BYTE(U8(0x2E))
	BYTE(U8(0x01))
}

func VPINSRQ_1_SI_X14_0() {
	BYTE(U8(0xC4))
	BYTE(U8(0x63))
	BYTE(U8(0x89))
	BYTE(U8(0x22))
	BYTE(U8(0x36))
	BYTE(U8(0x01))
}

func VPINSRQ_1_SI_X15_0() {
	BYTE(U8(0xC4))
	BYTE(U8(0x63))
	BYTE(U8(0x81))
	BYTE(U8(0x22))
	BYTE(U8(0x3E))
	BYTE(U8(0x01))
}

func VPINSRQ_1_SI_X11(n uint8) {
	BYTE(U8(0xC4))
	BYTE(U8(0x63))
	BYTE(U8(0xA1))
	BYTE(U8(0x22))
	BYTE(U8(0x5E))
	BYTE(U8(n))
	BYTE(U8(0x01))
}

func VPINSRQ_1_SI_X12(n uint8) {
	BYTE(U8(0xC4))
	BYTE(U8(0x63))
	BYTE(U8(0x99))
	BYTE(U8(0x22))
	BYTE(U8(0x66))
	BYTE(U8(n))
	BYTE(U8(0x01))
}

func VPINSRQ_1_SI_X13(n uint8) {
	BYTE(U8(0xC4))
	BYTE(U8(0x63))
	BYTE(U8(0x91))
	BYTE(U8(0x22))
	BYTE(U8(0x6E))
	BYTE(U8(n))
	BYTE(U8(0x01))
}

func VPINSRQ_1_SI_X14(n uint8) {
	BYTE(U8(0xC4))
	BYTE(U8(0x63))
	BYTE(U8(0x89))
	BYTE(U8(0x22))
	BYTE(U8(0x76))
	BYTE(U8(n))
	BYTE(U8(0x01))
}

func VPINSRQ_1_SI_X15(n uint8) {
	BYTE(U8(0xC4))
	BYTE(U8(0x63))
	BYTE(U8(0x81))
	BYTE(U8(0x22))
	BYTE(U8(0x7E))
	BYTE(U8(n))
	BYTE(U8(0x01))
}

func VMOVQ_R8_X15() {
	BYTE(U8(0xC4))
	BYTE(U8(0x41))
	BYTE(U8(0xF9))
	BYTE(U8(0x6E))
	BYTE(U8(0xF8))
}

func VPINSRQ_1_R9_X15() {
	BYTE(U8(0xC4))
	BYTE(U8(0x43))
	BYTE(U8(0x81))
	BYTE(U8(0x22))
	BYTE(U8(0xF9))
	BYTE(U8(0x01))
}

// load msg:
//
//	Y12 = (i0, i1, i2, i3)
//
// i0, i1, i2, i3 must not be 0
func LOAD_MSG_AVX2_Y12(i0, i1, i2, i3 uint8) {
	VMOVQ_SI_X12(i0 * 8)
	VMOVQ_SI_X11(i2 * 8)
	VPINSRQ_1_SI_X12(i1 * 8)
	VPINSRQ_1_SI_X11(i3 * 8)
	VINSERTI128(Imm(1), X11, Y12, Y12)
}

// load msg:
//
//	Y13 = (i0, i1, i2, i3)
//
// i0, i1, i2, i3 must not be 0
func LOAD_MSG_AVX2_Y13(i0, i1, i2, i3 uint8) {
	VMOVQ_SI_X13(i0 * 8)
	VMOVQ_SI_X11(i2 * 8)
	VPINSRQ_1_SI_X13(i1 * 8)
	VPINSRQ_1_SI_X11(i3 * 8)
	VINSERTI128(Imm(1), X11, Y13, Y13)
}

// load msg:
//
//	Y14 = (i0, i1, i2, i3)
//
// i0, i1, i2, i3 must not be 0
func LOAD_MSG_AVX2_Y14(i0, i1, i2, i3 uint8) {
	VMOVQ_SI_X14(i0 * 8)
	VMOVQ_SI_X11(i2 * 8)
	VPINSRQ_1_SI_X14(i1 * 8)
	VPINSRQ_1_SI_X11(i3 * 8)
	VINSERTI128(Imm(1), X11, Y14, Y14)
}

// load msg:
//
//	Y15 = (i0, i1, i2, i3)
//
// i0, i1, i2, i3 must not be 0
func LOAD_MSG_AVX2_Y15(i0, i1, i2, i3 uint8) {
	VMOVQ_SI_X15(i0 * 8)
	VMOVQ_SI_X11(i2 * 8)
	VPINSRQ_1_SI_X15(i1 * 8)
	VPINSRQ_1_SI_X11(i3 * 8)
	VINSERTI128(Imm(1), X11, Y15, Y15)
}

func LOAD_MSG_AVX2_0_2_4_6_1_3_5_7_8_10_12_14_9_11_13_15() {
	VMOVQ_SI_X12_0()
	VMOVQ_SI_X11(4 * 8)
	VPINSRQ_1_SI_X12(2 * 8)
	VPINSRQ_1_SI_X11(6 * 8)
	VINSERTI128(Imm(1), X11, Y12, Y12)
	LOAD_MSG_AVX2_Y13(1, 3, 5, 7)
	LOAD_MSG_AVX2_Y14(8, 10, 12, 14)
	LOAD_MSG_AVX2_Y15(9, 11, 13, 15)
}

func LOAD_MSG_AVX2_14_4_9_13_10_8_15_6_1_0_11_5_12_2_7_3() {
	LOAD_MSG_AVX2_Y12(14, 4, 9, 13)
	LOAD_MSG_AVX2_Y13(10, 8, 15, 6)
	VMOVQ_SI_X11(11 * 8)
	VPSHUFD(Imm(0x4E), Mem{Base: SI}.Offset(0*8), X14)
	VPINSRQ_1_SI_X11(5 * 8)
	VINSERTI128(Imm(1), X11, Y14, Y14)
	LOAD_MSG_AVX2_Y15(12, 2, 7, 3)
}

func LOAD_MSG_AVX2_11_12_5_15_8_0_2_13_10_3_7_9_14_6_1_4() {
	VMOVQ_SI_X11(5 * 8)
	VMOVDQU(Mem{Base: SI}.Offset(11*8), X12)
	VPINSRQ_1_SI_X11(15 * 8)
	VINSERTI128(Imm(1), X11, Y12, Y12)
	VMOVQ_SI_X13(8 * 8)
	VMOVQ_SI_X11(2 * 8)
	VPINSRQ_1_SI_X13_0()
	VPINSRQ_1_SI_X11(13 * 8)
	VINSERTI128(Imm(1), X11, Y13, Y13)
	LOAD_MSG_AVX2_Y14(10, 3, 7, 9)
	LOAD_MSG_AVX2_Y15(14, 6, 1, 4)
}

func LOAD_MSG_AVX2_7_3_13_11_9_1_12_14_2_5_4_15_6_10_0_8() {
	LOAD_MSG_AVX2_Y12(7, 3, 13, 11)
	LOAD_MSG_AVX2_Y13(9, 1, 12, 14)
	LOAD_MSG_AVX2_Y14(2, 5, 4, 15)
	VMOVQ_SI_X15(6 * 8)
	VMOVQ_SI_X11_0()
	VPINSRQ_1_SI_X15(10 * 8)
	VPINSRQ_1_SI_X11(8 * 8)
	VINSERTI128(Imm(1), X11, Y15, Y15)
}

func LOAD_MSG_AVX2_9_5_2_10_0_7_4_15_14_11_6_3_1_12_8_13() {
	LOAD_MSG_AVX2_Y12(9, 5, 2, 10)
	VMOVQ_SI_X13_0()
	VMOVQ_SI_X11(4 * 8)
	VPINSRQ_1_SI_X13(7 * 8)
	VPINSRQ_1_SI_X11(15 * 8)
	VINSERTI128(Imm(1), X11, Y13, Y13)
	LOAD_MSG_AVX2_Y14(14, 11, 6, 3)
	LOAD_MSG_AVX2_Y15(1, 12, 8, 13)
}

func LOAD_MSG_AVX2_2_6_0_8_12_10_11_3_4_7_15_1_13_5_14_9() {
	VMOVQ_SI_X12(2 * 8)
	VMOVQ_SI_X11_0()
	VPINSRQ_1_SI_X12(6 * 8)
	VPINSRQ_1_SI_X11(8 * 8)
	VINSERTI128(Imm(1), X11, Y12, Y12)
	LOAD_MSG_AVX2_Y13(12, 10, 11, 3)
	LOAD_MSG_AVX2_Y14(4, 7, 15, 1)
	LOAD_MSG_AVX2_Y15(13, 5, 14, 9)
}

func LOAD_MSG_AVX2_12_1_14_4_5_15_13_10_0_6_9_8_7_3_2_11() {
	LOAD_MSG_AVX2_Y12(12, 1, 14, 4)
	LOAD_MSG_AVX2_Y13(5, 15, 13, 10)
	VMOVQ_SI_X14_0()
	VPSHUFD(Imm(0x4E), Mem{Base: SI}.Offset(8*8), X11)
	VPINSRQ_1_SI_X14(6 * 8)
	VINSERTI128(Imm(1), X11, Y14, Y14)
	LOAD_MSG_AVX2_Y15(7, 3, 2, 11)
}

func LOAD_MSG_AVX2_13_7_12_3_11_14_1_9_5_15_8_2_0_4_6_10() {
	LOAD_MSG_AVX2_Y12(13, 7, 12, 3)
	LOAD_MSG_AVX2_Y13(11, 14, 1, 9)
	LOAD_MSG_AVX2_Y14(5, 15, 8, 2)
	VMOVQ_SI_X15_0()
	VMOVQ_SI_X11(6 * 8)
	VPINSRQ_1_SI_X15(4 * 8)
	VPINSRQ_1_SI_X11(10 * 8)
	VINSERTI128(Imm(1), X11, Y15, Y15)
}

func LOAD_MSG_AVX2_6_14_11_0_15_9_3_8_12_13_1_10_2_7_4_5() {
	VMOVQ_SI_X12(6 * 8)
	VMOVQ_SI_X11(11 * 8)
	VPINSRQ_1_SI_X12(14 * 8)
	VPINSRQ_1_SI_X11_0()
	VINSERTI128(Imm(1), X11, Y12, Y12)
	LOAD_MSG_AVX2_Y13(15, 9, 3, 8)
	VMOVQ_SI_X11(1 * 8)
	VMOVDQU(Mem{Base: SI}.Offset(12*8), X14)
	VPINSRQ_1_SI_X11(10 * 8)
	VINSERTI128(Imm(1), X11, Y14, Y14)
	VMOVQ_SI_X15(2 * 8)
	VMOVDQU(Mem{Base: SI}.Offset(4*8), X11)
	VPINSRQ_1_SI_X15(7 * 8)
	VINSERTI128(Imm(1), X11, Y15, Y15)
}

func LOAD_MSG_AVX2_10_8_7_1_2_4_6_5_15_9_3_13_11_14_12_0() {
	LOAD_MSG_AVX2_Y12(10, 8, 7, 1)
	VMOVQ_SI_X13(2 * 8)
	VPSHUFD(Imm(0x4E), Mem{Base: SI}.Offset(5*8), X11)
	VPINSRQ_1_SI_X13(4 * 8)
	VINSERTI128(Imm(1), X11, Y13, Y13)
	LOAD_MSG_AVX2_Y14(15, 9, 3, 13)
	VMOVQ_SI_X15(11 * 8)
	VMOVQ_SI_X11(12 * 8)
	VPINSRQ_1_SI_X15(14 * 8)
	VPINSRQ_1_SI_X11_0()
	VINSERTI128(Imm(1), X11, Y15, Y15)
}

func hashBlocksAVX2() {
	Implement("hashBlocksAVX2")
	Attributes(4)
	AllocLocal(320) // frame size = 288 + 32 byte alignment

	Load(Param("h"), RAX)
	Load(Param("c"), RBX)
	Load(Param("flag"), RCX)
	Load(Param("blocks").Base(), RSI)
	Load(Param("blocks").Len(), RDI)

	MOVQ(RSP, RDX)
	ADDQ(I32(31), RDX)
	ANDQ(I32(^31), RDX)

	MOVQ(RCX, Mem{Base: DX}.Offset(16))
	XORQ(RCX, RCX)
	MOVQ(RCX, Mem{Base: DX}.Offset(24))

	AVX2_c40 := AVX2_c40_DATA()
	AVX2_c48 := AVX2_c48_DATA()
	VMOVDQU(AVX2_c40, Y4)
	VMOVDQU(AVX2_c48, Y5)

	VMOVDQU(Mem{Base: AX}.Offset(0), Y8)
	VMOVDQU(Mem{Base: AX}.Offset(32), Y9)
	AVX2_iv0 := AVX2_iv0_DATA()
	AVX2_iv1 := AVX2_iv1_DATA()
	VMOVDQU(AVX2_iv0, Y6)
	VMOVDQU(AVX2_iv1, Y7)

	MOVQ(Mem{Base: BX}.Offset(0), R8)
	MOVQ(Mem{Base: BX}.Offset(8), R9)
	MOVQ(R9, Mem{Base: DX}.Offset(8))

	loop_AVX2()
	noinc_AVX2()
}

func loop_AVX2() {
	Label("loop")
	ADDQ(Imm(128), R8)
	MOVQ(R8, Mem{Base: DX}.Offset(0))
	CMPQ(R8, Imm(128))
	JGE(LabelRef("noinc"))
	INCQ(R9)
	MOVQ(R9, Mem{Base: DX}.Offset(8))
}

// line 312
func noinc_AVX2() {
	Label("noinc")
	VMOVDQA(Y8, Y0)
	VMOVDQA(Y9, Y1)
	VMOVDQA(Y6, Y2)
	VPXOR(Mem{Base: DX}.Offset(0), Y7, Y3)

	LOAD_MSG_AVX2_0_2_4_6_1_3_5_7_8_10_12_14_9_11_13_15()
	VMOVDQA(Y12, Mem{Base: DX}.Offset(32))
	VMOVDQA(Y13, Mem{Base: DX}.Offset(64))
	VMOVDQA(Y14, Mem{Base: DX}.Offset(96))
	VMOVDQA(Y15, Mem{Base: DX}.Offset(128))
	ROUND_AVX2(Y12, Y13, Y14, Y15, Y10, Y4, Y5)
	LOAD_MSG_AVX2_14_4_9_13_10_8_15_6_1_0_11_5_12_2_7_3()
	VMOVDQA(Y12, Mem{Base: DX}.Offset(160))
	VMOVDQA(Y13, Mem{Base: DX}.Offset(192))
	VMOVDQA(Y14, Mem{Base: DX}.Offset(224))
	VMOVDQA(Y15, Mem{Base: DX}.Offset(256))

	ROUND_AVX2(Y12, Y13, Y14, Y15, Y10, Y4, Y5)
	LOAD_MSG_AVX2_11_12_5_15_8_0_2_13_10_3_7_9_14_6_1_4()
	ROUND_AVX2(Y12, Y13, Y14, Y15, Y10, Y4, Y5)
	LOAD_MSG_AVX2_7_3_13_11_9_1_12_14_2_5_4_15_6_10_0_8()
	ROUND_AVX2(Y12, Y13, Y14, Y15, Y10, Y4, Y5)
	LOAD_MSG_AVX2_9_5_2_10_0_7_4_15_14_11_6_3_1_12_8_13()
	ROUND_AVX2(Y12, Y13, Y14, Y15, Y10, Y4, Y5)
	LOAD_MSG_AVX2_2_6_0_8_12_10_11_3_4_7_15_1_13_5_14_9()
	ROUND_AVX2(Y12, Y13, Y14, Y15, Y10, Y4, Y5)
	LOAD_MSG_AVX2_12_1_14_4_5_15_13_10_0_6_9_8_7_3_2_11()
	ROUND_AVX2(Y12, Y13, Y14, Y15, Y10, Y4, Y5)
	LOAD_MSG_AVX2_13_7_12_3_11_14_1_9_5_15_8_2_0_4_6_10()
	ROUND_AVX2(Y12, Y13, Y14, Y15, Y10, Y4, Y5)
	LOAD_MSG_AVX2_6_14_11_0_15_9_3_8_12_13_1_10_2_7_4_5()
	ROUND_AVX2(Y12, Y13, Y14, Y15, Y10, Y4, Y5)
	LOAD_MSG_AVX2_10_8_7_1_2_4_6_5_15_9_3_13_11_14_12_0()
	ROUND_AVX2(Y12, Y13, Y14, Y15, Y10, Y4, Y5)

	ROUND_AVX2(Mem{Base: DX}.Offset(32), Mem{Base: DX}.Offset(64), Mem{Base: DX}.Offset(96), Mem{Base: DX}.Offset(128), Y10, Y4, Y5)
	ROUND_AVX2(Mem{Base: DX}.Offset(160), Mem{Base: DX}.Offset(192), Mem{Base: DX}.Offset(224), Mem{Base: DX}.Offset(256), Y10, Y4, Y5)

	VPXOR(Y0, Y8, Y8)
	VPXOR(Y1, Y9, Y9)
	VPXOR(Y2, Y8, Y8)
	VPXOR(Y3, Y9, Y9)

	LEAQ(Mem{Base: SI}.Offset(128), RSI)
	SUBQ(Imm(128), RDI)
	JNE(LabelRef("loop"))

	MOVQ(R8, Mem{Base: BX}.Offset(0))
	MOVQ(R9, Mem{Base: BX}.Offset(8))

	VMOVDQU(Y8, Mem{Base: AX}.Offset(0))
	VMOVDQU(Y9, Mem{Base: AX}.Offset(32))
	VZEROUPPER()

	RET()
}

func VPUNPCKLQDQ_X2_X2_X15() {
	BYTE(U8(0xC5))
	BYTE(U8(0x69))
	BYTE(U8(0x6C))
	BYTE(U8(0xFA))
}

func VPUNPCKLQDQ_X3_X3_X15() {
	BYTE(U8(0xC5))
	BYTE(U8(0x61))
	BYTE(U8(0x6C))
	BYTE(U8(0xFB))
}

func VPUNPCKLQDQ_X7_X7_X15() {
	BYTE(U8(0xC5))
	BYTE(U8(0x41))
	BYTE(U8(0x6C))
	BYTE(U8(0xFF))
}

func VPUNPCKLQDQ_X13_X13_X15() {
	BYTE(U8(0xC4))
	BYTE(U8(0x41))
	BYTE(U8(0x11))
	BYTE(U8(0x6C))
	BYTE(U8(0xFD))
}

func VPUNPCKLQDQ_X14_X14_X15() {
	BYTE(U8(0xC4))
	BYTE(U8(0x41))
	BYTE(U8(0x09))
	BYTE(U8(0x6C))
	BYTE(U8(0xFE))
}

func VPUNPCKHQDQ_X15_X2_X2() {
	BYTE(U8(0xC4))
	BYTE(U8(0xC1))
	BYTE(U8(0x69))
	BYTE(U8(0x6D))
	BYTE(U8(0xD7))
}

func VPUNPCKHQDQ_X15_X3_X3() {
	BYTE(U8(0xC4))
	BYTE(U8(0xC1))
	BYTE(U8(0x61))
	BYTE(U8(0x6D))
	BYTE(U8(0xDF))
}

func VPUNPCKHQDQ_X15_X6_X6() {
	BYTE(U8(0xC4))
	BYTE(U8(0xC1))
	BYTE(U8(0x49))
	BYTE(U8(0x6D))
	BYTE(U8(0xF7))
}

func VPUNPCKHQDQ_X15_X7_X7() {
	BYTE(U8(0xC4))
	BYTE(U8(0xC1))
	BYTE(U8(0x41))
	BYTE(U8(0x6D))
	BYTE(U8(0xFF))
}

func VPUNPCKHQDQ_X15_X3_X2() {
	BYTE(U8(0xC4))
	BYTE(U8(0xC1))
	BYTE(U8(0x61))
	BYTE(U8(0x6D))
	BYTE(U8(0xD7))
}

func VPUNPCKHQDQ_X15_X7_X6() {
	BYTE(U8(0xC4))
	BYTE(U8(0xC1))
	BYTE(U8(0x41))
	BYTE(U8(0x6D))
	BYTE(U8(0xF7))
}

func VPUNPCKHQDQ_X15_X13_X3() {
	BYTE(U8(0xC4))
	BYTE(U8(0xC1))
	BYTE(U8(0x11))
	BYTE(U8(0x6D))
	BYTE(U8(0xDF))
}

func VPUNPCKHQDQ_X15_X13_X7() {
	BYTE(U8(0xC4))
	BYTE(U8(0xC1))
	BYTE(U8(0x11))
	BYTE(U8(0x6D))
	BYTE(U8(0xFF))
}

func SHUFFLE_AVX() {
	VMOVDQA(X6, X13)
	VMOVDQA(X2, X14)
	VMOVDQA(X4, X6)
	VPUNPCKLQDQ_X13_X13_X15()
	VMOVDQA(X5, X4)
	VMOVDQA(X6, X5)
	VPUNPCKHQDQ_X15_X7_X6()
	VPUNPCKLQDQ_X7_X7_X15()
	VPUNPCKHQDQ_X15_X13_X7()
	VPUNPCKLQDQ_X3_X3_X15()
	VPUNPCKHQDQ_X15_X2_X2()
	VPUNPCKLQDQ_X14_X14_X15()
	VPUNPCKHQDQ_X15_X3_X3()
}

func SHUFFLE_AVX_INV() {
	VMOVDQA(X2, X13)
	VMOVDQA(X4, X14)
	VPUNPCKLQDQ_X2_X2_X15()
	VMOVDQA(X5, X4)
	VPUNPCKHQDQ_X15_X3_X2()
	VMOVDQA(X14, X5)
	VPUNPCKLQDQ_X3_X3_X15()
	VMOVDQA(X6, X14)
	VPUNPCKHQDQ_X15_X13_X3()
	VPUNPCKLQDQ_X7_X7_X15()
	VPUNPCKHQDQ_X15_X6_X6()
	VPUNPCKLQDQ_X14_X14_X15()
	VPUNPCKHQDQ_X15_X7_X7()
}

func HALF_ROUND_AVX(v0, v1, v2, v3, v4, v5, v6, v7 VecPhysical, m0, m1, m2, m3 Op, t0, c40, c48 VecPhysical) {
	VPADDQ(m0, v0, v0)
	VPADDQ(v2, v0, v0)
	VPADDQ(m1, v1, v1)
	VPADDQ(v3, v1, v1)
	VPXOR(v0, v6, v6)
	VPXOR(v1, v7, v7)
	VPSHUFD(I8(-79), v6, v6)
	VPSHUFD(I8(-79), v7, v7)
	VPADDQ(v6, v4, v4)
	VPADDQ(v7, v5, v5)
	VPXOR(v4, v2, v2)
	VPXOR(v5, v3, v3)
	VPSHUFB(c40, v2, v2)
	VPSHUFB(c40, v3, v3)
	VPADDQ(m2, v0, v0)
	VPADDQ(v2, v0, v0)
	VPADDQ(m3, v1, v1)
	VPADDQ(v3, v1, v1)
	VPXOR(v0, v6, v6)
	VPXOR(v1, v7, v7)
	VPSHUFB(c48, v6, v6)
	VPSHUFB(c48, v7, v7)
	VPADDQ(v6, v4, v4)
	VPADDQ(v7, v5, v5)
	VPXOR(v4, v2, v2)
	VPXOR(v5, v3, v3)
	VPADDQ(v2, v2, t0)
	VPSRLQ(Imm(63), v2, v2)
	VPXOR(t0, v2, v2)
	VPADDQ(v3, v3, t0)
	VPSRLQ(Imm(63), v3, v3)
	VPXOR(t0, v3, v3)
}

// load msg:
//
//	X12 = (i0, i1), X13 = (i2, i3), X14 = (i4, i5), X15 = (i6, i7)
//
// i0, i1, i2, i3, i4, i5, i6, i7 must not be 0
func LOAD_MSG_AVX(i0, i1, i2, i3, i4, i5, i6, i7 uint8) {
	VMOVQ_SI_X12(i0 * 8)
	VMOVQ_SI_X13(i2 * 8)
	VMOVQ_SI_X14(i4 * 8)
	VMOVQ_SI_X15(i6 * 8)
	VPINSRQ_1_SI_X12(i1 * 8)
	VPINSRQ_1_SI_X13(i3 * 8)
	VPINSRQ_1_SI_X14(i5 * 8)
	VPINSRQ_1_SI_X15(i7 * 8)
}

// load msg:
//
//	X12 = (0, 2), X13 = (4, 6), X14 = (1, 3), X15 = (5, 7)
func LOAD_MSG_AVX_0_2_4_6_1_3_5_7() {
	VMOVQ_SI_X12_0()
	VMOVQ_SI_X13(4 * 8)
	VMOVQ_SI_X14(1 * 8)
	VMOVQ_SI_X15(5 * 8)
	VPINSRQ_1_SI_X12(2 * 8)
	VPINSRQ_1_SI_X13(6 * 8)
	VPINSRQ_1_SI_X14(3 * 8)
	VPINSRQ_1_SI_X15(7 * 8)
}

// load msg:
//
//	X12 = (1, 0), X13 = (11, 5), X14 = (12, 2), X15 = (7, 3)
func LOAD_MSG_AVX_1_0_11_5_12_2_7_3() {
	VPSHUFD(Imm(0x4E), Mem{Base: SI}.Offset(0*8), X12)
	VMOVQ_SI_X13(11 * 8)
	VMOVQ_SI_X14(12 * 8)
	VMOVQ_SI_X15(7 * 8)
	VPINSRQ_1_SI_X13(5 * 8)
	VPINSRQ_1_SI_X14(2 * 8)
	VPINSRQ_1_SI_X15(3 * 8)
}

// load msg:
//
//	X12 = (11, 12), X13 = (5, 15), X14 = (8, 0), X15 = (2, 13)
func LOAD_MSG_AVX_11_12_5_15_8_0_2_13() {
	VMOVDQU(Mem{Base: SI}.Offset(11*8), X12)
	VMOVQ_SI_X13(5 * 8)
	VMOVQ_SI_X14(8 * 8)
	VMOVQ_SI_X15(2 * 8)
	VPINSRQ_1_SI_X13(15 * 8)
	VPINSRQ_1_SI_X14_0()
	VPINSRQ_1_SI_X15(13 * 8)
}

// load msg:
//
//	X12 = (2, 5), X13 = (4, 15), X14 = (6, 10), X15 = (0, 8)
func LOAD_MSG_AVX_2_5_4_15_6_10_0_8() {
	VMOVQ_SI_X12(2 * 8)
	VMOVQ_SI_X13(4 * 8)
	VMOVQ_SI_X14(6 * 8)
	VMOVQ_SI_X15_0()
	VPINSRQ_1_SI_X12(5 * 8)
	VPINSRQ_1_SI_X13(15 * 8)
	VPINSRQ_1_SI_X14(10 * 8)
	VPINSRQ_1_SI_X15(8 * 8)
}

// load msg:
//
//	X12 = (9, 5), X13 = (2, 10), X14 = (0, 7), X15 = (4, 15)
func LOAD_MSG_AVX_9_5_2_10_0_7_4_15() {
	VMOVQ_SI_X12(9 * 8)
	VMOVQ_SI_X13(2 * 8)
	VMOVQ_SI_X14_0()
	VMOVQ_SI_X15(4 * 8)
	VPINSRQ_1_SI_X12(5 * 8)
	VPINSRQ_1_SI_X13(10 * 8)
	VPINSRQ_1_SI_X14(7 * 8)
	VPINSRQ_1_SI_X15(15 * 8)
}

// load msg:
//
//	X12 = (2, 6), X13 = (0, 8), X14 = (12, 10), X15 = (11, 3)
func LOAD_MSG_AVX_2_6_0_8_12_10_11_3() {
	VMOVQ_SI_X12(2 * 8)
	VMOVQ_SI_X13_0()
	VMOVQ_SI_X14(12 * 8)
	VMOVQ_SI_X15(11 * 8)
	VPINSRQ_1_SI_X12(6 * 8)
	VPINSRQ_1_SI_X13(8 * 8)
	VPINSRQ_1_SI_X14(10 * 8)
	VPINSRQ_1_SI_X15(3 * 8)
}

// load msg:
//
//	X12 = (0, 6), X13 = (9, 8), X14 = (7, 3), X15 = (2, 11)
func LOAD_MSG_AVX_0_6_9_8_7_3_2_11() {
	MOVQ(Mem{Base: SI}.Offset(0*8), X12)
	VPSHUFD(Imm(0x4E), Mem{Base: SI}.Offset(8*8), X13)
	MOVQ(Mem{Base: SI}.Offset(7*8), X14)
	MOVQ(Mem{Base: SI}.Offset(2*8), X15)
	VPINSRQ_1_SI_X12(6 * 8)
	VPINSRQ_1_SI_X14(3 * 8)
	VPINSRQ_1_SI_X15(11 * 8)
}

// load msg:
//
//	X12 = (6, 14), X13 = (11, 0), X14 = (15, 9), X15 = (3, 8)
func LOAD_MSG_AVX_6_14_11_0_15_9_3_8() {
	MOVQ(Mem{Base: SI}.Offset(6*8), X12)
	MOVQ(Mem{Base: SI}.Offset(11*8), X13)
	MOVQ(Mem{Base: SI}.Offset(15*8), X14)
	MOVQ(Mem{Base: SI}.Offset(3*8), X15)
	VPINSRQ_1_SI_X12(14 * 8)
	VPINSRQ_1_SI_X13_0()
	VPINSRQ_1_SI_X14(9 * 8)
	VPINSRQ_1_SI_X15(8 * 8)
}

// load msg:
//
//	X12 = (5, 15), X13 = (8, 2), X14 = (0, 4), X15 = (6, 10)
func LOAD_MSG_AVX_5_15_8_2_0_4_6_10() {
	MOVQ(Mem{Base: SI}.Offset(5*8), X12)
	MOVQ(Mem{Base: SI}.Offset(8*8), X13)
	MOVQ(Mem{Base: SI}.Offset(0*8), X14)
	MOVQ(Mem{Base: SI}.Offset(6*8), X15)
	VPINSRQ_1_SI_X12(15 * 8)
	VPINSRQ_1_SI_X13(2 * 8)
	VPINSRQ_1_SI_X14(4 * 8)
	VPINSRQ_1_SI_X15(10 * 8)
}

// load msg:
//
//	X12 = (12, 13), X13 = (1, 10), X14 = (2, 7), X15 = (4, 5)
func LOAD_MSG_AVX_12_13_1_10_2_7_4_5() {
	VMOVDQU(Mem{Base: SI}.Offset(12*8), X12)
	MOVQ(Mem{Base: SI}.Offset(1*8), X13)
	MOVQ(Mem{Base: SI}.Offset(2*8), X14)
	VPINSRQ_1_SI_X13(10 * 8)
	VPINSRQ_1_SI_X14(7 * 8)
	VMOVDQU(Mem{Base: SI}.Offset(4*8), X15)
}

// load msg:
//
//	X12 = (15, 9), X13 = (3, 13), X14 = (11, 14), X15 = (12, 0)
func LOAD_MSG_AVX_15_9_3_13_11_14_12_0() {
	MOVQ(Mem{Base: SI}.Offset(15*8), X12)
	MOVQ(Mem{Base: SI}.Offset(3*8), X13)
	MOVQ(Mem{Base: SI}.Offset(11*8), X14)
	MOVQ(Mem{Base: SI}.Offset(12*8), X15)
	VPINSRQ_1_SI_X12(9 * 8)
	VPINSRQ_1_SI_X13(13 * 8)
	VPINSRQ_1_SI_X14(14 * 8)
	VPINSRQ_1_SI_X15_0()
}

func hashBlocksAVX() {
	Implement("hashBlocksAVX")
	Attributes(4)
	AllocLocal(288) // frame size = 272 + 16 byte alignment

	Load(Param("h"), RAX)
	Load(Param("c"), RBX)
	Load(Param("flag"), RCX)
	Load(Param("blocks").Base(), RSI)
	Load(Param("blocks").Len(), RDI)

	MOVQ(RSP, R10)
	ADDQ(Imm(15), R10)
	ANDQ(I32(^15), R10)

	AVX_c40 := AVX_c40_DATA()
	AVX_c48 := AVX_c48_DATA()
	VMOVDQU(AVX_c40, X0)
	VMOVDQU(AVX_c48, X1)
	VMOVDQA(X0, X8)
	VMOVDQA(X1, X9)

	AVX_iv3 := AVX_iv3_DATA()
	VMOVDQU(AVX_iv3, X0)
	VMOVDQA(X0, Mem{Base: R10}.Offset(0))
	XORQ(RCX, Mem{Base: R10}.Offset(0)) // 0(R10) = ·AVX_iv3 ^ (CX || 0)

	VMOVDQU(Mem{Base: AX}.Offset(0), X10)
	VMOVDQU(Mem{Base: AX}.Offset(16), X11)
	VMOVDQU(Mem{Base: AX}.Offset(32), X2)
	VMOVDQU(Mem{Base: AX}.Offset(48), X3)

	MOVQ(Mem{Base: BX}.Offset(0), R8)
	MOVQ(Mem{Base: BX}.Offset(8), R9)

	loop_AVX()
	noinc_AVX()
}

func loop_AVX() {
	Label("loop")
	ADDQ(Imm(128), R8)
	CMPQ(R8, Imm(128))
	JGE(LabelRef("noinc"))
	INCQ(R9)
}

func noinc_AVX() {
	Label("noinc")
	VMOVQ_R8_X15()
	VPINSRQ_1_R9_X15()

	AVX_iv0 := AVX_iv0_DATA()
	AVX_iv1 := AVX_iv1_DATA()
	AVX_iv2 := AVX_iv2_DATA()
	VMOVDQA(X10, X0)
	VMOVDQA(X11, X1)
	VMOVDQU(AVX_iv0, X4)
	VMOVDQU(AVX_iv1, X5)
	VMOVDQU(AVX_iv2, X6)

	VPXOR(X15, X6, X6)
	VMOVDQA(Mem{Base: R10}.Offset(0), X7)

	LOAD_MSG_AVX_0_2_4_6_1_3_5_7()
	VMOVDQA(X12, Mem{Base: R10}.Offset(16))
	VMOVDQA(X13, Mem{Base: R10}.Offset(32))
	VMOVDQA(X14, Mem{Base: R10}.Offset(48))
	VMOVDQA(X15, Mem{Base: R10}.Offset(64))
	HALF_ROUND_AVX(X0, X1, X2, X3, X4, X5, X6, X7, X12, X13, X14, X15, X15, X8, X9)
	SHUFFLE_AVX()
	LOAD_MSG_AVX(8, 10, 12, 14, 9, 11, 13, 15)
	VMOVDQA(X12, Mem{Base: R10}.Offset(80))
	VMOVDQA(X13, Mem{Base: R10}.Offset(96))
	VMOVDQA(X14, Mem{Base: R10}.Offset(112))
	VMOVDQA(X15, Mem{Base: R10}.Offset(128))
	HALF_ROUND_AVX(X0, X1, X2, X3, X4, X5, X6, X7, X12, X13, X14, X15, X15, X8, X9)
	SHUFFLE_AVX_INV()

	LOAD_MSG_AVX(14, 4, 9, 13, 10, 8, 15, 6)
	VMOVDQA(X12, Mem{Base: R10}.Offset(144))
	VMOVDQA(X13, Mem{Base: R10}.Offset(160))
	VMOVDQA(X14, Mem{Base: R10}.Offset(176))
	VMOVDQA(X15, Mem{Base: R10}.Offset(192))
	HALF_ROUND_AVX(X0, X1, X2, X3, X4, X5, X6, X7, X12, X13, X14, X15, X15, X8, X9)
	SHUFFLE_AVX()
	LOAD_MSG_AVX_1_0_11_5_12_2_7_3()
	VMOVDQA(X12, Mem{Base: R10}.Offset(208))
	VMOVDQA(X13, Mem{Base: R10}.Offset(224))
	VMOVDQA(X14, Mem{Base: R10}.Offset(240))
	VMOVDQA(X15, Mem{Base: R10}.Offset(256))
	HALF_ROUND_AVX(X0, X1, X2, X3, X4, X5, X6, X7, X12, X13, X14, X15, X15, X8, X9)
	SHUFFLE_AVX_INV()

	LOAD_MSG_AVX_11_12_5_15_8_0_2_13()
	HALF_ROUND_AVX(X0, X1, X2, X3, X4, X5, X6, X7, X12, X13, X14, X15, X15, X8, X9)
	SHUFFLE_AVX()
	LOAD_MSG_AVX(10, 3, 7, 9, 14, 6, 1, 4)
	HALF_ROUND_AVX(X0, X1, X2, X3, X4, X5, X6, X7, X12, X13, X14, X15, X15, X8, X9)
	SHUFFLE_AVX_INV()

	LOAD_MSG_AVX(7, 3, 13, 11, 9, 1, 12, 14)
	HALF_ROUND_AVX(X0, X1, X2, X3, X4, X5, X6, X7, X12, X13, X14, X15, X15, X8, X9)
	SHUFFLE_AVX()
	LOAD_MSG_AVX_2_5_4_15_6_10_0_8()
	HALF_ROUND_AVX(X0, X1, X2, X3, X4, X5, X6, X7, X12, X13, X14, X15, X15, X8, X9)
	SHUFFLE_AVX_INV()

	LOAD_MSG_AVX_9_5_2_10_0_7_4_15()
	HALF_ROUND_AVX(X0, X1, X2, X3, X4, X5, X6, X7, X12, X13, X14, X15, X15, X8, X9)
	SHUFFLE_AVX()
	LOAD_MSG_AVX(14, 11, 6, 3, 1, 12, 8, 13)
	HALF_ROUND_AVX(X0, X1, X2, X3, X4, X5, X6, X7, X12, X13, X14, X15, X15, X8, X9)
	SHUFFLE_AVX_INV()

	LOAD_MSG_AVX_2_6_0_8_12_10_11_3()
	HALF_ROUND_AVX(X0, X1, X2, X3, X4, X5, X6, X7, X12, X13, X14, X15, X15, X8, X9)
	SHUFFLE_AVX()
	LOAD_MSG_AVX(4, 7, 15, 1, 13, 5, 14, 9)
	HALF_ROUND_AVX(X0, X1, X2, X3, X4, X5, X6, X7, X12, X13, X14, X15, X15, X8, X9)
	SHUFFLE_AVX_INV()

	LOAD_MSG_AVX(12, 1, 14, 4, 5, 15, 13, 10)
	HALF_ROUND_AVX(X0, X1, X2, X3, X4, X5, X6, X7, X12, X13, X14, X15, X15, X8, X9)
	SHUFFLE_AVX()
	LOAD_MSG_AVX_0_6_9_8_7_3_2_11()
	HALF_ROUND_AVX(X0, X1, X2, X3, X4, X5, X6, X7, X12, X13, X14, X15, X15, X8, X9)
	SHUFFLE_AVX_INV()

	LOAD_MSG_AVX(13, 7, 12, 3, 11, 14, 1, 9)
	HALF_ROUND_AVX(X0, X1, X2, X3, X4, X5, X6, X7, X12, X13, X14, X15, X15, X8, X9)
	SHUFFLE_AVX()
	LOAD_MSG_AVX_5_15_8_2_0_4_6_10()
	HALF_ROUND_AVX(X0, X1, X2, X3, X4, X5, X6, X7, X12, X13, X14, X15, X15, X8, X9)
	SHUFFLE_AVX_INV()

	LOAD_MSG_AVX_6_14_11_0_15_9_3_8()
	HALF_ROUND_AVX(X0, X1, X2, X3, X4, X5, X6, X7, X12, X13, X14, X15, X15, X8, X9)
	SHUFFLE_AVX()
	LOAD_MSG_AVX_12_13_1_10_2_7_4_5()
	HALF_ROUND_AVX(X0, X1, X2, X3, X4, X5, X6, X7, X12, X13, X14, X15, X15, X8, X9)
	SHUFFLE_AVX_INV()

	LOAD_MSG_AVX(10, 8, 7, 1, 2, 4, 6, 5)
	HALF_ROUND_AVX(X0, X1, X2, X3, X4, X5, X6, X7, X12, X13, X14, X15, X15, X8, X9)
	SHUFFLE_AVX()
	LOAD_MSG_AVX_15_9_3_13_11_14_12_0()
	HALF_ROUND_AVX(X0, X1, X2, X3, X4, X5, X6, X7, X12, X13, X14, X15, X15, X8, X9)
	SHUFFLE_AVX_INV()

	HALF_ROUND_AVX(X0, X1, X2, X3, X4, X5, X6, X7, Mem{Base: R10}.Offset(16), Mem{Base: R10}.Offset(32), Mem{Base: R10}.Offset(48), Mem{Base: R10}.Offset(64), X15, X8, X9)
	SHUFFLE_AVX()
	HALF_ROUND_AVX(X0, X1, X2, X3, X4, X5, X6, X7, Mem{Base: R10}.Offset(80), Mem{Base: R10}.Offset(96), Mem{Base: R10}.Offset(112), Mem{Base: R10}.Offset(128), X15, X8, X9)
	SHUFFLE_AVX_INV()

	HALF_ROUND_AVX(X0, X1, X2, X3, X4, X5, X6, X7, Mem{Base: R10}.Offset(144), Mem{Base: R10}.Offset(160), Mem{Base: R10}.Offset(176), Mem{Base: R10}.Offset(192), X15, X8, X9)
	SHUFFLE_AVX()
	HALF_ROUND_AVX(X0, X1, X2, X3, X4, X5, X6, X7, Mem{Base: R10}.Offset(208), Mem{Base: R10}.Offset(224), Mem{Base: R10}.Offset(240), Mem{Base: R10}.Offset(256), X15, X8, X9)
	SHUFFLE_AVX_INV()

	VMOVDQU(Mem{Base: AX}.Offset(32), X14)
	VMOVDQU(Mem{Base: AX}.Offset(48), X15)
	VPXOR(X0, X10, X10)
	VPXOR(X1, X11, X11)
	VPXOR(X2, X14, X14)
	VPXOR(X3, X15, X15)
	VPXOR(X4, X10, X10)
	VPXOR(X5, X11, X11)
	VPXOR(X6, X14, X2)
	VPXOR(X7, X15, X3)
	VMOVDQU(X2, Mem{Base: AX}.Offset(32))
	VMOVDQU(X3, Mem{Base: AX}.Offset(48))

	LEAQ(Mem{Base: SI}.Offset(128), RSI)
	SUBQ(Imm(128), RDI)
	JNE(LabelRef("loop"))

	VMOVDQU(X10, Mem{Base: AX}.Offset(0))
	VMOVDQU(X11, Mem{Base: AX}.Offset(16))

	MOVQ(R8, Mem{Base: BX}.Offset(0))
	MOVQ(R9, Mem{Base: BX}.Offset(8))
	VZEROUPPER()

	RET()
}

// ##~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~DATA SECTION~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~##

var (
	AVX2_iv0_ptr,
	AVX2_iv1_ptr,
	AVX2_c40_ptr,
	AVX2_c48_ptr,

	AVX_iv0_ptr,
	AVX_iv1_ptr,
	AVX_iv2_ptr,
	AVX_iv3_ptr,
	AVX_c40_ptr,
	AVX_c48_ptr *Mem
)

func AVX2_iv0_DATA() Mem {
	if AVX2_iv0_ptr != nil {
		return *AVX2_iv0_ptr
	}
	AVX2_iv0 := GLOBL(ThatPeskyUnicodeDot+"AVX2_iv0", NOPTR|RODATA)
	DATA(0x00, U64(0x6a09e667f3bcc908))
	DATA(0x08, U64(0xbb67ae8584caa73b))
	DATA(0x10, U64(0x3c6ef372fe94f82b))
	DATA(0x18, U64(0xa54ff53a5f1d36f1))
	return AVX2_iv0
}

func AVX2_iv1_DATA() Mem {
	if AVX2_iv1_ptr != nil {
		return *AVX2_iv1_ptr
	}
	AVX2_iv1 := GLOBL(ThatPeskyUnicodeDot+"AVX2_iv1", NOPTR|RODATA)
	DATA(0x00, U64(0x510e527fade682d1))
	DATA(0x08, U64(0x9b05688c2b3e6c1f))
	DATA(0x10, U64(0x1f83d9abfb41bd6b))
	DATA(0x18, U64(0x5be0cd19137e2179))
	return AVX2_iv1
}

func AVX2_c40_DATA() Mem {
	if AVX2_c40_ptr != nil {
		return *AVX2_c40_ptr
	}
	AVX2_c40 := GLOBL(ThatPeskyUnicodeDot+"AVX2_c40", NOPTR|RODATA)
	DATA(0x00, U64(0x0201000706050403))
	DATA(0x08, U64(0x0a09080f0e0d0c0b))
	DATA(0x10, U64(0x0201000706050403))
	DATA(0x18, U64(0x0a09080f0e0d0c0b))
	return AVX2_c40
}

func AVX2_c48_DATA() Mem {
	if AVX2_c48_ptr != nil {
		return *AVX2_c48_ptr
	}
	AVX2_c48 := GLOBL(ThatPeskyUnicodeDot+"AVX2_c48", NOPTR|RODATA)
	DATA(0x00, U64(0x0100070605040302))
	DATA(0x08, U64(0x09080f0e0d0c0b0a))
	DATA(0x10, U64(0x0100070605040302))
	DATA(0x18, U64(0x09080f0e0d0c0b0a))
	return AVX2_c48
}

func AVX_iv0_DATA() Mem {
	if AVX_iv0_ptr != nil {
		return *AVX_iv0_ptr
	}
	AVX_iv0 := GLOBL(ThatPeskyUnicodeDot+"AVX_iv0", NOPTR|RODATA)
	DATA(0x00, U64(0x6a09e667f3bcc908))
	DATA(0x08, U64(0xbb67ae8584caa73b))
	return AVX_iv0
}

func AVX_iv1_DATA() Mem {
	if AVX_iv1_ptr != nil {
		return *AVX_iv1_ptr
	}
	AVX_iv1 := GLOBL(ThatPeskyUnicodeDot+"AVX_iv1", NOPTR|RODATA)
	DATA(0x00, U64(0x3c6ef372fe94f82b))
	DATA(0x08, U64(0xa54ff53a5f1d36f1))
	return AVX_iv1
}

func AVX_iv2_DATA() Mem {
	if AVX_iv2_ptr != nil {
		return *AVX_iv2_ptr
	}
	AVX_iv2 := GLOBL(ThatPeskyUnicodeDot+"AVX_iv2", NOPTR|RODATA)
	DATA(0x00, U64(0x510e527fade682d1))
	DATA(0x08, U64(0x9b05688c2b3e6c1f))
	return AVX_iv2
}

func AVX_iv3_DATA() Mem {
	if AVX_iv3_ptr != nil {
		return *AVX_iv3_ptr
	}
	AVX_iv3 := GLOBL(ThatPeskyUnicodeDot+"AVX_iv3", NOPTR|RODATA)
	DATA(0x00, U64(0x1f83d9abfb41bd6b))
	DATA(0x08, U64(0x5be0cd19137e2179))
	return AVX_iv3
}

func AVX_c40_DATA() Mem {
	if AVX_c40_ptr != nil {
		return *AVX_c40_ptr
	}
	AVX_c40 := GLOBL(ThatPeskyUnicodeDot+"AVX_c40", NOPTR|RODATA)
	DATA(0x00, U64(0x0201000706050403))
	DATA(0x08, U64(0x0a09080f0e0d0c0b))
	return AVX_c40
}

func AVX_c48_DATA() Mem {
	if AVX_c48_ptr != nil {
		return *AVX_c48_ptr
	}
	AVX_c48 := GLOBL(ThatPeskyUnicodeDot+"AVX_c48", NOPTR|RODATA)
	DATA(0x00, U64(0x0100070605040302))
	DATA(0x08, U64(0x09080f0e0d0c0b0a))
	return AVX_c48
}
