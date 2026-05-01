// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package symcost

import (
	"encoding/binary"
	"testing"
)

// encAdrp returns a synthesized ADRP instruction word for the
// given destination register and 21-bit signed immediate (which
// the decoder then shifts left by 12 to produce a page-aligned
// byte address).
//
// The encoding (ARM ARM C6.2.10):
//
//	bit 31  = 1
//	30..29  = immlo (low 2 bits of imm21)
//	28..24  = 10000
//	23..5   = immhi (high 19 bits of imm21)
//	4..0    = Rd
func encAdrp(rd int, imm21 int64) uint32 {
	mask21 := int64((1 << 21) - 1)
	imm := uint32(imm21 & mask21)
	immlo := imm & 0x3
	immhi := (imm >> 2) & 0x7FFFF
	return 0x90000000 | (immlo << 29) | (immhi << 5) | uint32(rd&0x1F)
}

// encAddImm returns a synthesized 64-bit ADD-immediate instruction
// word `ADD Xd, Xn, #imm12`. sh=0 (Go's emit form for static-data
// addressing).
//
//	31     = sf (1 for 64-bit)
//	30..23 = 00100010
//	22     = sh (0)
//	21..10 = imm12
//	9..5   = Rn
//	4..0   = Rd
func encAddImm(rd, rn int, imm12 int64) uint32 {
	return 0x91000000 |
		(uint32(imm12&0xFFF) << 10) |
		(uint32(rn&0x1F) << 5) |
		uint32(rd&0x1F)
}

// TestAdrpDecode checks decoding of canonical ADRP encodings,
// including the sign-extension of the 21-bit immediate and the
// extraction of the destination register.
func TestAdrpDecode(t *testing.T) {
	tests := []struct {
		name    string
		ins     uint32
		wantRd  int
		wantImm int64
		wantOK  bool
	}{
		{
			// imm21 = 0x100 → imm = 0x100 << 12 = 0x100000.
			name:    "ADRP X0, page=0x100",
			ins:     encAdrp(0, 0x100),
			wantRd:  0,
			wantImm: 0x100000,
			wantOK:  true,
		},
		{
			// imm21 = 0x10 → imm = 0x10 << 12 = 0x10000.
			name:    "ADRP X3, page=0x10",
			ins:     encAdrp(3, 0x10),
			wantRd:  3,
			wantImm: 0x10000,
			wantOK:  true,
		},
		{
			// Negative imm21 (sign-extended): -1 → -0x1000.
			name:    "ADRP X5, page=-1",
			ins:     encAdrp(5, -1),
			wantRd:  5,
			wantImm: -0x1000,
			wantOK:  true,
		},
		{
			// Not an ADRP: a plain ADD is rejected.
			name:   "not ADRP",
			ins:    0x91000000,
			wantOK: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rd, imm, ok := adrpDecode(armInstr(tt.ins))
			if ok != tt.wantOK {
				t.Errorf("ok=%v, want %v", ok, tt.wantOK)
				return
			}
			if !ok {
				return
			}
			if rd != tt.wantRd {
				t.Errorf("rd=%d, want %d", rd, tt.wantRd)
			}
			if imm != tt.wantImm {
				t.Errorf("imm=%#x, want %#x", imm, tt.wantImm)
			}
		})
	}
}

// TestAddImmDecode checks decoding of the unshifted ADD-immediate
// form Go uses to complete a page+offset addressing pair.
func TestAddImmDecode(t *testing.T) {
	tests := []struct {
		name    string
		ins     uint32
		wantRd  int
		wantRn  int
		wantImm int64
		wantOK  bool
	}{
		{
			name:    "ADD X0, X0, #0x123",
			ins:     encAddImm(0, 0, 0x123),
			wantRd:  0,
			wantRn:  0,
			wantImm: 0x123,
			wantOK:  true,
		},
		{
			name:    "ADD X3, X3, #0x100",
			ins:     encAddImm(3, 3, 0x100),
			wantRd:  3,
			wantRn:  3,
			wantImm: 0x100,
			wantOK:  true,
		},
		{
			// Shifted ADD (sh=1) is rejected because Go doesn't
			// emit it for static-data addressing.
			name:   "ADD with sh=1 rejected",
			ins:    encAddImm(0, 0, 0) | (1 << 22),
			wantOK: false,
		},
		{
			// SUB-imm has a different opcode and is rejected.
			name:   "SUB rejected",
			ins:    0xD1000000,
			wantOK: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rd, rn, imm, ok := addImmDecode(armInstr(tt.ins))
			if ok != tt.wantOK {
				t.Errorf("ok=%v, want %v", ok, tt.wantOK)
				return
			}
			if !ok {
				return
			}
			if rd != tt.wantRd || rn != tt.wantRn || imm != tt.wantImm {
				t.Errorf("got rd=%d rn=%d imm=%#x; want rd=%d rn=%d imm=%#x",
					rd, rn, imm, tt.wantRd, tt.wantRn, tt.wantImm)
			}
		})
	}
}

// TestScanArm64RefsBasic verifies the scanner picks up a single
// ADRP+ADD pair as one resolved address.
func TestScanArm64RefsBasic(t *testing.T) {
	// At PC 0x100000:
	//   ADRP X3, page=0x4 (→ X3 = 0x100000 & ~0xFFF + 0x4000 = 0x104000)
	//   ADD  X3, X3, #0x100 (→ X3 = 0x104100)
	pc := uint64(0x100000)
	buf := make([]byte, 8)
	binary.LittleEndian.PutUint32(buf[0:], encAdrp(3, 0x4))
	binary.LittleEndian.PutUint32(buf[4:], encAddImm(3, 3, 0x100))

	refs := scanArm64Refs(pc, buf)
	if len(refs) != 1 {
		t.Fatalf("got %d refs, want 1: %v", len(refs), refs)
	}
	want := uint64(0x104100)
	if refs[0] != want {
		t.Errorf("ref = %#x, want %#x", refs[0], want)
	}
}

// TestScanArm64RefsPairs verifies that two ADRP+ADD pairs
// (separated by an unrelated instruction) each produce a distinct
// reference, and that the unrelated instruction doesn't disturb
// register state for the second pair.
func TestScanArm64RefsPairs(t *testing.T) {
	pc := uint64(0x200000)
	buf := make([]byte, 5*4)
	binary.LittleEndian.PutUint32(buf[0:], encAdrp(1, 0x10))       // X1 = 0x210000
	binary.LittleEndian.PutUint32(buf[4:], encAddImm(1, 1, 0x10))  // X1 = 0x210010
	binary.LittleEndian.PutUint32(buf[8:], 0xD503201F)             // NOP
	binary.LittleEndian.PutUint32(buf[12:], encAdrp(2, 0x20))      // X2 = 0x220000 (page-aligned)
	binary.LittleEndian.PutUint32(buf[16:], encAddImm(2, 2, 0x20)) // X2 = 0x220020

	refs := scanArm64Refs(pc, buf)
	got := map[uint64]bool{}
	for _, r := range refs {
		got[r] = true
	}
	for _, want := range []uint64{0x210010, 0x220020} {
		if !got[want] {
			t.Errorf("expected ref %#x, got %v", want, refs)
		}
	}
}

// TestScanArm64RefsDifferentRegisters verifies that ADD using a
// source register that didn't have a recent ADRP does not create
// a phantom reference.
func TestScanArm64RefsDifferentRegisters(t *testing.T) {
	pc := uint64(0x300000)
	buf := make([]byte, 3*4)
	// ADRP X1, page=0x10 → X1 holds 0x310000
	binary.LittleEndian.PutUint32(buf[0:], encAdrp(1, 0x10))
	// ADD  X2, X2, #0x40 → uses X2 as source; we never set X2,
	// so this should NOT produce a ref.
	binary.LittleEndian.PutUint32(buf[4:], encAddImm(2, 2, 0x40))
	// ADD X1, X1, #0x80 → completes the X1 pair → 0x310080.
	binary.LittleEndian.PutUint32(buf[8:], encAddImm(1, 1, 0x80))

	refs := scanArm64Refs(pc, buf)
	if len(refs) != 1 {
		t.Fatalf("got %d refs, want 1: %v", len(refs), refs)
	}
	if refs[0] != 0x310080 {
		t.Errorf("ref = %#x, want 0x310080", refs[0])
	}
}
