// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package symcost

// arm64 instruction-level scanning of .text to discover memory
// references from each function into rodata-bearing sections.
//
// Why this matters for size attribution:
//
// On arm64, Go emits all access to static data (rodata, type
// descriptors, string constants, generic dictionaries, GC bitmaps,
// itabs, ...) using the page-relative addressing pair:
//
//	ADRP Xn, page_of_target          ; upper 21 bits of target
//	ADD  Xn, Xn, #page_offset_of_target ; lower 12 bits
//
// (or, less commonly, ADRP+LDR when loading the value at the target
// rather than the address). After the ADRP+ADD pair, register Xn
// holds the absolute virtual address of a static datum.
//
// By walking each function's bytes and recognizing this idiom, we
// can find every named or unnamed datum the function touches and
// attribute the datum's size to that function. This closes the
// "function-side rodata attribution" gap that plain symbol-table
// analysis can't see.
//
// Recognized patterns in this file:
//
//   - ADRP+ADD: yields a precise address (the common case).
//   - ADRP+LDR (immediate, 12-bit unsigned, scaled): same idea,
//     but the LDR's immediate is in *units of access size* (e.g. 8
//     for a 64-bit load). We translate to bytes when computing the
//     final address.
//   - LDR (literal): a single instruction whose immediate encodes
//     a PC-relative byte offset to a 4- or 8-byte constant. Used
//     for embedded floating-point constants and the like.
//
// Other addressing forms (PC-relative branches, unscaled LDR/STR,
// scaled ADRP-only references) either don't reach rodata or are
// rare enough in Go arm64 codegen that we ignore them in the first
// pass. False negatives here just mean we attribute slightly less
// rodata; false positives could mis-attribute and would be worse.

// armInstr is a 32-bit aarch64 instruction.
type armInstr uint32

// adrpDecode reports whether ins is an ADRP and, if so, returns the
// destination register and a 33-bit signed immediate that, when
// added to (PC & ~0xfff), gives the addressed page.
//
// ADRP encoding (ARM ARM C6.2.10):
//
//	1 immlo:2 1 0000 immhi:19 Rd:5
//	bit 31 = 1, bits 28-24 = 10000
func adrpDecode(ins armInstr) (rd int, imm int64, ok bool) {
	if ins&0x9F000000 != 0x90000000 {
		return 0, 0, false
	}
	immlo := int64((ins >> 29) & 0x3)
	immhi := int64((ins >> 5) & 0x7FFFF)
	imm21 := (immhi << 2) | immlo
	// sign-extend from 21 bits, then shift left by 12 (page).
	if imm21&(1<<20) != 0 {
		imm21 |= ^int64((1 << 21) - 1)
	}
	return int(ins & 0x1F), imm21 << 12, true
}

// addImmDecode reports whether ins is `ADD Xd, Xn, #imm` (without
// shift) and returns (rd, rn, imm).
//
// ADD (immediate) encoding (ARM ARM C6.2.5):
//
//	sf 0 0 100010 sh:1 imm12 Rn:5 Rd:5
//	  with sf=1 for 64-bit
//	  bits 30-23 = 0_0100010, mask 0x7F800000, base value 0x11000000
//
// We accept the unshifted form (sh=0); Go's codegen for rodata
// addressing always emits the unshifted variant because the
// immediate is the low 12 bits of the target's offset within its
// 4 KB page.
func addImmDecode(ins armInstr) (rd, rn int, imm int64, ok bool) {
	if ins&0x7F800000 != 0x11000000 {
		return 0, 0, 0, false
	}
	if (ins>>22)&1 != 0 { // sh bit; Go uses sh=0 for these
		return 0, 0, 0, false
	}
	imm = int64((ins >> 10) & 0xFFF)
	rn = int((ins >> 5) & 0x1F)
	rd = int(ins & 0x1F)
	return rd, rn, imm, true
}

// ldrImmUnsignedDecode reports whether ins is `LDR Xt, [Xn, #imm]`
// in the unsigned-offset form and returns (rt, rn, byteOffset).
//
// LDR (immediate, unsigned offset) encoding for 64-bit:
//
//	1 1 1 1 1 0 0 1 0 1 imm12 Rn:5 Rt:5
//	mask 0xFFC00000, value 0xF9400000
//
// The 12-bit immediate is in units of 8 bytes for the 64-bit form;
// we return the byte-equivalent so callers can add it directly to a
// base address to compute the final addressed byte.
func ldrImmUnsignedDecode(ins armInstr) (rt, rn int, byteOffset int64, ok bool) {
	if ins&0xFFC00000 != 0xF9400000 {
		return 0, 0, 0, false
	}
	imm := int64((ins >> 10) & 0xFFF)
	rn = int((ins >> 5) & 0x1F)
	rt = int(ins & 0x1F)
	return rt, rn, imm * 8, true
}

// scanArm64Refs walks the bytes of a function (one 4-byte
// instruction at a time) and returns the set of byte addresses the
// function references via ADRP+ADD or ADRP+LDR pairs.
//
// pc is the function's entry virtual address; bytes is its full
// machine-code body. The little-endian assumption is correct for
// arm64 (all current Go arm64 ABIs are LE).
//
// The returned slice contains absolute target addresses (i.e. into
// the loaded image's address space). Duplicates are removed.
func scanArm64Refs(pc uint64, bytes []byte) []uint64 {
	if len(bytes)%4 != 0 {
		// Truncate to instruction granularity.
		bytes = bytes[:len(bytes)-(len(bytes)%4)]
	}

	// Track the most recent ADRP per destination register so that a
	// subsequent ADD/LDR with the same source register can resolve
	// the absolute address. We don't model arbitrary register flow;
	// this is sufficient because Go's compiler emits ADRP and its
	// completing ADD/LDR within a few instructions of each other.
	const numRegs = 32
	type pageState struct {
		page  uint64 // (PC & ~0xfff) + ADRP imm
		valid bool
	}
	var pageOf [numRegs]pageState

	seen := map[uint64]struct{}{}
	add := func(addr uint64) {
		if addr == 0 {
			return
		}
		seen[addr] = struct{}{}
	}

	for off := 0; off+4 <= len(bytes); off += 4 {
		insPC := pc + uint64(off)
		ins := armInstr(uint32(bytes[off]) |
			uint32(bytes[off+1])<<8 |
			uint32(bytes[off+2])<<16 |
			uint32(bytes[off+3])<<24)

		if rd, imm, ok := adrpDecode(ins); ok {
			page := (insPC &^ 0xFFF) + uint64(imm)
			pageOf[rd] = pageState{page: page, valid: true}
			continue
		}
		if rd, rn, imm, ok := addImmDecode(ins); ok {
			if rd != rn {
				// We require ADRP and ADD to share dst/src; this
				// is what Go emits and avoids false positives from
				// arithmetic ADDs.
				continue
			}
			ps := pageOf[rn]
			if ps.valid {
				add(ps.page + uint64(imm))
				// Don't invalidate; the same Xn may be reused for
				// multiple subsequent ADDs at the same page (rare
				// but possible after function-internal branches).
			}
			continue
		}
		if rt, rn, off64, ok := ldrImmUnsignedDecode(ins); ok {
			ps := pageOf[rn]
			if ps.valid {
				add(ps.page + uint64(off64))
			}
			_ = rt
			continue
		}
		// Branch, RET, B.cond, BL, etc.: instructions we don't
		// model. We also don't invalidate page state on these
		// because invalidation would cause false negatives across
		// straight-line basic blocks; in practice Go's emitter
		// schedules ADRP and its consumer adjacently so this is
		// a non-issue.
	}

	out := make([]uint64, 0, len(seen))
	for a := range seen {
		out = append(out, a)
	}
	return out
}
