// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// Package cpucaps reports capabilities of the host CPU that Go
// generated code and assembly can make use of, along with the
// x86-64 microarchitecture level the running binary was compiled
// for.
//
// Detection is lazy (no init-time work) and sources its data from
// golang.org/x/sys/cpu, which uses raw CPUID on x86 and in-process
// auxv/HWCAP (with trapped MRS register reads as fallback) on
// linux/arm64, so normally no files are read or parsed (x/sys/cpu
// retains /proc fallbacks on linux/arm64 that are unreachable when
// built with Go 1.21+). The host GOAMD64 level is derived from CPUID
// feature bits, mirroring the per-level checks in Go's
// runtime/asm_amd64.s: raw CPUID is what the Go runtime itself
// dispatches on, so it is the ground truth for what level a binary
// could run at on this machine. A linux/amd64 test cross-checks the
// derivation against the exact /proc/cpuinfo flag lists.
//
// All key target platforms are supported without external OS
// dependencies (no files parsed, no processes executed):
//
//   - amd64 (linux, windows, darwin, freebsd, android): raw CPUID
//   - linux+android/arm64: in-process auxv HWCAP, falling back to
//     kernel-emulated MRS reads of the ID_AA64* registers
//   - darwin+ios/arm64: sysctl syscalls (the ios GOOS satisfies the
//     darwin build constraint in x/sys/cpu)
//   - windows/arm64: IsProcessorFeaturePresent
//   - freebsd/arm64: kernel-emulated MRS read of ID_AA64ISAR0_EL1,
//     as Go's runtime/internal/cpu does on this platform (x/sys/cpu
//     does not yet support it)
//
// Building with the ts_omit_cpucaps tag removes all detection code:
// the detection functions then return zero values. The Caps type and
// its names remain available for decoding recorded values.
package cpucaps

import (
	"strconv"
	"strings"
)

// Caps is a bitmask of host CPU capabilities that Go's runtime and
// standard library dispatch on, normalized across architectures
// (e.g. CapAES means x86 AES-NI or arm64 FEAT_AES).
//
// Bits are append-only: never reuse or renumber a bit, even for
// features that become obsolete, so recorded values keep their
// meaning. Keep bit positions below 53 so values survive JSON
// round-trips through IEEE-754 consumers.
type Caps uint64

const (
	CapAES     Caps = 1 << iota // x86 AES-NI / arm64 FEAT_AES
	CapCLMUL                    // carry-less multiply for GHASH/GCM: x86 PCLMULQDQ / arm64 FEAT_PMULL
	CapSHA2                     // SHA-256 instructions: arm64 FEAT_SHA256 (x86 SHA-NI not yet exposed by x/sys/cpu)
	CapSHA512                   // SHA-512 instructions: arm64 FEAT_SHA512
	CapCRC32                    // arm64 FEAT_CRC32 (on x86, CRC32 is implied by GOAMD64 level >= 2 via SSE4.2)
	CapADX                      // x86 multi-precision add-carry (math/big)
	CapLSE                      // arm64 FEAT_LSE atomics
	CapAVX                      // x86 AVX, incl. OS XSAVE support
	CapAVX2                     // x86 AVX2, incl. OS XSAVE support (GOAMD64 v3 vector baseline)
	CapAVX512                   // x86 AVX-512 F+BW+CD+DQ+VL, the GOAMD64 v4 usable subset, incl. OS ZMM state support
	CapVAES                     // x86 VAES: vectorized AES over 256/512-bit lanes
	CapVPCLMUL                  // x86 VPCLMULQDQ: vectorized carry-less multiply
	CapGFNI                     // x86 Galois field new instructions

	capMax
)

var capNames = [...]string{
	"aes", "clmul", "sha2", "sha512", "crc32", "adx", "lse",
	"avx", "avx2", "avx512", "vaes", "vpclmul", "gfni",
}

// String returns a pipe-separated lower-case list of the set
// capability names, e.g. "aes|clmul|lse", or "" if none are set.
// Set bits without a known name (e.g. in a value recorded by a
// newer binary) are reported as a single hex remainder, e.g.
// "aes|unknown(0x4000)".
func (c Caps) String() string {
	var sb strings.Builder
	for i, name := range capNames {
		if c&(1<<i) != 0 {
			if sb.Len() > 0 {
				sb.WriteByte('|')
			}
			sb.WriteString(name)
		}
	}
	if unknown := c &^ (capMax - 1); unknown != 0 {
		if sb.Len() > 0 {
			sb.WriteByte('|')
		}
		sb.WriteString("unknown(0x")
		sb.WriteString(strconv.FormatUint(uint64(unknown), 16))
		sb.WriteString(")")
	}
	return sb.String()
}

// capsFromISAR0 returns the capabilities encoded in the arm64
// ID_AA64ISAR0_EL1 instruction set attribute register. Field values
// follow the ARM Architecture Reference Manual and match the
// decoding in x/sys/cpu's parseARM64SystemRegisters and Go's
// runtime/internal/cpu. It is used on platforms where x/sys/cpu
// lacks arm64 feature detection (currently FreeBSD).
func capsFromISAR0(isar0 uint64) (c Caps) {
	extract := func(lo uint) uint64 { return (isar0 >> lo) & 0xf }

	switch extract(4) { // AES field
	case 2:
		c |= CapCLMUL
		fallthrough
	case 1:
		c |= CapAES
	}
	switch extract(12) { // SHA2 field
	case 2:
		c |= CapSHA512
		fallthrough
	case 1:
		c |= CapSHA2
	}
	if extract(16) >= 1 { // CRC32 field
		c |= CapCRC32
	}
	if extract(20) >= 2 { // Atomic field
		c |= CapLSE
	}
	return c
}
