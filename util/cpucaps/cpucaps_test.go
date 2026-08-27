// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package cpucaps

import (
	"strings"
	"testing"
)

// goamd64LevelFlags maps each x86-64 microarchitecture level to the
// /proc/cpuinfo flag names it requires beyond the previous level.
// It matches the per-level feature checks in Go's runtime/asm_amd64.s
// and serves as the exact reference that the x/sys/cpu-derived
// implementation is checked against. Note that /proc/cpuinfo spells
// SSE3 as "pni" and LZCNT as "abm", and the kernel clears the AVX
// and AVX-512 flags when the OS lacks XSAVE support, so OSXSAVE
// needs no separate check.
var goamd64LevelFlags = [...][]string{
	2: {"cx16", "lahf_lm", "popcnt", "pni", "sse4_1", "sse4_2", "ssse3"},
	3: {"abm", "avx", "avx2", "bmi1", "bmi2", "f16c", "fma", "movbe"},
	4: {"avx512f", "avx512bw", "avx512cd", "avx512dq", "avx512vl"},
}

// goamd64LevelFromFlags returns the maximum GOAMD64 level (1-4)
// supported by a CPU with the given /proc/cpuinfo flags.
func goamd64LevelFromFlags(flags []string) int {
	has := make(map[string]bool, len(flags))
	for _, f := range flags {
		has[f] = true
	}
	level := 1
	for next := 2; next < len(goamd64LevelFlags); next++ {
		for _, f := range goamd64LevelFlags[next] {
			if !has[f] {
				return level
			}
		}
		level = next
	}
	return level
}

const v4Flags = "fpu vme de pse tsc msr pae mce cx8 apic sep mtrr pge mca cmov " +
	"pat pse36 clflush mmx fxsr sse sse2 ss ht syscall nx pdpe1gb rdtscp lm " +
	"constant_tsc rep_good nopl xtopology nonstop_tsc cpuid aperfmperf " +
	"tsc_known_freq pni pclmulqdq ssse3 fma cx16 pcid sse4_1 sse4_2 x2apic " +
	"movbe popcnt tsc_deadline_timer aes xsave avx f16c rdrand hypervisor " +
	"lahf_lm abm 3dnowprefetch invpcid_single pti fsgsbase tsc_adjust bmi1 " +
	"avx2 smep bmi2 erms invpcid avx512f avx512dq rdseed adx smap clflushopt " +
	"clwb avx512cd avx512bw avx512vl xsaveopt xsavec xgetbv1 xsaves"

func withoutFlags(flags string, remove ...string) []string {
	var out []string
	fs := strings.Fields(flags)
Outer:
	for _, f := range fs {
		for _, r := range remove {
			if f == r {
				continue Outer
			}
		}
		out = append(out, f)
	}
	return out
}

func TestGoAMD64LevelFromFlags(t *testing.T) {
	tests := []struct {
		name  string
		flags []string
		want  int
	}{
		{"v4", withoutFlags(v4Flags), 4},
		{"v3_no_avx512vl", withoutFlags(v4Flags, "avx512vl"), 3},
		{"v3_no_avx512", withoutFlags(v4Flags, "avx512f", "avx512dq", "avx512cd", "avx512bw", "avx512vl"), 3},
		{"v2_no_avx2", withoutFlags(v4Flags, "avx512f", "avx2"), 2},
		{"v2_no_abm", withoutFlags(v4Flags, "avx512bw", "abm"), 2},
		{"v1_no_popcnt", withoutFlags(v4Flags, "avx2", "popcnt"), 1},
		{"v1_no_sse42", withoutFlags(v4Flags, "sse4_2"), 1},
		{"empty", nil, 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := goamd64LevelFromFlags(tt.flags); got != tt.want {
				t.Errorf("goamd64LevelFromFlags = %d; want %d", got, tt.want)
			}
		})
	}
}

func TestCapNamesInSync(t *testing.T) {
	if want := Caps(1) << len(capNames); capMax != want {
		t.Errorf("capMax = %#x, want %#x; capNames and the Cap constants are out of sync", uint64(capMax), uint64(want))
	}
}

func TestCapsFromISAR0(t *testing.T) {
	// Field values per the ARM ARM for ID_AA64ISAR0_EL1:
	// AES [7:4], SHA2 [15:12], CRC32 [19:16], Atomic [23:20].
	mk := func(aes, sha2, crc32, atomic uint64) uint64 {
		return aes<<4 | sha2<<12 | crc32<<16 | atomic<<20
	}
	tests := []struct {
		name  string
		isar0 uint64
		want  Caps
	}{
		{"none", 0, 0},
		{"aes_only", mk(1, 0, 0, 0), CapAES},
		{"aes_pmull", mk(2, 0, 0, 0), CapAES | CapCLMUL},
		{"sha256", mk(0, 1, 0, 0), CapSHA2},
		{"sha512", mk(0, 2, 0, 0), CapSHA2 | CapSHA512},
		{"crc32", mk(0, 0, 1, 0), CapCRC32},
		{"atomic_v81", mk(0, 0, 0, 2), CapLSE},
		{"atomic_lse128", mk(0, 0, 0, 3), CapLSE},
		{"atomic_reserved1", mk(0, 0, 0, 1), 0},
		{"neoverse_n1", mk(2, 2, 1, 2), CapAES | CapCLMUL | CapSHA2 | CapSHA512 | CapCRC32 | CapLSE},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := capsFromISAR0(tt.isar0); got != tt.want {
				t.Errorf("capsFromISAR0(%#x) = %v; want %v", tt.isar0, got, tt.want)
			}
		})
	}
}

func TestCapsString(t *testing.T) {
	tests := []struct {
		c    Caps
		want string
	}{
		{0, ""},
		{CapAES, "aes"},
		{CapAES | CapCLMUL | CapLSE, "aes|clmul|lse"},
		{CapSHA512 | CapADX, "sha512|adx"},
		{CapAVX | CapAVX2 | CapAVX512, "avx|avx2|avx512"},
		{CapVAES | CapVPCLMUL | CapGFNI, "vaes|vpclmul|gfni"},
		{capMax, "unknown(0x2000)"},
		{CapAES | capMax | capMax<<1, "aes|unknown(0x6000)"},
	}
	for _, tt := range tests {
		if got := tt.c.String(); got != tt.want {
			t.Errorf("Caps(%#x).String() = %q; want %q", uint64(tt.c), got, tt.want)
		}
	}
}
