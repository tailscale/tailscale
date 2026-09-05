// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ts_omit_cpucaps

package cpucaps

import (
	"runtime"
	"runtime/debug"
	"strings"
	"sync"

	"golang.org/x/sys/cpu"
)

// Host returns the capabilities of the host CPU.
//
// The result is computed once on first call from x/sys/cpu feature
// bits that were already initialized at process start; subsequent
// calls are free.
func Host() Caps { return hostCaps() }

var hostCaps = sync.OnceValue(func() (c Caps) {
	if runtime.GOARCH == "amd64" || runtime.GOARCH == "386" {
		x := cpu.X86
		if x.HasAES {
			c |= CapAES
		}
		if x.HasPCLMULQDQ {
			c |= CapCLMUL
		}
		if x.HasADX {
			c |= CapADX
		}
		if x.HasAVX {
			c |= CapAVX
		}
		if x.HasAVX2 {
			c |= CapAVX2
		}
		if x.HasAVX512F && x.HasAVX512BW && x.HasAVX512CD && x.HasAVX512DQ && x.HasAVX512VL {
			c |= CapAVX512
		}
		// Note: x/sys/cpu detects VAES/VPCLMULQDQ/GFNI only when
		// the OS supports AVX-512 state, so hybrid parts that pair
		// these with only 256-bit vectors (e.g. Alder Lake E-core
		// configs) are not reported.
		if x.HasAVX512VAES {
			c |= CapVAES
		}
		if x.HasAVX512VPCLMULQDQ {
			c |= CapVPCLMUL
		}
		if x.HasAVX512GFNI {
			c |= CapGFNI
		}
		// x/sys/cpu does not expose x86 SHA-NI; CapSHA2 is
		// currently reported on arm64 only.
	}
	if runtime.GOARCH == "arm64" {
		a := cpu.ARM64
		if a.HasAES {
			c |= CapAES
		}
		if a.HasPMULL {
			c |= CapCLMUL
		}
		if a.HasSHA2 {
			c |= CapSHA2
		}
		if a.HasSHA512 {
			c |= CapSHA512
		}
		if a.HasCRC32 {
			c |= CapCRC32
		}
		if a.HasATOMICS {
			c |= CapLSE
		}
	}
	c |= hostCapsArch()
	return c
})

// HostGOAMD64Level returns the maximum GOAMD64 microarchitecture
// level (1-4) that the host CPU supports per its CPUID feature bits,
// regardless of what level this binary was compiled for. It returns
// 0 if the host is not x86-64.
func HostGOAMD64Level() int { return hostGOAMD64Level() }

var hostGOAMD64Level = sync.OnceValue(goamd64LevelFromXSysCPU)

// goamd64LevelFromXSysCPU returns the maximum GOAMD64 level (1-4)
// derived from x/sys/cpu feature bits, or 0 if not running on amd64.
// It mirrors the per-level feature checks in Go's runtime/asm_amd64.s,
// with one gap: x/sys/cpu does not expose LAHF/SAHF (level 2) or
// MOVBE, LZCNT and F16C (level 3), so those are assumed present when
// the remaining flags of their level are; no known x86-64 CPU has
// the checked subset without them. TestCPUInfoMatchesXSysCPU
// cross-checks this assumption against the exact /proc/cpuinfo flag
// lists on linux/amd64.
func goamd64LevelFromXSysCPU() int {
	if runtime.GOARCH != "amd64" {
		return 0
	}
	x := cpu.X86
	if !(x.HasCX16 && x.HasPOPCNT && x.HasSSE3 && x.HasSSSE3 && x.HasSSE41 && x.HasSSE42) {
		return 1
	}
	if !(x.HasAVX && x.HasAVX2 && x.HasBMI1 && x.HasBMI2 && x.HasFMA && x.HasOSXSAVE) {
		return 2
	}
	if !(x.HasAVX512F && x.HasAVX512BW && x.HasAVX512CD && x.HasAVX512DQ && x.HasAVX512VL) {
		return 3
	}
	return 4
}

// CompiledGOAMD64Level returns the GOAMD64 microarchitecture level
// (1-4) that this binary was compiled for, as recorded in its build
// info. It returns 0 if unknown or if the binary is not amd64.
func CompiledGOAMD64Level() int { return compiledGOAMD64Level() }

var compiledGOAMD64Level = sync.OnceValue(func() int {
	bi, ok := debug.ReadBuildInfo()
	if !ok {
		return 0
	}
	for _, s := range bi.Settings {
		if s.Key == "GOAMD64" {
			if v, ok := strings.CutPrefix(s.Value, "v"); ok && len(v) == 1 && v[0] >= '1' && v[0] <= '4' {
				return int(v[0] - '0')
			}
			return 0
		}
	}
	return 0
})
