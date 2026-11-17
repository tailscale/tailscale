// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !android

package varz

import (
	"bytes"
	"expvar"
	"os"
	"runtime/debug"
	"strings"
)

func init() {
	var capable any = hostGOAMD64Level()
	expvar.Publish("gauge_goamd64_capable", expvar.Func(func() any { return capable }))
	var compiled any = compiledGOAMD64Level()
	expvar.Publish("gauge_goamd64_compiled", expvar.Func(func() any { return compiled }))
}

// goamd64LevelFlags maps each x86-64 microarchitecture level to the
// /proc/cpuinfo flag names it requires beyond the previous level.
// It matches the per-level feature checks in Go's runtime/asm_amd64.s.
// Note that /proc/cpuinfo spells SSE3 as "pni" and LZCNT as "abm",
// and the kernel clears the AVX and AVX-512 flags when the OS lacks
// XSAVE support, so OSXSAVE needs no separate check.
var goamd64LevelFlags = [...][]string{
	2: {"cx16", "lahf_lm", "popcnt", "pni", "sse4_1", "sse4_2", "ssse3"},
	3: {"abm", "avx", "avx2", "bmi1", "bmi2", "f16c", "fma", "movbe"},
	4: {"avx512f", "avx512bw", "avx512cd", "avx512dq", "avx512vl"},
}

// hostGOAMD64Level returns the maximum GOAMD64 microarchitecture
// level (1-4) that the host CPU supports, regardless of what level
// this binary was compiled for. It returns 0 on error.
func hostGOAMD64Level() int {
	cpuinfo, err := os.ReadFile("/proc/cpuinfo")
	if err != nil {
		return 0
	}
	for line := range bytes.Lines(cpuinfo) {
		name, rest, ok := bytes.Cut(line, []byte(":"))
		if ok && string(bytes.TrimSpace(name)) == "flags" {
			return goamd64Level(strings.Fields(string(rest)))
		}
	}
	return 0
}

// goamd64Level returns the maximum GOAMD64 level (1-4) supported by
// a CPU with the given /proc/cpuinfo flags.
func goamd64Level(flags []string) int {
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

// compiledGOAMD64Level returns the GOAMD64 microarchitecture level
// (1-4) that this binary was compiled for, as recorded in its build
// info. It returns 0 if unknown.
func compiledGOAMD64Level() int {
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
}
