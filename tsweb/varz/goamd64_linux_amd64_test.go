// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !android

package varz

import (
	"strings"
	"testing"
)

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

func TestGoAMD64Level(t *testing.T) {
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
			if got := goamd64Level(tt.flags); got != tt.want {
				t.Errorf("goamd64Level = %d; want %d", got, tt.want)
			}
		})
	}
}

func TestHostGOAMD64Level(t *testing.T) {
	got := hostGOAMD64Level()
	t.Logf("hostGOAMD64Level = %d", got)
	if got < 0 || got > 4 {
		t.Errorf("out of range [0,4]")
	}
}

func TestCompiledGOAMD64Level(t *testing.T) {
	got := compiledGOAMD64Level()
	t.Logf("compiledGOAMD64Level = %d", got)
	if got < 1 || got > 4 {
		t.Errorf("got %d; want in range [1,4] since test binaries have build info", got)
	}
}
