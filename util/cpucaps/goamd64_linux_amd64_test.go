// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux && amd64 && !android && !ts_omit_cpucaps

package cpucaps

import (
	"bytes"
	"os"
	"strings"
	"testing"
)

// TestCPUInfoMatchesXSysCPU cross-checks the x/sys/cpu CPUID
// derivation of the host GOAMD64 level against the exact
// /proc/cpuinfo flag lists. The x/sys/cpu path assumes LAHF/SAHF,
// MOVBE, LZCNT and F16C accompany the rest of their level's flags; a
// mismatch here either means we found real hardware where that
// assumption is wrong and HostGOAMD64Level would over-report, or
// that the kernel's view diverges from raw CPUID (e.g. a clearcpuid=
// boot parameter or a hypervisor filtering /proc/cpuinfo but not
// guest CPUID).
func TestCPUInfoMatchesXSysCPU(t *testing.T) {
	cpuinfo, err := os.ReadFile("/proc/cpuinfo")
	if err != nil {
		t.Skipf("skipping: %v", err)
	}
	exact := -1
	for line := range bytes.Lines(cpuinfo) {
		name, rest, ok := bytes.Cut(line, []byte(":"))
		if ok && string(bytes.TrimSpace(name)) == "flags" {
			exact = goamd64LevelFromFlags(strings.Fields(string(rest)))
			break
		}
	}
	if exact == -1 {
		t.Skip("skipping: no flags line in /proc/cpuinfo")
	}
	approx := HostGOAMD64Level()
	t.Logf("cpuinfo=%d x/sys/cpu=%d", exact, approx)
	if exact != approx {
		t.Errorf("/proc/cpuinfo level %d != x/sys/cpu level %d", exact, approx)
	}
}
