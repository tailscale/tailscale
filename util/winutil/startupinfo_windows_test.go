// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package winutil

import (
	"runtime"
	"runtime/debug"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

var procGetProcessMemoryInfo = windows.NewLazySystemDLL("psapi.dll").NewProc("GetProcessMemoryInfo")

type processMemoryCountersEx struct {
	cb                         uint32
	pageFaultCount             uint32
	peakWorkingSetSize         uintptr
	workingSetSize             uintptr
	quotaPeakPagedPoolUsage    uintptr
	quotaPagedPoolUsage        uintptr
	quotaPeakNonPagedPoolUsage uintptr
	quotaNonPagedPoolUsage     uintptr
	pagefileUsage              uintptr
	peakPagefileUsage          uintptr
	privateUsage               uintptr
}

func privateBytes(t *testing.T) uintptr {
	t.Helper()
	runtime.GC()
	debug.FreeOSMemory()
	var pmc processMemoryCountersEx
	pmc.cb = uint32(unsafe.Sizeof(pmc))
	r, _, err := procGetProcessMemoryInfo.Call(uintptr(windows.CurrentProcess()), uintptr(unsafe.Pointer(&pmc)), uintptr(pmc.cb))
	if r == 0 {
		t.Fatalf("GetProcessMemoryInfo: %v", err)
	}
	return pmc.privateUsage
}

// TestResolveFreesAttributeListOnError checks that Resolve releases its
// ProcThreadAttributeList when UpdateProcThreadAttribute fails.
func TestResolveFreesAttributeListOnError(t *testing.T) {
	resolveBad := func() {
		var sib StartupInfoBuilder
		sib.makeAttrs()
		// Attribute IDs unknown to Windows make UpdateProcThreadAttribute fail.
		for i := range uintptr(4) {
			sib.attrs[0x7FF0+i] = windows.Handle(0)
		}
		if _, _, _, err := sib.Resolve(); err == nil {
			t.Fatal("Resolve succeeded with an invalid attribute")
		}
		sib.Close()
	}

	// Warm up so that one-time allocations are not counted.
	for range 1000 {
		resolveBad()
	}

	const n = 100000
	before := privateBytes(t)
	for range n {
		resolveBad()
	}
	after := privateBytes(t)

	// Each leaked list is roughly 100 bytes, so a leak grows private
	// memory by several megabytes; allow some slack for other noise.
	const limit = 2 << 20
	if after > before && after-before > limit {
		t.Errorf("private bytes grew by %d over %d failed Resolve calls; attribute list leaked", after-before, n)
	}
}
