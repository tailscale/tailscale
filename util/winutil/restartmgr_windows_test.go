// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package winutil

import (
	"fmt"
	"os/user"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

const oldFashionedCleanupExitCode = 7778

// oldFashionedCleanup cleans up any outstanding binaries using older APIs.
// This would be necessary if the restart manager were to fail during the test.
func oldFashionedCleanup(t *testing.T, binary string) {
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		t.Logf("CreateToolhelp32Snapshot failed: %v", err)
	}
	defer windows.CloseHandle(snap)

	binary = filepath.Clean(binary)
	binbase := filepath.Base(binary)
	pe := windows.ProcessEntry32{
		Size: uint32(unsafe.Sizeof(windows.ProcessEntry32{})),
	}
	for perr := windows.Process32First(snap, &pe); perr == nil; perr = windows.Process32Next(snap, &pe) {
		curBin := windows.UTF16ToString(pe.ExeFile[:])
		// Coarse check against the leaf name of the binary
		if !strings.EqualFold(binbase, curBin) {
			continue
		}

		proc, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION|windows.PROCESS_TERMINATE, false, pe.ProcessID)
		if err != nil {
			t.Logf("OpenProcess failed: %v", err)
			continue
		}
		defer windows.CloseHandle(proc)

		img, err := ProcessImageName(proc)
		if err != nil {
			t.Logf("ProcessImageName failed: %v", err)
			continue
		}

		// Now check that their fully-qualified paths match.
		if !strings.EqualFold(binary, filepath.Clean(img)) {
			continue
		}

		t.Logf("Found leftover pid %d, terminating...", pe.ProcessID)
		if err := windows.TerminateProcess(proc, oldFashionedCleanupExitCode); err != nil && err != windows.ERROR_ACCESS_DENIED {
			t.Logf("TerminateProcess failed: %v", err)
		}
	}
}

func testRestartableProcessesImpl(N int, t *testing.T) {
	const binary = "testrestartableprocesses"
	fq := pathToTestProg(t, binary)

	for range N {
		startTestProg(t, binary, "RestartableProcess")
	}
	t.Cleanup(func() {
		oldFashionedCleanup(t, fq)
	})

	logf := func(format string, args ...any) {
		t.Logf(format, args...)
	}
	rms, err := NewRestartManagerSession(logf)
	if err != nil {
		t.Fatalf("NewRestartManagerSession: %v", err)
	}
	defer rms.Close()

	if err := rms.AddPaths([]string{fq}); err != nil {
		t.Fatalf("AddPaths: %v", err)
	}

	ups, err := rms.AffectedProcesses()
	if err != nil {
		t.Fatalf("AffectedProcesses: %v", err)
	}

	rps := NewRestartableProcesses()
	defer rps.Close()

	for _, up := range ups {
		rp, err := up.AsRestartableProcess()
		if err != nil {
			t.Errorf("AsRestartableProcess: %v", err)
			continue
		}
		rps.Add(rp)
	}

	const terminateWithExitCode = 7777
	if err := rps.Terminate(logf, terminateWithExitCode, time.Duration(15)*time.Second); err != nil {
		t.Errorf("Terminate: %v", err)
	}

	for k, v := range rps {
		if v.hasExitCode {
			if v.exitCode != terminateWithExitCode {
				// Not strictly an error, but worth noting.
				logf("Subprocess %d terminated with unexpected exit code %d", k, v.exitCode)
			}
		} else {
			t.Errorf("Subprocess %d did not produce an exit code", k)
		}
		if v.handle != 0 {
			t.Errorf("Subprocess %d is unexpectedly still open", k)
		}
	}
}

func TestRestartableProcesses(t *testing.T) {
	u, err := user.Current()
	if err != nil {
		t.Fatalf("Could not obtain current user")
	}
	if u.Uid != localSystemSID {
		t.Skipf("This test must be run as SYSTEM")
	}

	forN := func(fn func(int, *testing.T)) func([]int) {
		return func(ns []int) {
			for _, n := range ns {
				t.Run(fmt.Sprintf("N=%d", n), func(tt *testing.T) { fn(n, tt) })
			}
		}
	}(testRestartableProcessesImpl)

	// Testing indicates that the restart manager cannot handle more than 127 processes (on Windows 10, at least), so we use that as our highest value.
	ns := []int{0, 1, _MAXIMUM_WAIT_OBJECTS - 1, _MAXIMUM_WAIT_OBJECTS, _MAXIMUM_WAIT_OBJECTS + 1, _MAXIMUM_WAIT_OBJECTS*2 - 1}
	forN(ns)
}
