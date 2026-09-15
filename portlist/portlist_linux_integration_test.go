// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux && !android

package portlist

import (
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"golang.org/x/sys/unix"
)

// requireDiag verifies the complete diagnostic path before a test relies on
// it. Constructor state alone cannot detect a kernel that lacks one of the
// requested protocol handlers (notably UDP).
func requireDiag(tb testing.TB, li *linuxImpl) {
	tb.Helper()
	if li.diagPermanent {
		tb.Skip("inet_diag unavailable in this environment")
	}
	if err := li.appendDiagPorts(); err != nil {
		if isDiagCapabilityError(err) {
			tb.Skipf("inet_diag unavailable in this environment: %v", err)
		}
		tb.Fatalf("inet_diag capability probe failed: %v", err)
	}
	if li.diagFD < 0 || li.diagPermanent {
		tb.Fatalf("inet_diag capability probe returned without a usable socket: fd=%d permanent=%v", li.diagFD, li.diagPermanent)
	}
}

func TestProcConstructionDoesNotOpenDiagSocket(t *testing.T) {
	li := newLinuxImplWithDiag(true, false)
	defer li.Close()
	if li.diagFD != -1 {
		t.Fatalf("proc-only construction opened diagnostic fd %d", li.diagFD)
	}
}

func TestDiagControlledListenerParity(t *testing.T) {
	maybeSkip(t)
	ln, err := net.Listen("tcp4", "0.0.0.0:0")
	if err != nil {
		t.Skipf("IPv4 listener unavailable: %v", err)
	}
	defer ln.Close()
	port := uint16(ln.Addr().(*net.TCPAddr).Port)

	proc := newLinuxImplWithDiag(true, false)
	defer proc.Close()
	diag := newLinuxImplWithDiag(true, true)
	defer diag.Close()
	requireDiag(t, diag)

	pick := func(li *linuxImpl) Port {
		ports, err := li.AppendListeningPorts(nil)
		if err != nil {
			t.Fatalf("listing ports: %v", err)
		}
		for _, p := range ports {
			if p.Proto == "tcp" && p.Port == port {
				return p
			}
		}
		t.Fatalf("controlled TCP listener port %d absent from %+v", port, ports)
		return Port{}
	}

	gotProc := pick(proc)
	gotDiag := pick(diag)
	if diff := cmp.Diff(gotDiag, gotProc); diff != "" {
		t.Fatalf("diag/proc controlled listener mismatch (-diag +proc):\n%s", diff)
	}
}

func TestDiagLoopbackFalseParity(t *testing.T) {
	maybeSkip(t)
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Skipf("IPv4 loopback listener unavailable: %v", err)
	}
	defer ln.Close()
	port := uint16(ln.Addr().(*net.TCPAddr).Port)

	proc := newLinuxImplWithDiag(false, false)
	defer proc.Close()
	diag := newLinuxImplWithDiag(false, true)
	defer diag.Close()
	requireDiag(t, diag)
	ports := func(li *linuxImpl) []Port {
		got, err := li.AppendListeningPorts(nil)
		if err != nil {
			t.Fatalf("listing ports: %v", err)
		}
		return got
	}
	for _, p := range ports(proc) {
		if p.Port == port {
			t.Fatalf("proc path included localhost port %d with IncludeLocalhost=false", port)
		}
	}
	for _, p := range ports(diag) {
		if p.Port == port {
			t.Fatalf("diag path included localhost port %d with IncludeLocalhost=false", port)
		}
	}
}

func TestDiagFallbackRecovery(t *testing.T) {
	maybeSkip(t)
	ln, err := net.Listen("tcp4", "0.0.0.0:0")
	if err != nil {
		t.Fatalf("fixture listener: %v", err)
	}
	defer ln.Close()
	port := uint16(ln.Addr().(*net.TCPAddr).Port)

	li := newLinuxImplWithDiag(true, true)
	defer li.Close()
	requireDiag(t, li)
	if _, err := li.AppendListeningPorts(nil); err != nil {
		t.Fatalf("initial diag poll: %v", err)
	}
	var want Port
	for _, p := range li.known {
		if p.port.Proto == "tcp" && p.port.Port == port {
			want = p.port
		}
	}
	if want.Port == 0 {
		t.Fatalf("fixture listener absent from initial diag result")
	}

	// Replace the socket atomically with a non-socket while preserving its fd
	// number. This makes the transient failure deterministic without leaving a
	// close/reopen window in which another descriptor could reuse the number.
	badFD, err := unix.Open("/dev/null", unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatalf("open fallback fixture: %v", err)
	}
	if err := unix.Dup3(badFD, li.diagFD, 0); err != nil {
		unix.Close(badFD)
		t.Fatalf("replace diag fixture fd: %v", err)
	}
	if err := unix.Close(badFD); err != nil {
		t.Fatalf("close fallback fixture: %v", err)
	}
	got, err := li.AppendListeningPorts(nil)
	if err != nil {
		t.Fatalf("proc fallback poll: %v", err)
	}
	if li.diagFD != -1 {
		t.Fatalf("failed diagnostic socket was not closed after fallback: fd=%d", li.diagFD)
	}
	var fallback Port
	for _, p := range got {
		if p.Proto == "tcp" && p.Port == port {
			fallback = p
		}
	}
	if diff := cmp.Diff(fallback, want); diff != "" {
		t.Fatalf("fallback record mismatch (-fallback +initial):\n%s", diff)
	}

	// A transient transport failure must recover on the next poll in the same
	// namespace; remaining on proc fallback forever defeats the replacement.
	got, err = li.AppendListeningPorts(nil)
	if err != nil {
		t.Fatalf("recovery poll: %v", err)
	}
	if li.diagFD < 0 || li.diagPermanent {
		t.Fatalf("diag did not recover after fallback: fd=%d permanent=%v", li.diagFD, li.diagPermanent)
	}
	_ = got
}

func TestDiagNamespaceMismatchFallback(t *testing.T) {
	maybeSkip(t)
	const childEnv = "PORTLIST_NAMESPACE_MISMATCH_CHILD=1"
	if os.Getenv("PORTLIST_NAMESPACE_MISMATCH_CHILD") != "1" {
		cmd := exec.Command(os.Args[0], "-test.run=^TestDiagNamespaceMismatchFallback$", "-test.v")
		cmd.Env = append(os.Environ(), childEnv)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("namespace child failed: %v\n%s", err, out)
		}
		if strings.Contains(string(out), "--- SKIP:") {
			t.Skipf("namespace child skipped: %s", out)
		}
		t.Logf("namespace child: %s", out)
		return
	}

	ln, err := net.Listen("tcp4", "0.0.0.0:0")
	if err != nil {
		t.Skipf("IPv4 listener unavailable: %v", err)
	}
	defer ln.Close()
	port := uint16(ln.Addr().(*net.TCPAddr).Port)
	orig, err := unix.Open("/proc/self/ns/net", unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Skipf("cannot open original network namespace: %v", err)
	}
	defer unix.Close(orig)
	type result struct {
		err          error
		skip         bool
		contaminated bool
	}
	check := func() result {
		pinned := newLinuxImplWithDiag(true, true)
		defer pinned.Close()
		if pinned.diagPermanent {
			return result{err: errors.New("inet_diag unavailable in constructor"), skip: true}
		}
		if err := pinned.appendDiagPorts(); err != nil {
			return result{err: err, skip: isDiagCapabilityError(err)}
		}
		if err := unix.Unshare(unix.CLONE_NEWNET); err != nil {
			return result{err: err, skip: errors.Is(err, unix.EPERM) || errors.Is(err, unix.EINVAL) || errors.Is(err, unix.ENOSYS)}
		}
		var testErr error
		// A healthy socket keeps its original namespace even when its caller
		// moves. After closing it, reopening in the foreign namespace must be
		// refused, leaving the pinned proc files as the complete fallback.
		if err := pinned.appendDiagPorts(); err != nil {
			testErr = fmt.Errorf("poll pinned socket after namespace switch: %w", err)
		}
		pinned.closeDiag()
		if _, err := pinned.AppendListeningPorts(nil); err != nil {
			testErr = fmt.Errorf("fallback after namespace switch: %w", err)
		} else if pinned.diagFD != -1 {
			testErr = errors.New("reopened diagnostic socket in foreign namespace")
		}
		li := newLinuxImplWithDiag(true, true)
		if !li.diagPermanent {
			testErr = errors.New("constructor did not disable inet_diag for differing proc/thread namespaces")
		} else {
			ports, err := li.AppendListeningPorts(nil)
			if err != nil {
				testErr = fmt.Errorf("proc fallback after namespace mismatch: %w", err)
			} else {
				found := false
				for _, p := range ports {
					if p.Proto == "tcp" && p.Port == port {
						found = true
						break
					}
				}
				if !found {
					testErr = fmt.Errorf("proc fallback lost listener from process-leader namespace: port %d, got %v", port, ports)
				}
			}
		}
		li.Close()
		// A setns on a locked worker must be undone before the thread is
		// returned to the runtime, otherwise a later test can inherit it.
		if err := unix.Setns(orig, unix.CLONE_NEWNET); err != nil {
			return result{err: fmt.Errorf("restore original network namespace: %w", err), contaminated: true}
		}
		if err := pinned.appendDiagPorts(); err != nil && testErr == nil {
			testErr = fmt.Errorf("reopen in original namespace: %w", err)
		}
		return result{err: testErr}
	}

	// If this test goroutine is already on a non-leader thread, it can switch
	// directly. Otherwise hold the leader thread while a locked worker runs the
	// check; this makes the two proc namespace views differ deterministically.
	runtime.LockOSThread()
	if unix.Gettid() != os.Getpid() {
		res := check()
		if !res.contaminated {
			runtime.UnlockOSThread()
		}
		if res.skip {
			t.Skipf("network namespace switching unavailable: %v", res.err)
		}
		if res.err != nil {
			t.Fatal(res.err)
		}
		return
	}
	done := make(chan result, 1)
	go func() {
		runtime.LockOSThread()
		res := check()
		done <- res
		// check restores the worker's namespace before returning. Keep this
		// lock until after the result is published so the thread cannot be
		// reused in the transient namespace.
		if !res.contaminated {
			runtime.UnlockOSThread()
		}
	}()
	res := <-done
	runtime.UnlockOSThread()
	if res.skip {
		t.Skipf("network namespace switching unavailable: %v", res.err)
	}
	if res.err != nil {
		t.Fatal(res.err)
	}
}
