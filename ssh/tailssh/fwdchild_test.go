// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build (linux && !android) || (darwin && !ios) || freebsd || openbsd

// Tests for the one-shot user-credential forwarding children and the
// monitor's dial/listen ops. They drive a real monitor and real one-shot
// fwd children through the self-exec seams: monitorSpawnPrefix in
// monitor_test.go for the monitor, fwdChildSpawnPrefix for the fwd
// children. Root runs use sudo and bind monitors to the non-root test
// user created by ensureFwdTestUser; those tests skip without root.
// The same-uid variants run everywhere.

package tailssh

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// fwdTestUser is the non-root user root runs bind test monitors to. It is
// created once via useradd if absent.
const fwdTestUser = "sshfwda"

var testFwdPrefix = []string{"-test.run=^TestSSHFwdHelperProcess$", "-test.timeout=0", "--", "ssh-fwd"}

// TestSSHFwdHelperProcess is not a test. It is the entry point of the
// re-exec'd ssh-fwd child: the monitor's fwdChildSpawnPrefix seam routes
// here in tests, and beFwdChild runs the op. In a normal test run there
// is no "--" in os.Args and it returns immediately.
func TestSSHFwdHelperProcess(t *testing.T) {
	for i, a := range os.Args {
		if a == "--" && i+1 < len(os.Args) && os.Args[i+1] == "ssh-fwd" {
			// Declared-fds pin for the fwd child. When the test asks
			// for it, the child dumps its exec-inherited fd table
			// before performing the op. The dump path arrives by
			// argv, from the monitor's spawn of this child: the child
			// itself runs with no environment. The test-only flag is
			// stripped before the op parser sees it.
			var childArgs []string
			for _, a := range os.Args[i+2:] {
				if p, ok := strings.CutPrefix(a, "--test-fdinfo="); ok {
					dumpChildFdsTo(p, "ssh-fwd")
					continue
				}
				childArgs = append(childArgs, a)
			}
			if err := beFwdChild(childArgs); err != nil {
				// The op's outcome was already reported on the result
				// channel; the exit code mirrors it.
				fmt.Fprintln(os.Stderr, "ssh-fwd child:", err)
				os.Exit(1)
			}
			os.Exit(0)
		}
	}
}

// startFwdTestMonitor spawns a real monitor whose fwd-child spawns are
// routed to the helper test above, bound to the given identity.
func startFwdTestMonitor(t *testing.T, uid, gid int, groups []int) *monitorClient {
	t.Helper()
	exe := makeExecutableReachable(t)
	// The override must reach the monitor process, which spawns the fwd
	// children, so it travels through the environment.
	t.Setenv("TS_TEST_SSH_FWD_PREFIX", strings.Join(testFwdPrefix, " "))
	old := monitorSpawnPrefix
	monitorSpawnPrefix = testMonitorPrefix
	t.Cleanup(func() { monitorSpawnPrefix = old })
	mc, err := spawnMonitor(exe, uint32(uid), uint32(gid), intToU32s(groups), fwdTestUser)
	if err != nil {
		t.Fatalf("spawnMonitor: %v", err)
	}
	t.Cleanup(func() {
		if err := mc.Close(); err != nil {
			t.Errorf("close monitor: %v", err)
		}
	})
	return mc
}

// makeExecutableReachable returns a path to the test binary that the
// bound user can exec. Under a root run the binary may live in a 0700
// directory, root's home under sudo. Rather than chmodding it and every
// ancestor up to /, which would leave them world-readable after the
// run, it is copied into a fresh world-traversable temp dir and the
// copy's path is returned. The copy dies with the test.
func makeExecutableReachable(t *testing.T) string {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	if os.Getuid() != 0 {
		// Same-user runs: the invoking user could already exec it.
		return exe
	}
	dir, err := os.MkdirTemp("", "tailssh-test-exe")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	// Traversable by the bound user regardless of umask.
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	dst := filepath.Join(dir, filepath.Base(exe))
	data, err := os.ReadFile(exe)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dst, data, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dst, 0o755); err != nil {
		t.Fatal(err)
	}
	return dst
}

// ensureFwdTestUser returns the uid/gid of the non-root test user,
// creating it once via useradd if absent. Root runs only. Non-root runs
// skip. The same-uid variants still pin the monitor-side mechanics.
func ensureFwdTestUser(t *testing.T) (int, int) {
	t.Helper()
	if os.Getuid() != 0 {
		t.Skip("root-only test: binds the monitor to a non-root test user (run under sudo; the user is created once via useradd)")
	}
	u, err := user.Lookup(fwdTestUser)
	if err != nil {
		useradd, lerr := exec.LookPath("useradd")
		if lerr != nil {
			t.Skipf("useradd unavailable (%v); cannot create test user %s", lerr, fwdTestUser)
		}
		out, xerr := exec.Command(useradd, "-M", fwdTestUser).CombinedOutput()
		if xerr != nil {
			t.Fatalf("useradd -M %s: %v: %s", fwdTestUser, xerr, out)
		}
		u, err = user.Lookup(fwdTestUser)
		if err != nil {
			t.Fatalf("lookup %s after creation: %v", fwdTestUser, err)
		}
	}
	uid, err := strconv.Atoi(u.Uid)
	if err != nil {
		t.Fatalf("parse uid %q: %v", u.Uid, err)
	}
	gid, err := strconv.Atoi(u.Gid)
	if err != nil {
		t.Fatalf("parse gid %q: %v", u.Gid, err)
	}
	return uid, gid
}

// fwdBoundIdentity returns the identity test monitors bind to. Under
// root runs it is the dedicated non-root test user, which pins the
// cross-uid behavior. Otherwise it is the current user.
func fwdBoundIdentity(t *testing.T) (int, int, []int) {
	t.Helper()
	if os.Getuid() == 0 {
		uid, gid := ensureFwdTestUser(t)
		return uid, gid, []int{gid}
	}
	return os.Getuid(), os.Getgid(), testGroups(t)
}

// fwdWritableDir returns a dir the bound identity can create sockets
// in: under a root run the temp dir is chowned to the bound user, or
// the child's bind fails EACCES.
func fwdWritableDir(t *testing.T, uid, gid int) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "fwdtest")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	if os.Getuid() == 0 && uid != os.Getuid() {
		if err := os.Chown(dir, uid, gid); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// connRoundTrip writes data on c and returns the echo, under deadlines.
func connRoundTrip(t *testing.T, c net.Conn, data string) string {
	t.Helper()
	if err := c.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Write([]byte(data)); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, len(data))
	if _, err := io.ReadFull(c, buf); err != nil {
		t.Fatalf("read: %v", err)
	}
	return string(buf)
}

// TestFwdDialRoundTrip dials a unix socket through the monitor's
// one-shot child, bound to the current uid, and verifies data flows
// through the returned descriptor and that the listener observes the
// dialer child's credentials via SO_PEERCRED as the bound uid. The
// assertion is Linux-only; elsewhere the helper is a no-op and the
// check degrades to a log line.
func TestFwdDialRoundTrip(t *testing.T) {
	mc := startFwdTestMonitor(t, os.Getuid(), os.Getgid(), testGroups(t))

	dir := fwdWritableDir(t, os.Getuid(), os.Getgid())
	path := filepath.Join(dir, "echo.sock")
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	type peerNote struct {
		uid int
		err error
	}
	peers := make(chan peerNote, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			peers <- peerNote{0, err}
			return
		}
		defer c.Close()
		uid, perr := peerCredUID(c)
		peers <- peerNote{uid, perr}
		c.SetDeadline(time.Now().Add(5 * time.Second))
		b := make([]byte, 64)
		n, _ := c.Read(b)
		c.Write(b[:n])
	}()

	ctx, cancel := testCtx()
	defer cancel()
	c, err := mc.Dial(ctx, path)
	if err != nil {
		t.Fatalf("monitor dial: %v", err)
	}
	defer c.Close()
	if got := connRoundTrip(t, c, "ping"); got != "ping" {
		t.Fatalf("echo through monitor-dialed socket = %q, want %q", got, "ping")
	}
	if p := <-peers; p.err == nil {
		if p.uid != os.Getuid() {
			t.Fatalf("listener observed SO_PEERCRED euid %d, want the bound uid %d", p.uid, os.Getuid())
		}
	} else {
		t.Logf("SO_PEERCRED not asserted on %s: %v", runtime.GOOS, p.err)
	}

	// A nonexistent path is an ordinary error reply, and the channel stays
	// healthy afterwards.
	if _, err := mc.Dial(ctx, filepath.Join(dir, "absent.sock")); err == nil {
		t.Fatal("dial of nonexistent socket should fail")
	}
	if err := mc.Ping(ctx); err != nil {
		t.Fatalf("ping after failed dial: %v", err)
	}
}

// TestFwdDialCrossUser is the cross-uid dial pin. Root runs need a
// root-owned socket and a non-root bound monitor, via the sshfwda test
// user. With the monitor bound to the non-root user:
//
//   - a root-owned 0600 unix socket cannot be dialed
//   - a world-accessible root-owned socket can be dialed, and the
//     listener observes SO_PEERCRED euid == the bound uid
func TestFwdDialCrossUser(t *testing.T) {
	uid, gid := ensureFwdTestUser(t)
	mc := startFwdTestMonitor(t, uid, gid, []int{gid})
	ctx, cancel := testCtx()
	defer cancel()

	dir := t.TempDir() // root-owned; sockets live here, binds do not
	// Make the dir chain below /tmp traversable so the dial pins are
	// about the socket mode, not the root-owned 0700 temp dirs. /tmp
	// itself stays untouched; its sticky bit must survive for the
	// unlink-if-owned test's semantics.
	for d := dir; d != "/tmp"; d = filepath.Dir(d) {
		if fi, err := os.Stat(d); err != nil {
			t.Fatal(err)
		} else if fi.Mode().Perm()&0o055 != 0o055 {
			if err := os.Chmod(d, fi.Mode().Perm()|0o055); err != nil {
				t.Fatal(err)
			}
		}
		if filepath.Dir(d) == d {
			break
		}
	}

	priv := filepath.Join(dir, "priv.sock")
	l0, err := net.Listen("unix", priv)
	if err != nil {
		t.Fatal(err)
	}
	defer l0.Close()
	if err := os.Chmod(priv, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := mc.Dial(ctx, priv); err == nil {
		t.Fatal("dial of a root-owned 0600 socket as a non-root-bound monitor should fail (DAC)")
	} else {
		t.Logf("root-owned 0600 dial (want permission denied): %v", err)
		if !strings.Contains(err.Error(), "permission denied") {
			t.Errorf("want an EACCES-flavored error, got: %v", err)
		}
	}

	pub := filepath.Join(dir, "pub.sock")
	l1, err := net.Listen("unix", pub)
	if err != nil {
		t.Fatal(err)
	}
	defer l1.Close()
	if err := os.Chmod(pub, 0o666); err != nil {
		t.Fatal(err)
	}
	peers := make(chan int, 1)
	go func() {
		c, err := l1.Accept()
		if err != nil {
			peers <- -1
			return
		}
		defer c.Close()
		pu, perr := peerCredUID(c)
		if perr != nil {
			peers <- -1
			return
		}
		peers <- pu
		c.SetDeadline(time.Now().Add(5 * time.Second))
		b := make([]byte, 16)
		c.Read(b)
	}()
	c, err := mc.Dial(ctx, pub)
	if err != nil {
		t.Fatalf("dial of an accessible socket as the bound user: %v", err)
	}
	c.SetDeadline(time.Now().Add(5 * time.Second))
	c.Write([]byte("x"))
	c.Close()
	select {
	case pu := <-peers:
		if pu == -1 {
			t.Skipf("SO_PEERCRED helper unavailable on %s", runtime.GOOS)
		}
		t.Logf("SO_PEERCRED observed euid %d == bound uid %d (the dialer ran as the bound user, never as the root monitor)", pu, uid)
		if pu != uid {
			t.Fatalf("SO_PEERCRED euid = %d, want the bound uid %d (and NOT 0)", pu, uid)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("listener never observed the dial")
	}
}

// TestFwdListenUnix binds a unix listener through the bound-identity child
// and pins the socket's construction: mode 0600 from creation, owner
// equal to the bound uid. The listener serves a connection end to end.
func TestFwdListenUnix(t *testing.T) {
	uid, gid, groups := fwdBoundIdentity(t)
	mc := startFwdTestMonitor(t, uid, gid, groups)
	ctx, cancel := testCtx()
	defer cancel()

	dir := fwdWritableDir(t, uid, gid)
	path := filepath.Join(dir, "l.sock")
	ln, err := mc.Listen(ctx, "unix", path, false)
	if err != nil {
		t.Fatalf("monitor listen unix: %v", err)
	}
	defer ln.Close()

	fi, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := fi.Mode().Perm(); got != 0o600 {
		t.Errorf("socket mode = %o, want 600 (umask-at-bind)", got)
	}
	if fi.Mode()&fs.ModeSocket == 0 {
		t.Errorf("%s is not a socket", path)
	}
	if st, ok := fi.Sys().(*syscall.Stat_t); ok && st.Uid != uint32(uid) {
		t.Errorf("socket owner uid = %d, want the bound uid %d", st.Uid, uid)
	}

	// Connect through it: accept works, data flows.
	done := make(chan string, 1)
	go func() {
		a, err := ln.Accept()
		if err != nil {
			done <- ""
			return
		}
		defer a.Close()
		a.SetDeadline(time.Now().Add(5 * time.Second))
		b := make([]byte, 64)
		n, _ := a.Read(b)
		a.Write(b[:n])
		done <- string(b[:n])
	}()
	c, err := net.Dial("unix", path)
	if err != nil {
		t.Fatalf("connect to monitor listener: %v", err)
	}
	defer c.Close()
	if got := connRoundTrip(t, c, "ping"); got != "ping" {
		t.Fatalf("echo through monitor listener = %q, want %q", got, "ping")
	}
	if got := <-done; got != "ping" {
		t.Fatalf("accepted side saw %q, want %q", got, "ping")
	}

	// Binding the same live path again without unlink fails EADDRINUSE.
	if _, err := mc.Listen(ctx, "unix", path, false); err == nil {
		t.Fatal("listen at an existing live socket path without unlink should fail")
	} else if !strings.Contains(err.Error(), "address already in use") {
		t.Errorf("want an EADDRINUSE-flavored error, got: %v", err)
	}
}

// TestFwdListenUnlinkIfOwned pins the listen op's unlink-if-owned
// semantics: the conn's own stale socket, left by a previous listen,
// is removed and rebound, and a foreign-owned socket is left alone
// with the bind failing EADDRINUSE. See fwdUnlinkIfOwned. The
// foreign-owned half needs root (creating a foreign-owned live
// socket).
func TestFwdListenUnlinkIfOwned(t *testing.T) {
	uid, gid, groups := fwdBoundIdentity(t)
	mc := startFwdTestMonitor(t, uid, gid, groups)
	ctx, cancel := testCtx()
	defer cancel()

	dir := fwdWritableDir(t, uid, gid)
	path := filepath.Join(dir, "u.sock")

	ln1, err := mc.Listen(ctx, "unix", path, false)
	if err != nil {
		t.Fatalf("first listen: %v", err)
	}
	ln1.Close() // leaves the socket file in place (no unlink)
	if _, err := os.Lstat(path); err != nil {
		t.Fatalf("stale socket file should exist after Close: %v", err)
	}
	ln2, err := mc.Listen(ctx, "unix", path, true)
	if err != nil {
		t.Fatalf("listen with unlink-if-owned over own stale socket: %v", err)
	}
	defer ln2.Close()
	c, err := net.Dial("unix", path)
	if err != nil {
		t.Fatalf("connect to rebound socket: %v", err)
	}
	c.Close()

	if os.Getuid() == 0 && uid != 0 {
		// A foreign-owned live socket in the canonical sticky dir: the
		// child's lstat refuses the unlink, the bind fails, and the
		// original socket is untouched.
		foreign := filepath.Join("/tmp", fmt.Sprintf("fwdtest-foreign-%d.sock", os.Getpid()))
		fl, err := net.Listen("unix", foreign)
		if err != nil {
			t.Fatal(err)
		}
		defer fl.Close()
		defer os.Remove(foreign)
		if _, err := mc.Listen(ctx, "unix", foreign, true); err == nil {
			t.Fatal("listen over a foreign-owned socket should fail")
		} else if !strings.Contains(err.Error(), "address already in use") {
			t.Errorf("want an EADDRINUSE-flavored error, got: %v", err)
		}
		// Untouched: the original socket still accepts.
		c, err := net.Dial("unix", foreign)
		if err != nil {
			t.Fatalf("original socket dead after refused listen: %v", err)
		}
		c.Close()
	} else if os.Getuid() != 0 {
		t.Log("foreign-owned half of the unlink test is root-only (needs a socket owned by another user)")
	}
}

// TestFwdListenTCP binds TCP listeners as the bound (non-root) identity:
// loopback and wildcard binds work, the reply echoes the
// concrete bound address, and a privileged port fails EACCES by kernel
// construction.
func TestFwdListenTCP(t *testing.T) {
	uid, gid, groups := fwdBoundIdentity(t)
	if uid == 0 {
		t.Skip("bound identity is root: privileged ports would succeed; the non-root-bound variant is the meaningful pin")
	}
	mc := startFwdTestMonitor(t, uid, gid, groups)
	ctx, cancel := testCtx()
	defer cancel()

	ln, err := mc.Listen(ctx, "tcp", "127.0.0.1:0", false)
	if err != nil {
		t.Fatalf("listen tcp 127.0.0.1:0: %v", err)
	}
	defer ln.Close()
	if _, portStr, err := net.SplitHostPort(ln.Addr().String()); err != nil {
		t.Fatal(err)
	} else if port, _ := strconv.Atoi(portStr); port == 0 {
		t.Fatalf("bound port = %q, want a concrete port", portStr)
	}

	// The reply echoes the bound address.
	r, fds, err := mc.call(ctx, rpcListenReq(0, "tcp", "127.0.0.1:0", false, false))
	if err != nil {
		t.Fatalf("raw listen call: %v", err)
	}
	if r.Addr == "" {
		closeFds(fds)
		t.Fatalf("listen reply Addr echo missing: %+v", r)
	}
	if len(fds) != 1 {
		closeFds(fds)
		t.Fatalf("listen reply carried %d fds, want 1", len(fds))
	}
	if ln2, err := wrapListenerFD(fds[0], r.Addr); err != nil {
		t.Fatalf("wrap listener fd: %v", err)
	} else {
		ln2.Close()
	}

	lnAll, err := mc.Listen(ctx, "tcp", "0.0.0.0:0", false)
	if err != nil {
		t.Fatalf("listen tcp 0.0.0.0:0: %v", err)
	}
	lnAll.Close()

	// A privileged port fails EACCES: the bind runs as the bound user.
	// Only where the kernel enforces the restriction: privileged CI
	// containers often set ip_unprivileged_port_start to 0, which lets
	// any uid bind any port, and darwin does not restrict the range at
	// all. The rest of this test is unaffected.
	if unprivilegedPrivilegedBinds() {
		t.Skip("kernel allows unprivileged binds to privileged ports; the EACCES pin is vacuous here")
	}
	for _, p := range []string{"1", "13", "23", "37"} {
		_, err := mc.Listen(ctx, "tcp", "127.0.0.1:"+p, false)
		if err == nil {
			t.Fatalf("privileged bind 127.0.0.1:%s succeeded as uid %d: privilege leak", p, uid)
		}
		if strings.Contains(err.Error(), "permission denied") {
			t.Logf("privileged port %s as uid %d (want permission denied): %v", p, uid, err)
			return
		}
		// Not EACCES: fall through to the next candidate port (e.g. one
		// already in use); exhausting them all fails below.
	}
	t.Fatal("no privileged-port candidate produced permission denied")
}

// unprivilegedPrivilegedBinds reports whether this kernel lets an
// unprivileged user bind ports below 1024. Linux exposes the floor as
// ip_unprivileged_port_start, which privileged CI containers often set
// to 0, and darwin does not restrict the range at all. The
// privileged-bind-must-fail assertions are only meaningful where the
// kernel enforces the restriction.
func unprivilegedPrivilegedBinds() bool {
	if runtime.GOOS != "linux" {
		return true
	}
	b, err := os.ReadFile("/proc/sys/net/ipv4/ip_unprivileged_port_start")
	if err != nil {
		// The floor is unknowable; assume the kernel enforces the
		// restriction and keep the assertions live.
		return false
	}
	start, err := strconv.Atoi(strings.TrimSpace(string(b)))
	return err == nil && start < 1024
}

// TestFwdListenAgent pins the agent-forwarding socket's construction:
// a user-owned 0700 temp dir and a 0600 socket inside it, created by
// umask-at-bind, the path
// in the reply, a working accept, and caller-side RemoveAll cleanup.
func TestFwdListenAgent(t *testing.T) {
	uid, gid, groups := fwdBoundIdentity(t)
	mc := startFwdTestMonitor(t, uid, gid, groups)
	ctx, cancel := testCtx()
	defer cancel()

	ln, sockPath, err := mc.ListenAgent(ctx)
	if err != nil {
		t.Fatalf("listen agent: %v", err)
	}
	defer ln.Close()

	dir := filepath.Dir(sockPath)
	if base := filepath.Base(dir); !strings.HasPrefix(base, "auth-agent") {
		t.Errorf("agent dir base = %q, want an auth-agent* temp dir", base)
	}
	dfi, err := os.Lstat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got := dfi.Mode().Perm(); got != 0o700 {
		t.Errorf("agent dir mode = %o, want 700", got)
	}
	if st, ok := dfi.Sys().(*syscall.Stat_t); ok && st.Uid != uint32(uid) {
		t.Errorf("agent dir owner uid = %d, want the bound uid %d", st.Uid, uid)
	}
	sfi, err := os.Lstat(sockPath)
	if err != nil {
		t.Fatal(err)
	}
	if sfi.Mode()&fs.ModeSocket == 0 {
		t.Errorf("%s is not a socket", sockPath)
	}
	if got := sfi.Mode().Perm(); got != 0o600 {
		t.Errorf("agent socket mode = %o, want 600 (umask-at-bind)", got)
	}
	if st, ok := sfi.Sys().(*syscall.Stat_t); ok && st.Uid != uint32(uid) {
		t.Errorf("agent socket owner uid = %d, want the bound uid %d", st.Uid, uid)
	}

	// Connect through it; the listener accepts.
	c, err := net.Dial("unix", sockPath)
	if err != nil {
		t.Fatalf("connect to agent socket: %v", err)
	}
	if err := c.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	c.Close()
	accepted := make(chan error, 1)
	go func() {
		a, err := ln.Accept()
		if a != nil {
			a.Close()
		}
		accepted <- err
	}()
	if err := <-accepted; err != nil {
		t.Fatalf("accept on agent listener: %v", err)
	}

	// Caller-side cleanup of the whole dir.
	if err := os.RemoveAll(dir); err != nil {
		t.Fatalf("RemoveAll of agent dir: %v", err)
	}
}

// TestFwdZombieHygiene pins that one-shot fwd children are reaped
// promptly: after a burst of dials, none of the monitor's children remain
// zombies within ~1s. The SIGCHLD-driven sweep is the bound.
func TestFwdZombieHygiene(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("zombie scan via /proc is linux-only")
	}
	mc := startFwdTestMonitor(t, os.Getuid(), os.Getgid(), testGroups(t))

	dir := fwdWritableDir(t, os.Getuid(), os.Getgid())
	path := filepath.Join(dir, "z.sock")
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	ctx, cancel := testCtx()
	defer cancel()
	for i := 0; i < 5; i++ {
		c, err := mc.Dial(ctx, path)
		if err != nil {
			t.Fatalf("dial %d: %v", i, err)
		}
		c.Close()
	}
	deadline := time.Now().Add(time.Second)
	for {
		if n := zombieChildrenOf(mc.Pid()); n == 0 {
			return
		} else if time.Now().After(deadline) {
			t.Fatalf("%d zombie children of monitor %d remain after 1s", n, mc.Pid())
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// zombieChildrenOf counts a process's zombie children by scanning /proc
// (state Z with the given ppid).
func zombieChildrenOf(ppid int) int {
	matches, err := filepath.Glob("/proc/[0-9]*/stat")
	if err != nil {
		return 0
	}
	n := 0
	for _, m := range matches {
		b, err := os.ReadFile(m)
		if err != nil {
			continue
		}
		s := string(b)
		i := strings.LastIndexByte(s, ')')
		if i < 0 || i+2 >= len(s) {
			continue
		}
		fields := strings.Fields(s[i+2:])
		if len(fields) < 2 {
			continue
		}
		if fields[0] == "Z" && fields[1] == strconv.Itoa(ppid) {
			n++
		}
	}
	return n
}

// TestFwdRequestsCarryNoIdentity pins that the dial/listen request
// shapes carry no identity keys on the wire.
func TestFwdRequestsCarryNoIdentity(t *testing.T) {
	for _, f := range []rpcFrame{
		rpcDialReq(1, "unix", "/tmp/x.sock"),
		rpcDialReq(6, "tcp", "localhost:443"),
		rpcListenReq(2, "unix", "/tmp/x.sock", false, false),
		rpcListenReq(3, "unix", "/tmp/x.sock", true, false),
		rpcListenReq(4, "tcp", "127.0.0.1:0", false, false),
		rpcListenReq(5, "", "", false, true),
	} {
		b, err := json.Marshal(f)
		if err != nil {
			t.Fatal(err)
		}
		s := string(b)
		for _, key := range []string{`"uid"`, `"gid"`, `"groups"`, `"user"`, `"euid"`, `"cred"`} {
			if strings.Contains(s, key) {
				t.Fatalf("op %s request %s carries identity key %s", f.Op, s, key)
			}
		}
	}

	// The ops refuse unsupported networks and malformed addresses, and
	// the channel stays healthy afterwards.
	mc := startFwdTestMonitor(t, os.Getuid(), os.Getgid(), testGroups(t))
	ctx, cancel := testCtx()
	defer cancel()
	for _, f := range []rpcFrame{
		{Op: opDial, Net: "udp", Addr: "127.0.0.1:1"},
		{Op: opDial, Net: "tcp", Addr: "127.0.0.1:65536"},
		{Op: opDial, Net: "tcp", Addr: "localhost:http"},
		{Op: opDial, Net: "tcp", Addr: "missing-port"},
		{Op: opDial, Net: "unix", Addr: "relative.sock"},
		{Op: opDial, Net: "unix", Addr: "@/abstract"},
		{Op: opListen, Net: "udp", Addr: "x"},
		{Op: opListen, Net: "unix", Addr: "relative.sock"},
	} {
		if _, _, err := mc.call(ctx, f); err == nil {
			t.Fatalf("op %s %v: unexpectedly accepted", f.Op, f)
		}
	}
	if err := mc.Ping(ctx); err != nil {
		t.Fatalf("ping after refused ops: %v", err)
	}
}

// TestFwdDialLatencyBudget measures the per-dial cost: the spawn of the
// one-shot child, in production a full tailscaled binary re-exec, plus
// the unix dial round trip. The numbers are logged; the test makes no
// tight assertion.
func TestFwdDialLatencyBudget(t *testing.T) {
	mc := startFwdTestMonitor(t, os.Getuid(), os.Getgid(), testGroups(t))

	dir := fwdWritableDir(t, os.Getuid(), os.Getgid())
	path := filepath.Join(dir, "b.sock")
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	const n = 20
	var total, worst time.Duration
	for i := 0; i < n; i++ {
		start := time.Now()
		c, err := mc.Dial(ctx, path)
		if err != nil {
			t.Fatalf("dial %d: %v", i, err)
		}
		d := time.Since(start)
		total += d
		if d > worst {
			worst = d
		}
		c.Close()
	}
	t.Logf("per-dial budget (n=%d): mean %v, worst %v (spawn of the one-shot fwd child + unix dial round trip)", n, total/n, worst)
}
