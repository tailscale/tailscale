// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build (linux && !android) || (darwin && !ios) || freebsd || openbsd

// Conn-level tests for the monitor-backed forwarding paths: unix -L,
// unix -R, TCP -R, and agent forwarding. The tested entry points are
// mayForwardLocalUnixTo, mayReverseUnixForwardTo, fwdTCPHandler, and
// handleSSHAgentForwarding. The forwarding-path tests drive a real conn
// with a real monitor and real one-shot fwd children through the
// self-exec seams in fwdchild_test.go. TestFwdAllowedSocketPathCaps and
// TestConnMonitorClosedRefusesRespawn exercise the lexical policy and
// the closed flag directly. Under root the conn binds to the non-root
// test user, so the cross-uid closures are pinned: socket ownership,
// permission-denied dials, and kernel privileged-port refusal. Non-root
// runs bind to the current user.

package tailssh

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	gliderssh "github.com/tailscale/gliderssh"
	gossh "golang.org/x/crypto/ssh"
	"tailscale.com/envknob"
	"tailscale.com/net/memnet"
	"tailscale.com/tailcfg"
	testssh "tailscale.com/tempfork/sshtest/ssh"
)

// fwdTestIdentity returns the local user the conn binds its monitor to.
// Under root it is the non-root test user, so sockets created by the
// forwarding children are owned by the session user. Otherwise it is the
// current user, where a non-root tailscaled binds the monitor to itself.
func fwdTestIdentity(t *testing.T) *userMeta {
	t.Helper()
	if os.Getuid() == 0 {
		uid, gid := ensureFwdTestUser(t)
		return &userMeta{User: user.User{
			Username: fwdTestUser,
			Uid:      strconv.Itoa(uid),
			Gid:      strconv.Itoa(gid),
			HomeDir:  "/nonexistent", // no home needed. Tests use /tmp paths.
		}}
	}
	u, err := user.Current()
	if err != nil {
		t.Fatalf("user.Current: %v", err)
	}
	return &userMeta{User: *u}
}

// newFwdTestConn returns a conn whose forwarding paths go through a real
// monitor (spawned lazily on first use), bound to lu's identity, with the
// given final action. It registers the monitor self-exec seams and closes
// the monitor on cleanup.
func newFwdTestConn(t *testing.T, lu *userMeta, final *tailcfg.SSHAction) *conn {
	t.Helper()
	exe := makeExecutableReachable(t)
	// The override must reach the monitor process, which spawns the fwd
	// children. It therefore travels through the environment.
	t.Setenv("TS_TEST_SSH_FWD_PREFIX", strings.Join(testFwdPrefix, " "))
	old := monitorSpawnPrefix
	monitorSpawnPrefix = testMonitorPrefix
	t.Cleanup(func() { monitorSpawnPrefix = old })

	groups := []string{}
	if g, err := os.Getgroups(); err == nil {
		for _, v := range g {
			groups = append(groups, strconv.Itoa(v))
		}
	} else {
		t.Fatalf("os.Getgroups: %v", err)
	}
	// Install a matching policy and authenticated state for forwarding rechecks.
	rule := &tailcfg.SSHRule{
		SSHUsers:   map[string]string{lu.Username: lu.Username},
		Action:     final,
		Principals: []*tailcfg.SSHPrincipal{{Any: true}},
	}
	c := &conn{
		// t.Logf so bind/spawn failures are visible in test output.
		// tailscaledPath is the reachable copy of the test binary: the
		// monitor exec'd from it spawns the fwd children from the same
		// path, and under a root run the bound user can exec the copy
		// but not the original.
		srv: &server{logf: t.Logf, tailscaledPath: exe, lb: &localState{
			sshEnabled:   true,
			matchingRule: rule,
		}},
		localUser:       lu,
		mappedLocalUser: lu.Username,
		userGroupIDs:    groups,
		action0:         final,
		finalAction:     final,
		info: &sshConnInfo{
			sshUser: lu.Username,
			src:     netip.MustParseAddrPort("100.100.100.101:2231"),
			dst:     netip.MustParseAddrPort("100.100.100.102:22"),
		},
	}
	c.authCompleted.Store(true)
	t.Cleanup(c.closeConnMonitor)
	return c
}

// fwdTestCtx returns a gliderssh.Context for driving the conn callbacks and
// handlers directly, whose ContextKeyConn value is sshConn and which is
// canceled by the returned cancel func. Every other Value lookup returns
// true, matching process_unix_test.go's agentFwdContext.
func fwdTestCtx(sshConn gossh.Conn) (gliderssh.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(context.Background())
	return fwdTestContext{Context: ctx, Mutex: &sync.Mutex{}, conn: sshConn}, cancel
}

// fwdTestContext implements gliderssh.Context. Value serves ContextKeyConn
// and returns true otherwise. Everything else is inert. The embedded mutex
// satisfies the interface's Locker requirement, like process_unix_test.go's
// agentFwdContext.
type fwdTestContext struct {
	context.Context
	*sync.Mutex
	conn gossh.Conn
}

func (c fwdTestContext) Value(key any) any {
	if key == gliderssh.ContextKeyConn {
		return c.conn
	}
	return true
}
func (fwdTestContext) User() string                        { return "test" }
func (fwdTestContext) SessionID() string                   { return "test" }
func (fwdTestContext) ClientVersion() string               { return "2.0" }
func (fwdTestContext) ServerVersion() string               { return "2.0" }
func (fwdTestContext) RemoteAddr() net.Addr                { return nil }
func (fwdTestContext) LocalAddr() net.Addr                 { return nil }
func (fwdTestContext) Permissions() *gliderssh.Permissions { return nil }
func (fwdTestContext) SetValue(key, value any)             {}

// fwdTestSSHConn is a gossh.ServerConn stub for the TCP -R handler.
// OpenChannel returns an echo channel. What the client writes through the
// forwarded TCP connection comes back, so bicopy is exercised end to end.
type fwdTestSSHConn struct{ gossh.Conn }

// OpenChannel returns an echo channel so the accept loop and bicopy are
// exercised end to end. The handler type-asserts the ContextKeyConn value
// to gossh.Conn. A real server hands it a *gossh.ServerConn.
func (fwdTestSSHConn) OpenChannel(name string, data []byte) (gossh.Channel, <-chan *gossh.Request, error) {
	if name != "forwarded-tcpip" {
		return nil, nil, fmt.Errorf("unexpected channel type %q", name)
	}
	return newEchoChannel(), nil, nil
}

// echoChannel is a gossh.Channel that echoes its Write payload back out of
// Read. bicopy(ch, nc) then makes the TCP peer see its own writes.
type echoChannel struct {
	buf     chan []byte
	closed  chan struct{}
	closeMu sync.Mutex
}

func newEchoChannel() *echoChannel {
	return &echoChannel{buf: make(chan []byte, 16), closed: make(chan struct{})}
}

func (e *echoChannel) Read(p []byte) (int, error) {
	select {
	case b := <-e.buf:
		return copy(p, b), nil
	case <-e.closed:
		return 0, io.EOF
	}
}

func (e *echoChannel) Write(p []byte) (int, error) {
	select {
	case e.buf <- bytes.Clone(p):
		return len(p), nil
	case <-e.closed:
		return 0, errors.New("channel closed")
	}
}

func (e *echoChannel) Close() error {
	e.closeMu.Lock()
	defer e.closeMu.Unlock()
	select {
	case <-e.closed:
	default:
		close(e.closed)
	}
	return nil
}

func (e *echoChannel) CloseWrite() error { return nil }
func (e *echoChannel) SendRequest(string, bool, []byte) (bool, error) {
	return false, nil
}
func (e *echoChannel) Stderr() io.ReadWriter { return e }

// fwdTmpDir creates a directory under /tmp, inside the socket-path
// allowlist, that the monitor's bound identity can use. Root runs create
// it as root and chmod it 0777 for the non-root bound user.
func fwdTmpDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "tailssh-fwd-test-")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o777); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return dir
}

// statOwnerMode returns the owner uid and permission bits of path.
func statOwnerMode(t *testing.T, path string) (int, os.FileMode) {
	t.Helper()
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		t.Fatalf("stat %q: unsupported syscall.Stat_t type %T", path, fi.Sys())
	}
	return int(st.Uid), fi.Mode().Perm()
}

// setDeadlineConn gives every blocking read/write in these tests a
// deadline so nothing can wedge the suite.
func setDeadlineConn(t *testing.T, c net.Conn) {
	t.Helper()
	dl := time.Now().Add(10 * time.Second)
	if err := c.SetDeadline(dl); err != nil {
		t.Fatal(err)
	}
}

// TestFwdConnLocalUnixDial drives mayForwardLocalUnixTo (unix -L) through
// a real monitor: a dial to an accessible socket in /tmp returns a live
// connection dialed as the bound identity, and paths outside the
// allowlist (or relative/abstract) are rejected.
func TestFwdConnLocalUnixDial(t *testing.T) {
	lu := fwdTestIdentity(t)
	c := newFwdTestConn(t, lu, &tailcfg.SSHAction{
		Accept:                   true,
		AllowLocalPortForwarding: true,
	})

	socketPath := filepath.Join(fwdTmpDir(t), "service.sock")
	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	// The test process owns the socket and may be root while the conn
	// binds to the non-root test user, so make it connectable by the
	// bound identity. TestFwdDialRoundTrip and TestFwdDialCrossUser pin
	// the permission-denied direction; here we assert the conn-level path
	// returns a live conn.
	if err := os.Chmod(socketPath, 0o666); err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			sc, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer sc.Close()
				io.Copy(sc, sc)
			}()
		}
	}()

	ctx, _ := fwdTestCtx(nil)
	uc, err := c.mayForwardLocalUnixTo(ctx, socketPath)
	if err != nil {
		t.Fatalf("mayForwardLocalUnixTo(%q): %v", socketPath, err)
	}
	defer uc.Close()
	setDeadlineConn(t, uc)

	want := "GET /_ping HTTP/1.1\r\n\r\n"
	if _, err := uc.Write([]byte(want)); err != nil {
		t.Fatalf("write through forwarded conn: %v", err)
	}
	got := make([]byte, len(want))
	if _, err := io.ReadFull(uc, got); err != nil {
		t.Fatalf("read through forwarded conn: %v", err)
	}
	if string(got) != want {
		t.Errorf("echo = %q; want %q", got, want)
	}

	// Paths outside the allowed directories are rejected.
	for _, bad := range []string{"/var/run/docker.sock", "/etc/evil.sock"} {
		_, err := c.mayForwardLocalUnixTo(ctx, bad)
		if err == nil {
			t.Errorf("dial %q: unexpectedly allowed", bad)
			continue
		}
		if !errors.Is(err, gliderssh.ErrRejected) || !strings.Contains(err.Error(), "not in an allowed directory") {
			t.Errorf("dial %q error = %v; want an ErrRejected \"not in an allowed directory\"", bad, err)
		}
	}
	// Relative and abstract paths are rejected.
	for _, bad := range []string{"relative.sock", "@/tmp/abstract.sock"} {
		_, err := c.mayForwardLocalUnixTo(ctx, bad)
		if !errors.Is(err, gliderssh.ErrRejected) {
			t.Errorf("dial %q error = %v; want ErrRejected", bad, err)
		}
	}
}

// TestFwdConnReverseUnixListen drives mayReverseUnixForwardTo (unix -R):
// the returned listener's socket is 0600 and owned by the bound identity.
// Data flows through it, and a foreign-owned live socket in a sticky
// directory is not unlinked in the root run.
func TestFwdConnReverseUnixListen(t *testing.T) {
	lu := fwdTestIdentity(t)
	uid, _ := strconv.Atoi(lu.Uid)
	c := newFwdTestConn(t, lu, &tailcfg.SSHAction{
		Accept:                    true,
		AllowLocalPortForwarding:  true, // for the dial-side half of the round trip
		AllowRemotePortForwarding: true,
	})

	socketPath := filepath.Join(fwdTmpDir(t), "reverse.sock")
	ctx, _ := fwdTestCtx(nil)
	ln, err := c.mayReverseUnixForwardTo(ctx, socketPath)
	if err != nil {
		t.Fatalf("mayReverseUnixForwardTo(%q): %v", socketPath, err)
	}
	t.Cleanup(func() { ln.Close() })

	// Socket created by the monitor's child: 0600, owned by the bound
	// identity (the non-root test user under root runs).
	gotUid, mode := statOwnerMode(t, socketPath)
	if mode != 0o600 {
		t.Errorf("socket mode = %o; want 0600", mode)
	}
	if gotUid != uid {
		t.Errorf("socket uid = %d; want %d (the session user)", gotUid, uid)
	}

	// Round trip: accept on the reverse listener, dial it through the
	// conn's own -L path, which is self-consistent because the same user
	// can reach its own 0600 socket.
	go func() {
		sc, err := ln.Accept()
		if err != nil {
			return
		}
		defer sc.Close()
		io.Copy(sc, sc)
	}()
	uc, err := c.mayForwardLocalUnixTo(ctx, socketPath)
	if err != nil {
		t.Fatalf("dial reverse socket through -L path: %v", err)
	}
	defer uc.Close()
	setDeadlineConn(t, uc)
	want := "hello reverse"
	if _, err := uc.Write([]byte(want)); err != nil {
		t.Fatalf("write: %v", err)
	}
	got := make([]byte, len(want))
	if _, err := io.ReadFull(uc, got); err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(got) != want {
		t.Errorf("echo = %q; want %q", got, want)
	}

	// Root run: a foreign root-owned live socket in sticky /tmp is not
	// unlinked by a bind from the non-root session user. The bind fails
	// EADDRINUSE and the original socket still accepts. Subtest so the
	// non-root round trip above passes on its own and this guard's skip
	// cannot erase it.
	t.Run("foreign-socket-not-unlinked", func(t *testing.T) {
		if os.Getuid() != 0 {
			t.Skipf("non-root run: bound identity is the current user, so the foreign-socket case is same-uid; TestFwdListenUnlinkIfOwned pins it at monitor level")
		}
		foreignPath := filepath.Join(fwdTmpDir(t), "foreign.sock")
		foreignLn, err := net.Listen("unix", foreignPath)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { foreignLn.Close() })
		go func() {
			for {
				sc, err := foreignLn.Accept()
				if err != nil {
					return
				}
				sc.Close()
			}
		}()
		if _, err := c.mayReverseUnixForwardTo(ctx, foreignPath); err == nil {
			t.Fatal("bind over foreign-owned socket: unexpectedly allowed")
		} else if !strings.Contains(err.Error(), "address already in use") {
			t.Errorf("bind over foreign socket error = %v; want EADDRINUSE", err)
		}
		// The foreign socket was not unlinked and still accepts.
		if _, _, err := statOwnerModeOK(foreignPath); err != nil {
			t.Fatalf("foreign socket unlinked by refused bind: %v", err)
		}
		if _, err := net.Dial("unix", foreignPath); err != nil {
			t.Errorf("foreign socket no longer accepts: %v", err)
		}
	})
}

func statOwnerModeOK(path string) (int, os.FileMode, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return 0, 0, err
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, 0, fmt.Errorf("unsupported Stat_t %T", fi.Sys())
	}
	return int(st.Uid), fi.Mode().Perm(), nil
}

// TestFwdTCPHandler drives the tailssh-owned tcpip-forward handler: a
// loopback bind goes through the monitor's user-cred listener child and
// accepts with data echoing through the SSH channel stub. Non-loopback
// binds are rejected unless TS_SSH_FORWARD_GATEWAY_PORTS is set, and a
// privileged port is refused for a non-root bound identity.
func TestFwdTCPHandler(t *testing.T) {
	lu := fwdTestIdentity(t)
	c := newFwdTestConn(t, lu, &tailcfg.SSHAction{
		Accept:                    true,
		AllowRemotePortForwarding: true,
	})

	ctx, cancel := fwdTestCtx(fwdTestSSHConn{})
	t.Cleanup(cancel)
	h := &fwdTCPHandler{conn: c}
	tcpReq := func(addr string, port uint32) *gossh.Request {
		return &gossh.Request{
			Type:      "tcpip-forward",
			WantReply: true,
			Payload:   gossh.Marshal(fwdRemoteForwardRequest{BindAddr: addr, BindPort: port}),
		}
	}

	// 127.0.0.1:0 binds via the monitor's child and accepts. Data written
	// by a local dialer echoes back through the SSH channel stub.
	ok, payload := h.HandleSSHRequest(ctx, nil, tcpReq("127.0.0.1", 0))
	if !ok {
		t.Fatalf("tcpip-forward 127.0.0.1:0 rejected: %s", payload)
	}
	var succ fwdRemoteForwardSuccess
	if err := gossh.Unmarshal(payload, &succ); err != nil {
		t.Fatal(err)
	}
	if succ.BindPort == 0 {
		t.Fatal("reply carried no concrete port")
	}
	fwdAddr := net.JoinHostPort("127.0.0.1", strconv.Itoa(int(succ.BindPort)))
	tc, err := net.DialTimeout("tcp", fwdAddr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial forwarded listener %s: %v", fwdAddr, err)
	}
	defer tc.Close()
	setDeadlineConn(t, tc)
	want := "ping through reverse tcp forward"
	if _, err := tc.Write([]byte(want)); err != nil {
		t.Fatalf("write to forwarded listener: %v", err)
	}
	got := make([]byte, len(want))
	if _, err := io.ReadFull(tc, got); err != nil {
		t.Fatalf("read from forwarded listener: %v", err)
	}
	if string(got) != want {
		t.Errorf("echo = %q; want %q", got, want)
	}

	// Connection cancellation must close the forwarded listener.
	cancel()
	eventually(t, 5*time.Second, "forwarded listener remained open after cancellation", func() bool {
		conn, err := net.DialTimeout("tcp", fwdAddr, time.Second)
		if err != nil {
			return true
		}
		conn.Close()
		return false
	})

	// Non-loopback binds are rejected without the gateway-ports knob…
	ctx2, cancel2 := fwdTestCtx(fwdTestSSHConn{})
	t.Cleanup(cancel2)
	if ok, msg := h.HandleSSHRequest(ctx2, nil, tcpReq("0.0.0.0", 0)); ok {
		t.Fatal("tcpip-forward 0.0.0.0:0 allowed without TS_SSH_FORWARD_GATEWAY_PORTS")
	} else if !bytes.Contains(msg, []byte("non-loopback")) {
		t.Errorf("rejection message = %q; want non-loopback notice", msg)
	}
	// …and allowed with it. The knob widens address policy only, and the
	// bind still runs with the user's credentials.
	envknob.SetenvForTest(t, "TS_SSH_FORWARD_GATEWAY_PORTS", "1")
	if ok, msg := h.HandleSSHRequest(ctx2, nil, tcpReq("0.0.0.0", 0)); !ok {
		t.Fatalf("tcpip-forward 0.0.0.0:0 rejected with TS_SSH_FORWARD_GATEWAY_PORTS: %s", msg)
	}
	cancel2()

	// Privileged ports fail at the kernel for the non-root bound
	// identity, matching OpenSSH's rule that only root binds privileged
	// ports. The port-80 refusal above pins that the bind runs as the
	// bound user. Only where the kernel enforces the restriction:
	// privileged CI containers often set ip_unprivileged_port_start to
	// 0, which lets any uid bind any port, and darwin does not restrict
	// the range at all.
	if unprivilegedPrivilegedBinds() {
		t.Log("skipping the privileged-port refusal: the kernel allows unprivileged privileged binds")
	} else {
		ctx3, cancel3 := fwdTestCtx(fwdTestSSHConn{})
		t.Cleanup(cancel3)
		if ok, msg := h.HandleSSHRequest(ctx3, nil, tcpReq("127.0.0.1", 80)); ok {
			t.Fatalf("tcpip-forward 127.0.0.1:80 allowed for non-root bound identity %q", lu.Username)
		} else {
			t.Logf("privileged bind rejected: %s", msg)
		}
		cancel3()
	}
}

// TestFwdTCPHandlerPolicyGate pins the handler's policy gates: the final
// action's AllowRemotePortForwarding and TS_SSH_DISABLE_FORWARDING.
func TestFwdTCPHandlerPolicyGate(t *testing.T) {
	lu := fwdTestIdentity(t)
	denied := newFwdTestConn(t, lu, &tailcfg.SSHAction{
		Accept:                    true,
		AllowRemotePortForwarding: false,
	})
	ctx, cancel := fwdTestCtx(fwdTestSSHConn{})
	t.Cleanup(cancel)
	h := &fwdTCPHandler{conn: denied}
	req := &gossh.Request{
		Type:      "tcpip-forward",
		WantReply: true,
		Payload:   gossh.Marshal(fwdRemoteForwardRequest{BindAddr: "127.0.0.1", BindPort: 0}),
	}
	if ok, msg := h.HandleSSHRequest(ctx, nil, req); ok {
		t.Fatal("tcpip-forward allowed without AllowRemotePortForwarding")
	} else if !bytes.Contains(msg, []byte("port forwarding is disabled")) {
		t.Errorf("rejection message = %q", msg)
	}

	envknob.SetenvForTest(t, "TS_SSH_DISABLE_FORWARDING", "1")
	if ok, msg := h.HandleSSHRequest(ctx, nil, req); ok {
		t.Fatal("tcpip-forward allowed with TS_SSH_DISABLE_FORWARDING")
	} else if !bytes.Contains(msg, []byte("port forwarding is disabled")) {
		t.Errorf("rejection message = %q", msg)
	}
	cancel()
}

// TestFwdDisableForwarding pins that TS_SSH_DISABLE_FORWARDING rejects all
// four forwarding paths.
func TestFwdDisableForwarding(t *testing.T) {
	envknob.SetenvForTest(t, "TS_SSH_DISABLE_FORWARDING", "1")
	lu := fwdTestIdentity(t)
	c := newFwdTestConn(t, lu, &tailcfg.SSHAction{
		Accept:                    true,
		AllowLocalPortForwarding:  true,
		AllowRemotePortForwarding: true,
		AllowAgentForwarding:      true,
	})
	ctx, cancel := fwdTestCtx(fwdTestSSHConn{})
	t.Cleanup(cancel)

	if _, err := c.mayForwardLocalUnixTo(ctx, "/tmp/anything.sock"); !errors.Is(err, gliderssh.ErrRejected) {
		t.Errorf("unix -L error = %v; want ErrRejected", err)
	}
	if _, err := c.mayReverseUnixForwardTo(ctx, "/tmp/anything.sock"); !errors.Is(err, gliderssh.ErrRejected) {
		t.Errorf("unix -R error = %v; want ErrRejected", err)
	}
	h := &fwdTCPHandler{conn: c}
	req := &gossh.Request{
		Type:      "tcpip-forward",
		WantReply: true,
		Payload:   gossh.Marshal(fwdRemoteForwardRequest{BindAddr: "127.0.0.1", BindPort: 0}),
	}
	if ok, msg := h.HandleSSHRequest(ctx, nil, req); ok {
		t.Error("TCP -R allowed with TS_SSH_DISABLE_FORWARDING")
	} else if !bytes.Contains(msg, []byte("port forwarding is disabled")) {
		t.Errorf("TCP -R rejection message = %q", msg)
	}
	// Agent forwarding silently does not start, as before.
	ss, s := newAgentTestSession(t, c)
	if err := ss.handleSSHAgentForwarding(s, lu); err != nil {
		t.Errorf("handleSSHAgentForwarding: %v", err)
	}
	if ss.agentListener != nil {
		t.Error("agent listener started with TS_SSH_DISABLE_FORWARDING")
	}
	cancel()
}

// TestFwdFullStackLocalUnix is the full-stack -L test. A real SSH
// connection from an sshtest client over memnet reaches a real tailssh
// server with a real policy, with SSHUsers mapping alice to the bound
// user. The direct-streamlocal dial goes through the conn's lazily
// spawned real monitor and its one-shot fwd child. The service reads a
// fixed-length payload under a deadline, echoes it, and on linux reports
// the dialer's peer uid, which must be the monitor's bound uid.
func TestFwdFullStackLocalUnix(t *testing.T) {
	lu := fwdTestIdentity(t)
	boundUID, err := strconv.Atoi(lu.Uid)
	if err != nil {
		t.Fatalf("parse bound uid %q: %v", lu.Uid, err)
	}

	// The monitor seam overrides must be in place before the conn lazily
	// spawns its monitor on the -L dial.
	exe := makeExecutableReachable(t)
	t.Setenv("TS_TEST_SSH_FWD_PREFIX", strings.Join(testFwdPrefix, " "))
	old := monitorSpawnPrefix
	monitorSpawnPrefix = testMonitorPrefix
	t.Cleanup(func() { monitorSpawnPrefix = old })

	// The service socket is in the allowlist's /tmp and is created by the
	// test process, which may be root while the conn binds to the
	// non-root test user, so it must be reachable by the bound identity.
	socketPath := filepath.Join(fwdTmpDir(t), "svc.sock")
	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	if err := os.Chmod(socketPath, 0o666); err != nil {
		t.Fatal(err)
	}

	payload := []byte("GET /_ping HTTP/1.1\r\n\r\n") // fixed, known length
	type serviceResult struct {
		peerUID int
		err     error
	}
	svc := make(chan serviceResult, 1)
	go func() {
		sc, err := ln.Accept()
		if err != nil {
			svc <- serviceResult{err: err}
			return
		}
		defer sc.Close()
		if err := sc.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
			svc <- serviceResult{err: err}
			return
		}
		got := make([]byte, len(payload))
		if _, err := io.ReadFull(sc, got); err != nil {
			svc <- serviceResult{err: fmt.Errorf("service read: %w", err)}
			return
		}
		if !bytes.Equal(got, payload) {
			svc <- serviceResult{err: fmt.Errorf("service got %q, want %q", got, payload)}
			return
		}
		// The dialer is the monitor's fwd child, so its credentials are
		// the conn's bound identity. peerCredUID is linux-only.
		peerUID := -1
		if runtime.GOOS == "linux" {
			peerUID, err = peerCredUID(sc)
			if err != nil {
				svc <- serviceResult{err: fmt.Errorf("service peer cred: %w", err)}
				return
			}
		}
		if _, err := sc.Write(payload); err != nil {
			svc <- serviceResult{err: fmt.Errorf("service echo: %w", err)}
			return
		}
		svc <- serviceResult{peerUID: peerUID}
	}()

	// The server runs a real auth flow with alice mapped to the bound
	// local user and -L forwarding allowed.
	rule := &tailcfg.SSHRule{
		SSHUsers: map[string]string{"alice": lu.Username},
		Action:   &tailcfg.SSHAction{Accept: true, AllowLocalPortForwarding: true},
		Principals: []*tailcfg.SSHPrincipal{
			{Any: true},
		},
	}
	s := &server{
		logf:           t.Logf,
		tailscaledPath: exe, // the reachable copy; see makeExecutableReachable
		lb: &localState{
			sshEnabled:   true,
			varRoot:      t.TempDir(),
			matchingRule: rule,
		},
	}

	src, dst := netip.MustParseAddrPort("100.100.100.101:2231"), netip.MustParseAddrPort("100.100.100.102:22")
	clientConn, serverConn := memnet.NewTCPConn(src, dst, 1024)
	// Deadline on the client side of the memnet transport, so nothing can
	// wedge the test waiting on a transport that stopped making progress.
	if err := clientConn.SetDeadline(time.Now().Add(30 * time.Second)); err != nil {
		t.Fatal(err)
	}

	var wg sync.WaitGroup
	wg.Go(func() {
		cl, chans, reqs, err := testssh.NewClientConn(clientConn, clientConn.RemoteAddr().String(), &testssh.ClientConfig{
			User:            "alice",
			HostKeyCallback: testssh.InsecureIgnoreHostKey(),
			Timeout:         15 * time.Second,
		})
		if err != nil {
			t.Errorf("client handshake: %v", err)
			return
		}
		client := testssh.NewClient(cl, chans, reqs)
		defer client.Close()

		uc, err := client.Dial("unix", socketPath)
		if err != nil {
			t.Errorf("client -L dial %q: %v", socketPath, err)
			return
		}
		defer uc.Close()
		// No deadline on the channel-backed conn because x/crypto channels
		// do not support deadlines. The memnet transport deadline above
		// and the fixed-length reads bound this side instead.
		if _, err := uc.Write(payload); err != nil {
			t.Errorf("write through forwarded conn: %v", err)
			return
		}
		got := make([]byte, len(payload))
		if _, err := io.ReadFull(uc, got); err != nil {
			t.Errorf("read through forwarded conn: %v", err)
			return
		}
		if !bytes.Equal(got, payload) {
			t.Errorf("echo = %q; want %q", got, payload)
		}
	})
	if err := s.HandleSSHConn(serverConn); err != nil {
		t.Errorf("HandleSSHConn: %v", err)
	}
	wg.Wait()

	select {
	case r := <-svc:
		if r.err != nil {
			t.Fatalf("service: %v", r.err)
		}
		if runtime.GOOS == "linux" && r.peerUID != boundUID {
			t.Errorf("service observed peer uid %d; want %d (the conn's bound identity, not root tailscaled)", r.peerUID, boundUID)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("service never saw the forwarded connection")
	}
}

// fwdTestCtxTimeout is fwdTestCtx with a deadline. The race test's dial
// attempts each carry a short budget so nothing can wedge the loop.
func fwdTestCtxTimeout(timeout time.Duration) (gliderssh.Context, context.CancelFunc) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	return fwdTestContext{Context: ctx, Mutex: &sync.Mutex{}, conn: nil}, cancel
}

// canaryListener is a marker-emitting canary unix socket for the
// root-dial-TOCTOU regression tests. Every accepted connection is served
// exactly one marker write and closed. markers is buffered so the accept
// loop never blocks. The test drains it to assert which side ever got
// served.
type canaryListener struct {
	ln      *net.UnixListener
	markers chan string
	done    chan struct{} // closed when the accept loop exits
}

// listenCanary binds the canary socket at path with a umask-at-bind mode
// and starts its marker-emitting accept loop. See canaryListener for the
// markers channel semantics. The mode 0o600 comes from umask 0o177 and
// 0o666 from umask 0o111, so the socket is created directly at the
// requested mode.
func listenCanary(t *testing.T, path string, mode int, marker string) *canaryListener {
	t.Helper()
	old := syscall.Umask(0o777 &^ mode)
	ln, err := net.Listen("unix", path)
	syscall.Umask(old)
	if err != nil {
		t.Fatalf("listen canary %q: %v", path, err)
	}
	c := &canaryListener{
		ln:      ln.(*net.UnixListener),
		markers: make(chan string, 64),
		done:    make(chan struct{}),
	}
	go func() {
		defer close(c.done)
		for {
			sc, err := ln.Accept()
			if err != nil {
				return
			}
			sc.(*net.UnixConn).SetDeadline(time.Now().Add(5 * time.Second))
			sc.Write([]byte(marker + "\n"))
			sc.Close()
			select {
			case c.markers <- marker:
			default:
			}
		}
	}()
	return c
}

// close stops the canary's accept loop and closes the socket.
// Closing the listener also unlinks the socket file.
func (c *canaryListener) close() {
	c.ln.Close()
	<-c.done
}

// TestFwdConnLocalUnixSymlinkToProtectedSocket pins the static-symlink
// variant of the root-dial race: a symlink inside an allowed directory
// may resolve anywhere, and the dial runs with the bound user's own
// permissions.
//
// The reachable half runs everywhere: a symlink inside the allowed /tmp
// dir to a socket the bound identity can open is served. The protected
// half is root-only: a root-owned 0600 canary outside the allowed
// directories, behind an in-allowlist symlink, must fail permission
// denied for the bound user. TestFwdDialCrossUser pins the same check
// at monitor level.
func TestFwdConnLocalUnixSymlinkToProtectedSocket(t *testing.T) {
	lu := fwdTestIdentity(t)
	c := newFwdTestConn(t, lu, &tailcfg.SSHAction{
		Accept:                   true,
		AllowLocalPortForwarding: true,
	})

	dir := fwdTmpDir(t)
	ctx, cancel := fwdTestCtx(nil)
	t.Cleanup(cancel)

	// Reachable half, in every run. The allowlist does not resolve
	// symlinks, so the user's own connect permission is the boundary.
	reachable := filepath.Join(dir, "reachable.sock")
	rl, err := net.Listen("unix", reachable)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { rl.Close() })
	if err := os.Chmod(reachable, 0o666); err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			sc, err := rl.Accept()
			if err != nil {
				return
			}
			go func() {
				defer sc.Close()
				sc.SetDeadline(time.Now().Add(10 * time.Second))
				io.Copy(sc, sc)
			}()
		}
	}()
	okLink := filepath.Join(dir, "ok-link.sock")
	if err := os.Symlink(reachable, okLink); err != nil {
		t.Fatal(err)
	}
	uc, err := c.mayForwardLocalUnixTo(ctx, okLink)
	if err != nil {
		t.Fatalf("dial through in-allowlist symlink to reachable socket: %v", err)
	}
	setDeadlineConn(t, uc)
	want := "symlink-dac"
	if _, err := uc.Write([]byte(want)); err != nil {
		t.Fatalf("write through symlinked forward: %v", err)
	}
	got := make([]byte, len(want))
	if _, err := io.ReadFull(uc, got); err != nil {
		t.Fatalf("read through symlinked forward: %v", err)
	}
	if string(got) != want {
		t.Errorf("echo through symlinked forward = %q, want %q", got, want)
	}
	uc.Close()

	// Protected half (root runs only): a root-owned 0600 canary outside
	// the allowed directories, behind an in-allowlist symlink. Subtest so
	// the reachable half above passes on its own and this guard's skip
	// cannot erase it.
	t.Run("protected-socket-dac", func(t *testing.T) {
		if os.Getuid() != 0 {
			t.Skipf("protected half is root-only: creating a socket protected against the bound user %q requires another uid; a root run of the suite exercises it (monitor-level DAC pin: TestFwdDialCrossUser)", lu.Username)
		}
		escape := filepath.Join("/var/run", fmt.Sprintf("tailssh-fwd-symlink-%d", os.Getpid()))
		if err := os.MkdirAll(escape, 0o755); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { os.RemoveAll(escape) })
		protected := filepath.Join(escape, "canary.sock")
		canary := listenCanary(t, protected, 0o600, "PROTECTED")
		t.Cleanup(canary.close)
		evilLink := filepath.Join(dir, "evil-link.sock")
		if err := os.Symlink(protected, evilLink); err != nil {
			t.Fatal(err)
		}

		// Every dial attempt through the symlink must fail with the kernel's
		// EACCES as the bound user. None may reach the canary.
		for i := 0; i < 5; i++ {
			uc, err := c.mayForwardLocalUnixTo(ctx, evilLink)
			if err == nil {
				uc.Close()
				t.Fatalf("root-dial regression: dial through in-allowlist symlink to root-owned 0600 socket SUCCEEDED as bound user %q", lu.Username)
			}
			if errors.Is(err, gliderssh.ErrRejected) {
				t.Errorf("dial %q: allowlist rejected a lexically-allowed symlink path (%v); the boundary must be DAC, not path strings", evilLink, err)
			}
			if !strings.Contains(err.Error(), "permission denied") {
				t.Errorf("dial %q error = %v, want permission denied (the bound user's DAC)", evilLink, err)
			}
		}

		// Control dial: the canary is served directly, without the forward,
		// proving it is alive.
		ctrl, err := net.Dial("unix", protected)
		if err != nil {
			t.Fatalf("control dial of canary: %v", err)
		}
		if err := ctrl.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, 64)
		n, err := io.ReadFull(ctrl, buf[:len("PROTECTED\n")])
		if err != nil {
			t.Fatalf("control read of canary marker: %v", err)
		}
		if string(buf[:n]) != "PROTECTED\n" {
			t.Fatalf("canary control marker = %q", buf[:n])
		}
		ctrl.Close()
		select {
		case m := <-canary.markers:
			if m != "PROTECTED" {
				t.Fatalf("unexpected canary marker %q", m)
			}
		case <-time.After(5 * time.Second):
			// Reading the socket marker does not synchronize with the
			// canary goroutine's subsequent channel send.
			t.Fatal("control marker not recorded by canary")
		}
		// The five forwarded attempts through the symlink were all refused.
		if got := len(canary.markers); got != 0 {
			t.Errorf("canary served %d extra connections after the control dial; the forwarded attempts reached the protected socket (root-dial race regression)", got)
		}
	})
}

// TestFwdConnLocalUnixDirSwapRaceNeverServesProtectedSocket is the
// direct pin of the race variant of the root-dial race: a parent
// directory is concurrently switched between the real directory and a
// symlink to an escape directory while forwarded dial attempts run. The
// dial runs as the connection's bound user, so a root-owned 0600 canary
// behind the raced path must never be served, and EACCES-classified
// attempts prove the symlink windows were hit. Root runs only.
func TestFwdConnLocalUnixDirSwapRaceNeverServesProtectedSocket(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("root-only test: the race pin needs a protected (root-owned 0600) canary facing a non-root bound user; run under sudo")
	}
	lu := fwdTestIdentity(t)
	c := newFwdTestConn(t, lu, &tailcfg.SSHAction{
		Accept:                   true,
		AllowLocalPortForwarding: true,
	})

	base := fwdTmpDir(t) // 0777, inside the allowlist
	owned := filepath.Join(base, "owned")
	aside := filepath.Join(base, "aside")
	for _, d := range []string{owned, aside} {
		if err := os.Mkdir(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	// The escape directory is outside the tested path's own tree, like
	// /var/run/docker.sock. It is traversable by every user, and its
	// canary is protected by socket mode alone.
	escape := filepath.Join("/var/run", fmt.Sprintf("tailssh-fwd-race-%d", os.Getpid()))
	if err := os.MkdirAll(escape, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(escape) })
	canaryPath := filepath.Join(escape, "canary.sock")
	dialPath := filepath.Join(owned, "canary.sock")

	// The swap loop alternates <owned> between the real empty directory
	// and a symlink to the escape directory. It holds each state about
	// 3ms so both are well represented across the dial attempts. A
	// failed step restores the real-dir state, so the loop self-heals.
	stop := make(chan struct{})
	swapsDone := make(chan struct{})
	var swaps, attempts, dials, eacces, enoent atomic.Int64
	hold := func() {
		select {
		case <-stop:
		case <-time.After(3 * time.Millisecond):
		}
	}
	go func() {
		defer close(swapsDone)
		for {
			select {
			case <-stop:
				return
			default:
			}
			os.Remove(aside)
			if err := os.Rename(owned, aside); err != nil {
				continue
			}
			if err := os.Symlink(escape, owned); err != nil {
				os.Rename(aside, owned)
				continue
			}
			swaps.Add(1)
			hold() // symlink state is in place
			os.Remove(owned)
			if err := os.Rename(aside, owned); err != nil {
				os.Mkdir(owned, 0o755)
			}
			hold()
		}
	}()
	t.Cleanup(func() {
		close(stop)
		<-swapsDone
	})

	// One forwarded dial attempt for the raced path, classified.
	probe := func() (servedMarker string, class string) {
		gctx, cancel := fwdTestCtxTimeout(8 * time.Second)
		defer cancel()
		attempts.Add(1)
		uc, err := c.mayForwardLocalUnixTo(gctx, dialPath)
		if err != nil {
			switch s := err.Error(); {
			case strings.Contains(s, "permission denied"):
				eacces.Add(1)
				return "", "eacces"
			case strings.Contains(s, "no such file"):
				enoent.Add(1)
				return "", "enoent"
			default:
				return "", "err"
			}
		}
		dials.Add(1)
		defer uc.Close()
		if err := uc.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
			t.Errorf("SetDeadline on forward conn: %v", err)
			return "", "ok"
		}
		buf := make([]byte, 128)
		n, _ := uc.Read(buf)
		return strings.TrimSpace(string(buf[:n])), "ok"
	}

	const controlMarker = "CTL-CANARY"
	const protectedMarker = "PRT-CANARY"

	// In the control phase, an accessible 0666 canary proves the harness
	// delivers markers through raced forwards when the target is
	// user-accessible.
	control := listenCanary(t, canaryPath, 0o666, controlMarker)
	served := 0
	for i := 0; i < 60; i++ {
		if marker, class := probe(); class == "ok" {
			if marker != controlMarker {
				t.Fatalf("control phase served unexpected marker %q", marker)
			}
			served++
			break
		}
	}
	if served == 0 {
		t.Fatalf("control configuration never delivered a marker; cannot attest the race harness (swaps so far: %d, attempts: %d)", swaps.Load(), attempts.Load())
	}
	t.Logf("control configuration: marker delivered (attempts so far: %d, swaps: %d)", attempts.Load(), swaps.Load())
	control.close()
	// The stdlib unix listener's Close already unlinked the socket, so
	// the removal tolerates ENOENT. The path must be gone before the
	// protected canary rebinds it.
	if err := os.Remove(canaryPath); err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}

	// In the protected phase, a root-owned 0600 canary behind the very same
	// raced path. It must never serve.
	protected := listenCanary(t, canaryPath, 0o600, protectedMarker)
	t.Cleanup(protected.close)
	const raceAttempts = 200
	for i := 0; i < raceAttempts; i++ {
		marker, class := probe()
		if class == "ok" {
			t.Fatalf("root-dial race regression: attempt %d reached the protected canary through the raced forward (marker %q)", i, marker)
		}
		if marker != "" {
			t.Fatalf("root-dial regression: attempt %d received %q from beyond the forward; the protected canary was served", i, marker)
		}
	}
	if got := len(protected.markers); got != 0 {
		t.Fatalf("REGRESSION: protected canary served %d connections through the raced forward", got)
	}
	if got := eacces.Load(); got == 0 {
		t.Fatalf("no dial attempt hit the protected canary through the swapped symlink (%d attempts, %d swaps); the race harness did not exercise the symlink state", attempts.Load(), swaps.Load())
	}
	if got := enoent.Load(); got == 0 {
		t.Logf("note: no ENOENT-classified attempt observed (%d attempts)", attempts.Load())
	}
	t.Logf("protected canary never served: %d total attempts, %d succeeded, %d EACCES (symlink state hit, DAC-refused), %d ENOENT, %d swaps",
		attempts.Load(), dials.Load(), eacces.Load(), enoent.Load(), swaps.Load())
}

// TestMonExitRegistryPIDReuse checks both exit-before-registration and
// registration-before-exit when two child generations share a PID.
func TestMonExitRegistryPIDReuse(t *testing.T) {
	var r monExitRegistry
	old := monitorProcess{PID: 42, ID: 1}
	fresh := monitorProcess{PID: 42, ID: 2}
	ch, ch2 := newMonExitStatus(), newMonExitStatus()
	r.dispatchExit(old, 7)
	r.registerSessionExit(fresh, ch2)
	r.registerSessionExit(old, ch)
	<-ch.done
	if ch.code != 7 {
		t.Fatalf("old exit = %d; want 7", ch.code)
	}
	select {
	case <-ch2.done:
		t.Fatal("old notification completed the new child")
	default:
	}
	r.dispatchExit(fresh, 9)
	<-ch2.done
	if ch2.code != 9 || ch.code != 7 {
		t.Fatalf("exit codes = %d, %d; want 7, 9", ch.code, ch2.code)
	}
}

// TestFwdAllowedSocketPathCaps pins the allowlist's two lexical caps:
// a home directory that cleans to "/" must not collapse the allowlist
// to "every absolute path", and over-long paths beyond the sun_path
// capacity reject lexically.
func TestFwdAllowedSocketPathCaps(t *testing.T) {
	for _, home := range []string{"/", "//", ""} {
		c := &conn{localUser: &userMeta{User: user.User{Username: "u", Uid: "1000", Gid: "1000", HomeDir: home}}}
		for _, bad := range []string{"/var/run/docker.sock", "/etc/passwd", "/root/x.sock", "/home"} {
			if _, err := c.fwdAllowedSocketPath(bad); err == nil {
				t.Errorf("fwdAllowedSocketPath(%q) with HomeDir %q = nil error; want rejection (a /-home must not match every path)", bad, home)
			}
		}
		// The unconditional entries survive a collapsed home.
		for _, ok := range []string{"/tmp/x.sock", "/run/user/1000/x.sock"} {
			if _, err := c.fwdAllowedSocketPath(ok); err != nil {
				t.Errorf("fwdAllowedSocketPath(%q) with HomeDir %q: %v; want allowed", ok, home, err)
			}
		}
	}
	// The sun_path length cap rejects at and above the cap and passes
	// below, still inside an allowed dir.
	c := &conn{localUser: &userMeta{User: user.User{Username: "u", Uid: "1000", Gid: "1000", HomeDir: "/home/u"}}}
	if _, err := c.fwdAllowedSocketPath("/tmp/" + strings.Repeat("a", fwdMaxSunPathLen)); err == nil {
		t.Errorf("path of length %d accepted; want the sun_path cap to reject", len("/tmp/")+fwdMaxSunPathLen)
	}
	if _, err := c.fwdAllowedSocketPath("/tmp/" + strings.Repeat("a", fwdMaxSunPathLen-6)); err != nil {
		t.Errorf("path below the sun_path cap rejected: %v", err)
	}
}

// TestConnMonitorClosedRefusesRespawn pins the closed flag on connMonitorState.
// See connMonitorState.closed. Once the conn's teardown has run, connMonitor must
// refuse to spawn for every late caller, including session launch, unix
// and TCP forwarding, and agent forwarding.
func TestConnMonitorClosedRefusesRespawn(t *testing.T) {
	lu := fwdTestIdentity(t)
	c := newFwdTestConn(t, lu, &tailcfg.SSHAction{Accept: true})
	if _, err := c.connMonitor(); err != nil {
		t.Fatalf("spawning monitor: %v", err)
	}
	c.closeConnMonitor()

	if _, err := c.connMonitor(); err == nil {
		t.Fatal("connMonitor spawned a monitor after closeConnMonitor; want refusal (nobody would close it)")
	}
	if mc := c.connMonitorIfAny(); mc != nil {
		t.Fatal("connMonitor left a monitor in monitor.mon after closeConnMonitor")
	}
	// Closing again stays a no-op.
	c.closeConnMonitor()
}

// TestRemoveAgentForwardingDirRefuses pins the session-end removal guard
// for the agent-forwarding directory. The directory was created by a
// child running as the connection's user and the removal runs with the
// daemon's credentials, so only the shape the child was supposed to
// produce — a real directory (never a symlink) named auth-agent*,
// directly inside the root-owned agentDirRoot, owned by the connection's
// user with no group or other access — is removed. A symlink entry, a
// directory outside agentDirRoot, and a loosened mode are all refused
// and left in place.
func TestRemoveAgentForwardingDirRefuses(t *testing.T) {
	if fi, err := os.Stat(agentDirRoot); err != nil || !fi.Mode().IsDir() {
		t.Skipf("agentDirRoot %s unavailable: %v", agentDirRoot, err)
	}
	if st, ok := fi2stat(t, agentDirRoot); !ok || st.Uid != 0 {
		t.Skipf("agentDirRoot %s is not root-owned; the pin needs the standard temp root", agentDirRoot)
	}
	lu := &userMeta{User: user.User{Uid: strconv.Itoa(os.Getuid()), Username: "self"}}

	// Positive control: the real shape is removed.
	dir, err := os.MkdirTemp(agentDirRoot, "auth-agent")
	if err != nil {
		t.Fatal(err)
	}
	removeAgentForwardingDir(dir, lu, t.Logf)
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatalf("agent dir %q still exists after removal (err=%v)", dir, err)
	}

	// A symlink entry is never followed: the symlink is refused and its
	// target untouched.
	d, err := os.MkdirTemp(agentDirRoot, "auth-agent")
	if err != nil {
		t.Fatal(err)
	}
	os.Remove(d)
	target := t.TempDir()
	if err := os.Symlink(target, d); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Remove(d) })
	removeAgentForwardingDir(d, lu, t.Logf)
	if _, err := os.Stat(d); err != nil {
		t.Fatalf("steered symlink entry %q was removed", d)
	}
	if _, err := os.Stat(target); err != nil {
		t.Fatalf("symlink target %q removed through the steered entry", target)
	}

	// A directory outside agentDirRoot is refused, whatever its name.
	outside := filepath.Join(t.TempDir(), "auth-agent-outside")
	if err := os.Mkdir(outside, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(outside) })
	removeAgentForwardingDir(outside, lu, t.Logf)
	if _, err := os.Stat(outside); err != nil {
		t.Fatalf("outside dir %q was removed", outside)
	}

	// A loosened mode is refused: the dir stays behind.
	loose, err := os.MkdirTemp(agentDirRoot, "auth-agent")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(loose) })
	if err := os.Chmod(loose, 0o711); err != nil {
		t.Fatal(err)
	}
	removeAgentForwardingDir(loose, lu, t.Logf)
	if _, err := os.Stat(loose); err != nil {
		t.Fatalf("loose-mode dir %q was removed", loose)
	}
}

// fi2stat returns the syscall.Stat_t of path, reporting ok=false when
// the platform does not expose one.
func fi2stat(t *testing.T, path string) (syscall.Stat_t, bool) {
	t.Helper()
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	return *st, ok
}
