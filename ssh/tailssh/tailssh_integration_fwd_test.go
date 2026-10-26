// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build integrationtest

package tailssh

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"tailscale.com/envknob"
	"tailscale.com/tailcfg"
	"tailscale.com/tstest"
)

// This file tests TCP, Unix socket, and agent forwarding end to end
// through the in-process server and its per-connection ssh-monitor.

// fwdSessionUser is the local user every forwarding test logs in as.
const fwdSessionUser = "testuser"

// fwdTestTimeout bounds each blocking step of the forwarding tests.
const fwdTestTimeout = 15 * time.Second

// fwdTestClient starts a server configured by opts and returns a client
// connected to it as [fwdSessionUser]. The client is closed after a minute
// so that a stuck forwarding op fails the test instead of hanging it.
func fwdTestClient(t *testing.T, opts testServerOpts) *ssh.Client {
	t.Helper()
	opts.username = fwdSessionUser
	addr := testServerWithOpts(t, opts)
	cl, err := ssh.Dial("tcp", addr, &ssh.ClientConfig{
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         fwdTestTimeout,
	})
	if err != nil {
		t.Fatal(err)
	}
	watchdog := time.AfterFunc(time.Minute, func() { cl.Close() })
	t.Cleanup(func() {
		watchdog.Stop()
		cl.Close()
	})
	return cl
}

// fwdSessionUserIDs returns the uid and gid of [fwdSessionUser].
func fwdSessionUserIDs(t *testing.T) (uid, gid int) {
	t.Helper()
	u, err := user.Lookup(fwdSessionUser)
	if err != nil {
		t.Fatal(err)
	}
	uid, err = strconv.Atoi(u.Uid)
	if err != nil {
		t.Fatal(err)
	}
	gid, err = strconv.Atoi(u.Gid)
	if err != nil {
		t.Fatal(err)
	}
	return uid, gid
}

// fwdSocketDir returns a new directory under /tmp, one of the allowed
// forwarding socket directories, that [fwdSessionUser] can create and
// remove sockets in.
func fwdSocketDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "tailssh-fwd-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	if err := os.Chmod(dir, 0o777); err != nil {
		t.Fatal(err)
	}
	return dir
}

// serveEcho accepts connections on ln until it is closed and echoes
// back everything each connection sends.
func serveEcho(ln net.Listener) {
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		go func() {
			defer c.Close()
			io.Copy(c, c)
		}()
	}
}

// startTCPEcho starts a loopback TCP echo server in the test process,
// standing in for a service on the SSH server's host.
func startTCPEcho(t *testing.T) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go serveEcho(ln)
	return ln
}

// checkEcho sends n random bytes on c, which must lead to an echo
// server, while concurrently reading them back. It closes c when done.
func checkEcho(t *testing.T, c net.Conn, n int) {
	t.Helper()
	defer c.Close()
	want := make([]byte, n)
	rand.Read(want)
	writeErr := make(chan error, 1)
	go func() {
		_, err := c.Write(want)
		writeErr <- err
	}()
	got := make([]byte, n)
	readErr := make(chan error, 1)
	go func() {
		_, err := io.ReadFull(c, got)
		readErr <- err
	}()
	for range 2 {
		select {
		case err := <-writeErr:
			if err != nil {
				t.Fatalf("write: %v", err)
			}
		case err := <-readErr:
			if err != nil {
				t.Fatalf("read: %v", err)
			}
		case <-time.After(fwdTestTimeout):
			t.Fatal("timed out exchanging data through the forward")
		}
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("echoed data differs from sent data (%d bytes)", n)
	}
}

// readAllTimeout reads c to EOF, bounded by [fwdTestTimeout]. SSH
// channel conns don't support deadlines, so the read runs in a
// goroutine.
func readAllTimeout(t *testing.T, c io.Reader) string {
	t.Helper()
	type result struct {
		b   []byte
		err error
	}
	done := make(chan result, 1)
	go func() {
		b, err := io.ReadAll(c)
		done <- result{b, err}
	}()
	select {
	case r := <-done:
		if r.err != nil {
			t.Fatalf("read: %v", r.err)
		}
		return string(r.b)
	case <-time.After(fwdTestTimeout):
		t.Fatal("timed out reading to EOF")
		return ""
	}
}

// waitConnRefused waits for network address addr to stop accepting
// connections. The listener's last descriptor copies are released
// asynchronously by the monitor and its one-shot child, so this polls.
func waitConnRefused(t *testing.T, network, addr string) {
	t.Helper()
	err := tstest.WaitFor(fwdTestTimeout, func() error {
		c, err := net.DialTimeout(network, addr, time.Second)
		if err != nil {
			return nil
		}
		c.Close()
		return fmt.Errorf("%s %s still accepts connections", network, addr)
	})
	if err != nil {
		t.Fatal(err)
	}
}

// TestIntegrationTCPLocalForwarding tests direct-tcpip (ssh -L): the
// client opens a channel to a TCP service on the server's host, and the
// server dials it and proxies data in both directions.
func TestIntegrationTCPLocalForwarding(t *testing.T) {
	echo := startTCPEcho(t)
	cl := fwdTestClient(t, testServerOpts{allowLocalPortForwarding: true})

	for _, n := range []int{1, 256 << 10} {
		c, err := cl.Dial("tcp", echo.Addr().String())
		if err != nil {
			t.Fatalf("direct-tcpip to %v: %v", echo.Addr(), err)
		}
		checkEcho(t, c, n)
	}
}

// TestIntegrationTCPRemoteForwarding tests tcpip-forward (ssh -R) with
// an allocated port, connections from the server's host back to the
// client, cancel-tcpip-forward, and the loopback-only bind policy.
func TestIntegrationTCPRemoteForwarding(t *testing.T) {
	cl := fwdTestClient(t, testServerOpts{allowRemotePortForwarding: true})

	// Port 0 asks the server to allocate a port and report it back.
	ln, err := cl.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("tcpip-forward: %v", err)
	}
	defer ln.Close()
	addr := ln.Addr().String()
	if port := ln.Addr().(*net.TCPAddr).Port; port == 0 {
		t.Fatalf("tcpip-forward returned port 0, want the allocated port")
	}
	go serveEcho(ln)

	// A local process on the server's host connects to the forwarded
	// port and reaches the client's echo service.
	for _, n := range []int{1, 256 << 10} {
		c, err := net.DialTimeout("tcp", addr, fwdTestTimeout)
		if err != nil {
			t.Fatalf("dialing forwarded port %s: %v", addr, err)
		}
		checkEcho(t, c, n)
	}

	// Closing the client's listener sends cancel-tcpip-forward, after
	// which the server must stop listening on the port.
	if err := ln.Close(); err != nil {
		t.Fatalf("cancel-tcpip-forward: %v", err)
	}
	waitConnRefused(t, "tcp", addr)

	// Without TS_SSH_FORWARD_GATEWAY_PORTS, only loopback binds are
	// permitted.
	if ln, err := cl.Listen("tcp", "0.0.0.0:0"); err == nil {
		ln.Close()
		t.Errorf("tcpip-forward on 0.0.0.0 succeeded; want refusal of non-loopback bind")
	}
}

// TestIntegrationTCPForwardingDenied checks that the policy's
// AllowLocalPortForwarding and AllowRemotePortForwarding bits each
// gate only their own direction of TCP forwarding.
func TestIntegrationTCPForwardingDenied(t *testing.T) {
	echo := startTCPEcho(t)
	tests := []struct {
		name          string
		local, remote bool
	}{
		{"none", false, false},
		{"local_only", true, false},
		{"remote_only", false, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cl := fwdTestClient(t, testServerOpts{
				allowLocalPortForwarding:  tt.local,
				allowRemotePortForwarding: tt.remote,
			})

			c, err := cl.Dial("tcp", echo.Addr().String())
			if tt.local {
				if err != nil {
					t.Fatalf("permitted direct-tcpip failed: %v", err)
				}
				checkEcho(t, c, 1)
			} else {
				if err == nil {
					c.Close()
					t.Fatal("direct-tcpip succeeded; want rejection")
				}
				var oce *ssh.OpenChannelError
				if !errors.As(err, &oce) || oce.Reason != ssh.Prohibited {
					t.Errorf("direct-tcpip error = %v; want administratively prohibited", err)
				}
			}

			ln, err := cl.Listen("tcp", "127.0.0.1:0")
			if tt.remote {
				if err != nil {
					t.Fatalf("permitted tcpip-forward failed: %v", err)
				}
				ln.Close()
			} else if err == nil {
				ln.Close()
				t.Fatal("tcpip-forward succeeded; want rejection")
			}
		})
	}
}

// halfCloseRequest is what the requesting side of a half-close exchange
// sends before closing its write side.
const halfCloseRequest = "request-then-close-write"

// halfCloseResponse is what the responding side sends only after it has
// read the request to EOF.
const halfCloseResponse = "response-after-eof"

// respondAfterEOF is the responding side of a half-close exchange on c:
// it reads c to EOF, reports what it read to got, then writes
// [halfCloseResponse] and closes c. The response can only reach the
// requester if the forward propagated the requester's EOF without
// tearing down the other direction.
func respondAfterEOF(c net.Conn, got chan<- string) {
	defer c.Close()
	b, _ := io.ReadAll(c)
	got <- string(b)
	io.WriteString(c, halfCloseResponse)
}

// requestWithHalfClose is the requesting side of a half-close exchange
// on c: it writes [halfCloseRequest], closes its write side, and checks
// that [halfCloseResponse] arrives afterward. It also checks the
// request the responder reported to got.
func requestWithHalfClose(t *testing.T, c net.Conn, got <-chan string) {
	t.Helper()
	defer c.Close()
	if _, err := io.WriteString(c, halfCloseRequest); err != nil {
		t.Fatalf("write: %v", err)
	}
	cw, ok := c.(interface{ CloseWrite() error })
	if !ok {
		t.Fatalf("%T does not implement CloseWrite", c)
	}
	if err := cw.CloseWrite(); err != nil {
		t.Fatalf("CloseWrite: %v", err)
	}
	if resp := readAllTimeout(t, c); resp != halfCloseResponse {
		t.Errorf("response = %q; want %q", resp, halfCloseResponse)
	}
	select {
	case req := <-got:
		if req != halfCloseRequest {
			t.Errorf("responder read %q; want %q", req, halfCloseRequest)
		}
	case <-time.After(fwdTestTimeout):
		t.Fatal("responder never reported its request")
	}
}

// TestIntegrationTCPForwardingHalfClose checks that an EOF from one end
// of a TCP forward reaches the other end while the reverse direction
// keeps flowing, for both ssh -L and ssh -R.
func TestIntegrationTCPForwardingHalfClose(t *testing.T) {
	t.Run("local", func(t *testing.T) {
		svc, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer svc.Close()
		got := make(chan string, 1)
		go func() {
			c, err := svc.Accept()
			if err == nil {
				respondAfterEOF(c, got)
			}
		}()

		cl := fwdTestClient(t, testServerOpts{allowLocalPortForwarding: true})
		c, err := cl.Dial("tcp", svc.Addr().String())
		if err != nil {
			t.Fatalf("direct-tcpip: %v", err)
		}
		requestWithHalfClose(t, c, got)
	})

	t.Run("remote", func(t *testing.T) {
		cl := fwdTestClient(t, testServerOpts{allowRemotePortForwarding: true})
		ln, err := cl.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("tcpip-forward: %v", err)
		}
		defer ln.Close()
		got := make(chan string, 1)
		go func() {
			c, err := ln.Accept()
			if err == nil {
				respondAfterEOF(c, got)
			}
		}()

		c, err := net.DialTimeout("tcp", ln.Addr().String(), fwdTestTimeout)
		if err != nil {
			t.Fatalf("dialing forwarded port: %v", err)
		}
		requestWithHalfClose(t, c, got)
	})
}

// TestIntegrationUnixReverseForwardingCancel tests
// cancel-streamlocal-forward@openssh.com: after the client closes its
// listener, the server's socket stops accepting connections, and the
// same path can be forwarded again.
func TestIntegrationUnixReverseForwardingCancel(t *testing.T) {
	cl := fwdTestClient(t, testServerOpts{allowRemotePortForwarding: true})
	sockPath := filepath.Join(fwdSocketDir(t), "cancel.sock")

	for i := range 2 {
		ln, err := cl.ListenUnix(sockPath)
		if err != nil {
			t.Fatalf("streamlocal-forward #%d: %v", i, err)
		}
		go serveEcho(ln)
		c, err := net.DialTimeout("unix", sockPath, fwdTestTimeout)
		if err != nil {
			t.Fatalf("dialing forwarded socket #%d: %v", i, err)
		}
		checkEcho(t, c, 1<<10)

		// Closing the client's listener sends
		// cancel-streamlocal-forward@openssh.com. The server leaves the
		// socket file in place (see [conn.fwdListenUnix]), but nothing
		// listens on it. The next iteration's bind reclaims it.
		if err := ln.Close(); err != nil {
			t.Fatalf("cancel-streamlocal-forward #%d: %v", i, err)
		}
		waitConnRefused(t, "unix", sockPath)
	}
}

// TestIntegrationUnixReverseForwardingStaleSocket tests the server's
// unlink-if-owned BindUnlink policy for streamlocal-forward: an existing
// socket file owned by the session user is replaced, while a socket
// owned by someone else, or a non-socket file, is left untouched and
// the forward fails.
func TestIntegrationUnixReverseForwardingStaleSocket(t *testing.T) {
	uid, gid := fwdSessionUserIDs(t)

	// makeStaleSocket leaves a socket file with no listener at path.
	makeStaleSocket := func(t *testing.T, path string) {
		t.Helper()
		ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
		if err != nil {
			t.Fatal(err)
		}
		ln.SetUnlinkOnClose(false)
		ln.Close()
	}
	// chownToSessionUser makes path owned by [fwdSessionUser], which it
	// already is when the test runs as that user.
	chownToSessionUser := func(t *testing.T, path string) {
		t.Helper()
		if os.Getuid() == uid {
			return
		}
		if err := os.Lchown(path, uid, gid); err != nil {
			t.Fatal(err)
		}
	}

	tests := []struct {
		name     string
		setup    func(t *testing.T, path string)
		wantBind bool
		wantType fs.FileMode // file type that must remain after a refused bind
	}{
		{
			name: "own_stale_socket",
			setup: func(t *testing.T, path string) {
				makeStaleSocket(t, path)
				chownToSessionUser(t, path)
			},
			wantBind: true,
		},
		{
			name: "foreign_stale_socket",
			setup: func(t *testing.T, path string) {
				if os.Getuid() != 0 {
					t.Skip("creating a socket owned by another user requires root")
				}
				makeStaleSocket(t, path) // owned by root
			},
			wantType: fs.ModeSocket,
		},
		{
			name: "regular_file",
			setup: func(t *testing.T, path string) {
				if err := os.WriteFile(path, []byte("keep"), 0o600); err != nil {
					t.Fatal(err)
				}
				chownToSessionUser(t, path)
			},
			wantType: 0,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sockPath := filepath.Join(fwdSocketDir(t), "stale.sock")
			tt.setup(t, sockPath)
			before, err := os.Lstat(sockPath)
			if err != nil {
				t.Fatal(err)
			}

			cl := fwdTestClient(t, testServerOpts{allowRemotePortForwarding: true})
			ln, err := cl.ListenUnix(sockPath)
			if !tt.wantBind {
				if err == nil {
					ln.Close()
					t.Fatal("streamlocal-forward over an existing file succeeded; want refusal")
				}
				after, err := os.Lstat(sockPath)
				if err != nil {
					t.Fatalf("existing file removed by refused forward: %v", err)
				}
				if after.Mode().Type() != tt.wantType || !os.SameFile(before, after) {
					t.Errorf("existing file replaced by refused forward: mode %v -> %v", before.Mode(), after.Mode())
				}
				return
			}
			if err != nil {
				t.Fatalf("streamlocal-forward over own stale socket: %v", err)
			}
			defer ln.Close()
			// A connection reaching the client proves the stale socket was
			// replaced, since nothing listens on the old one. Inode numbers
			// are reused too quickly to compare.
			go serveEcho(ln)
			c, err := net.DialTimeout("unix", sockPath, fwdTestTimeout)
			if err != nil {
				t.Fatalf("dialing forwarded socket: %v", err)
			}
			checkEcho(t, c, 1<<10)
		})
	}
}

// startAgentSession forwards keyring over cl, starts a session that
// requests agent forwarding and stays open until the returned end func
// is called, and returns the session's SSH_AUTH_SOCK ("" if unset).
func startAgentSession(t *testing.T, cl *ssh.Client, keyring agent.Agent) (sock string, end func()) {
	t.Helper()
	if err := agent.ForwardToAgent(cl, keyring); err != nil {
		t.Fatal(err)
	}
	s, err := cl.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	// The server accepts the request even when it won't forward the
	// agent; the policy is enforced by not creating the socket.
	if err := agent.RequestAgentForwarding(s); err != nil {
		t.Fatalf("requesting agent forwarding: %v", err)
	}
	stdin, err := s.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := s.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Start(`echo "SSH_AUTH_SOCK=${SSH_AUTH_SOCK:-}"; read x`); err != nil {
		t.Fatal(err)
	}
	line := make(chan string, 1)
	go func() {
		sc := bufio.NewScanner(stdout)
		for sc.Scan() {
			if v, ok := strings.CutPrefix(sc.Text(), "SSH_AUTH_SOCK="); ok {
				line <- v
				break
			}
		}
		io.Copy(io.Discard, stdout)
	}()
	select {
	case sock = <-line:
	case <-time.After(fwdTestTimeout):
		t.Fatal("timed out waiting for the session's SSH_AUTH_SOCK")
	}
	return sock, func() {
		stdin.Close()
		s.Wait()
	}
}

// newTestKeyring returns an agent keyring holding one new key.
func newTestKeyring(t *testing.T) agent.Agent {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keyring := agent.NewKeyring()
	if err := keyring.Add(agent.AddedKey{PrivateKey: priv}); err != nil {
		t.Fatal(err)
	}
	return keyring
}

// TestIntegrationAgentForwardingSocket checks the agent socket the
// server creates for ssh -A: it is a live connection to the client's
// agent, owned by the session user with mode 0600 inside a 0700
// user-owned directory, and the directory is removed when the session
// ends. With AllowAgentForwarding off, the session gets no socket.
func TestIntegrationAgentForwardingSocket(t *testing.T) {
	t.Run("allowed", func(t *testing.T) {
		uid, _ := fwdSessionUserIDs(t)
		cl := fwdTestClient(t, testServerOpts{})
		sock, end := startAgentSession(t, cl, newTestKeyring(t))
		if sock == "" {
			t.Fatal("SSH_AUTH_SOCK unset in session with agent forwarding allowed")
		}
		dir := filepath.Dir(sock)
		for _, f := range []struct {
			path     string
			wantType fs.FileMode
			wantPerm fs.FileMode
		}{
			{sock, fs.ModeSocket, 0o600},
			{dir, fs.ModeDir, 0o700},
		} {
			fi, err := os.Lstat(f.path)
			if err != nil {
				t.Fatal(err)
			}
			if got := fi.Mode().Type(); got != f.wantType {
				t.Errorf("%s: type %v; want %v", f.path, got, f.wantType)
			}
			if got := fi.Mode().Perm(); got != f.wantPerm {
				t.Errorf("%s: mode %04o; want %04o", f.path, got, f.wantPerm)
			}
			if got := fi.Sys().(*syscall.Stat_t).Uid; int(got) != uid {
				t.Errorf("%s: owned by uid %d; want %s's uid %d", f.path, got, fwdSessionUser, uid)
			}
		}

		c, err := net.DialTimeout("unix", sock, fwdTestTimeout)
		if err != nil {
			t.Fatalf("dialing agent socket: %v", err)
		}
		keys, err := agent.NewClient(c).List()
		c.Close()
		if err != nil {
			t.Fatalf("listing keys through forwarded agent: %v", err)
		}
		if len(keys) != 1 {
			t.Errorf("forwarded agent has %d keys; want 1", len(keys))
		}

		end()
		err = tstest.WaitFor(fwdTestTimeout, func() error {
			if _, err := os.Lstat(dir); !os.IsNotExist(err) {
				return fmt.Errorf("agent dir %s still present after session end (err=%v)", dir, err)
			}
			return nil
		})
		if err != nil {
			t.Error(err)
		}
	})

	t.Run("denied", func(t *testing.T) {
		cl := fwdTestClient(t, testServerOpts{
			modifyRule: func(r *tailcfg.SSHRule) { r.Action.AllowAgentForwarding = false },
		})
		sock, end := startAgentSession(t, cl, newTestKeyring(t))
		defer end()
		if sock != "" {
			t.Errorf("SSH_AUTH_SOCK = %q with AllowAgentForwarding=false; want unset", sock)
		}
	})
}

// TestIntegrationForwardingDisabledByEnvknob checks that
// TS_SSH_DISABLE_FORWARDING refuses TCP, Unix socket, and agent
// forwarding even when the policy allows all of them.
func TestIntegrationForwardingDisabledByEnvknob(t *testing.T) {
	envknob.SetenvForTest(t, "TS_SSH_DISABLE_FORWARDING", "true")

	echo := startTCPEcho(t)
	dir := fwdSocketDir(t)
	unixSvcPath := filepath.Join(dir, "svc.sock")
	unixSvc, err := net.Listen("unix", unixSvcPath)
	if err != nil {
		t.Fatal(err)
	}
	defer unixSvc.Close()
	if err := os.Chmod(unixSvcPath, 0o666); err != nil {
		t.Fatal(err)
	}
	go serveEcho(unixSvc)

	cl := fwdTestClient(t, testServerOpts{
		allowLocalPortForwarding:  true,
		allowRemotePortForwarding: true,
	})

	if c, err := cl.Dial("tcp", echo.Addr().String()); err == nil {
		c.Close()
		t.Error("TCP local forward succeeded")
	}
	if ln, err := cl.Listen("tcp", "127.0.0.1:0"); err == nil {
		ln.Close()
		t.Error("TCP remote forward succeeded")
	}
	if c, err := cl.Dial("unix", unixSvcPath); err == nil {
		c.Close()
		t.Error("Unix local forward succeeded")
	}
	if ln, err := cl.ListenUnix(filepath.Join(dir, "reverse.sock")); err == nil {
		ln.Close()
		t.Error("Unix remote forward succeeded")
	}
	sock, end := startAgentSession(t, cl, newTestKeyring(t))
	defer end()
	if sock != "" {
		t.Errorf("SSH_AUTH_SOCK = %q; want unset", sock)
	}
}

// openSSHProc is a system ssh client started by [startOpenSSH].
type openSSHProc struct {
	lines  chan string   // stderr lines; sends are dropped when full
	done   chan struct{} // closed when the client has exited
	err    error         // exit error, set before done is closed
	stderr lockedBuffer  // all stderr output
}

// startOpenSSH starts the system ssh client at sshPath with -N against
// the server at addr, logging in as [fwdSessionUser] with "none" auth,
// with the given extra arguments. The client is killed at test cleanup.
func startOpenSSH(t *testing.T, sshPath, addr string, args ...string) *openSSHProc {
	t.Helper()
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatal(err)
	}
	argv := []string{
		"-F", "/dev/null",
		"-N", "-T",
		"-o", "BatchMode=yes",
		"-o", "ConnectTimeout=15",
		"-o", "ExitOnForwardFailure=yes",
		"-o", "GSSAPIAuthentication=no",
		"-o", "GlobalKnownHostsFile=/dev/null",
		"-o", "HostbasedAuthentication=no",
		"-o", "IdentityAgent=none",
		"-o", "KbdInteractiveAuthentication=no",
		"-o", "NumberOfPasswordPrompts=0",
		"-o", "PasswordAuthentication=no",
		"-o", "PreferredAuthentications=none",
		"-o", "PubkeyAuthentication=no",
		"-o", "StrictHostKeyChecking=no",
		"-o", "UserKnownHostsFile=/dev/null",
		"-p", port,
	}
	argv = append(argv, args...)
	argv = append(argv, fwdSessionUser+"@"+host)

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	cmd := exec.CommandContext(ctx, sshPath, argv...)
	stderr, err := cmd.StderrPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	p := &openSSHProc{
		lines: make(chan string, 64),
		done:  make(chan struct{}),
	}
	go func() {
		sc := bufio.NewScanner(stderr)
		for sc.Scan() {
			fmt.Fprintln(&p.stderr, sc.Text())
			select {
			case p.lines <- sc.Text():
			default:
			}
		}
		p.err = cmd.Wait()
		close(p.done)
	}()
	t.Cleanup(func() {
		cancel()
		<-p.done
		if t.Failed() {
			t.Logf("ssh %q stderr:\n%s", argv, p.stderr.String())
		}
	})
	return p
}

// allocatedPortRx matches OpenSSH's report of the port a "-R 0:..."
// forward was given.
var allocatedPortRx = regexp.MustCompile(`Allocated port (\d+) for remote forward`)

// TestIntegrationOpenSSHForwarding runs the system OpenSSH client with
// -L and -R against the server, with ExitOnForwardFailure so that a
// refused forward ends the client.
func TestIntegrationOpenSSHForwarding(t *testing.T) {
	sshPath, err := exec.LookPath("ssh")
	if err != nil {
		t.Skipf("skipping without OpenSSH client: %v", err)
	}
	echo := startTCPEcho(t)
	echoPort := strconv.Itoa(echo.Addr().(*net.TCPAddr).Port)
	allowAll := testServerOpts{
		username:                  fwdSessionUser,
		allowLocalPortForwarding:  true,
		allowRemotePortForwarding: true,
	}

	t.Run("local", func(t *testing.T) {
		// The client listens on a Unix socket so there is no local port
		// to pick, and forwards it over direct-tcpip to the echo service.
		localSock := filepath.Join(t.TempDir(), "L.sock")
		addr := testServerWithOpts(t, allowAll)
		p := startOpenSSH(t, sshPath, addr, "-L", localSock+":127.0.0.1:"+echoPort)

		var c net.Conn
		err := tstest.WaitFor(fwdTestTimeout, func() error {
			select {
			case <-p.done:
				return fmt.Errorf("ssh exited: %v", p.err)
			default:
			}
			var err error
			c, err = net.Dial("unix", localSock)
			return err
		})
		if err != nil {
			t.Fatalf("ssh -L listener never became ready: %v", err)
		}
		checkEcho(t, c, 64<<10)
	})

	t.Run("remote", func(t *testing.T) {
		addr := testServerWithOpts(t, allowAll)
		p := startOpenSSH(t, sshPath, addr, "-R", "127.0.0.1:0:127.0.0.1:"+echoPort)

		var port string
		timeout := time.After(fwdTestTimeout)
		for port == "" {
			select {
			case line := <-p.lines:
				if m := allocatedPortRx.FindStringSubmatch(line); m != nil {
					port = m[1]
				}
			case <-p.done:
				t.Fatalf("ssh exited before reporting its allocated port: %v", p.err)
			case <-timeout:
				t.Fatal("timed out waiting for ssh -R to report its allocated port")
			}
		}
		c, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", port), fwdTestTimeout)
		if err != nil {
			t.Fatalf("dialing forwarded port: %v", err)
		}
		checkEcho(t, c, 64<<10)
	})

	t.Run("remote_denied", func(t *testing.T) {
		addr := testServerWithOpts(t, testServerOpts{username: fwdSessionUser})
		p := startOpenSSH(t, sshPath, addr, "-R", "127.0.0.1:0:127.0.0.1:"+echoPort)
		select {
		case <-p.done:
		case <-time.After(fwdTestTimeout):
			t.Fatal("ssh with a refused -R and ExitOnForwardFailure=yes did not exit")
		}
		var ee *exec.ExitError
		if !errors.As(p.err, &ee) || ee.ExitCode() != 255 {
			t.Errorf("ssh exit = %v; want exit status 255", p.err)
		}
		if out := p.stderr.String(); !strings.Contains(out, "remote port forwarding failed") {
			t.Errorf("ssh stderr lacks the forwarding failure:\n%s", out)
		}
	})
}
