// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux && !android

package tailssh

import (
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"tailscale.com/net/memnet"
	"tailscale.com/tailcfg"
	testssh "tailscale.com/tempfork/sshtest/ssh"
	"tailscale.com/tstest"
)

// TestFwdDialRelayCloseReapsChild leaves the service open and completely
// silent, even after the client is gone. The relay must exit and be reaped
// without depending on service traffic or closing the SSH connection.
func TestFwdDialRelayCloseReapsChild(t *testing.T) {
	for _, mode := range []string{"close", "close-buffered", "close-backpressured", "discard-reply"} {
		t.Run(mode, func(t *testing.T) {
			mc := startFwdTestMonitor(t, os.Getuid(), os.Getgid(), testGroups(t))
			dir := fwdWritableDir(t, os.Getuid(), os.Getgid())
			path := filepath.Join(dir, "silent.sock")
			ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
			if err != nil {
				t.Fatal(err)
			}
			defer ln.Close()
			if err := ln.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := testCtx()
			defer cancel()
			var closeClient func()
			var clientConn net.Conn
			if mode != "discard-reply" {
				client, err := mc.Dial(ctx, path)
				if err != nil {
					t.Fatal(err)
				}
				clientConn = client
				closeClient = func() { client.Close() }
			} else {
				// Model the descriptor cleanup of a reply whose caller has
				// abandoned it: no connection wrapper is ever constructed.
				_, fds, err := mc.call(ctx, rpcDialReq(0, "unix", path))
				if err != nil {
					t.Fatal(err)
				}
				closeClient = func() {
					closeFds(fds)
					fds = nil
				}
			}
			defer func() { closeClient() }()
			service, err := ln.AcceptUnix()
			if err != nil {
				t.Fatal(err)
			}
			defer service.Close()
			pid := relayPeerPID(t, service)
			if pid <= 0 || pid == os.Getpid() || pid == mc.Pid() {
				t.Fatalf("service peer PID %d is not a relay child", pid)
			}
			if err := unix.Kill(pid, 0); err != nil {
				t.Fatalf("relay %d not alive before client close: %v", pid, err)
			}
			var payload string
			stopped := false
			defer func() {
				if stopped {
					unix.Kill(pid, unix.SIGCONT)
				}
			}()
			if mode == "close-buffered" {
				// Suspend the child so the payload is still queued when the
				// client fully closes. It must drain, not be discarded by
				// cancellation racing the copy goroutines on resume.
				if err := unix.Kill(pid, unix.SIGSTOP); err != nil {
					t.Fatal(err)
				}
				stopped = true
				payload = strings.Repeat("x", 16<<10)
				if _, err := io.WriteString(clientConn, payload); err != nil {
					t.Fatal(err)
				}
			}
			var writeDone chan struct{}
			if mode == "close-backpressured" {
				// More than the socket buffers can hold. Read just one byte
				// to establish that forwarding started, then leave the service
				// open without draining the rest. The close-drain deadline
				// must bound the child's blocked write.
				writeDone = make(chan struct{})
				go func() {
					clientConn.Write(make([]byte, 4<<20))
					close(writeDone)
				}()
				if err := service.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
					t.Fatal(err)
				}
				var first [1]byte
				if _, err := io.ReadFull(service, first[:]); err != nil {
					t.Fatal(err)
				}
			}
			closeClient()
			if writeDone != nil {
				<-writeDone
			}
			if mode == "close-buffered" {
				if err := unix.Kill(pid, unix.SIGCONT); err != nil {
					t.Fatal(err)
				}
				stopped = false
				if err := service.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
					t.Fatal(err)
				}
				if b, err := io.ReadAll(service); err != nil || string(b) != payload {
					t.Fatalf("drained payload length = %d, err %v; want %d bytes", len(b), err, len(payload))
				}
			}
			waitRelayReaped(t, pid)
			if err := mc.Ping(ctx); err != nil {
				t.Fatalf("monitor after relay reaped: %v", err)
			}
		})
	}
}

func relayPeerPID(t *testing.T, service *net.UnixConn) int {
	t.Helper()
	f, err := service.File()
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	cred, err := unix.GetsockoptUcred(int(f.Fd()), unix.SOL_SOCKET, unix.SO_PEERCRED)
	if err != nil {
		t.Fatal(err)
	}
	return int(cred.Pid)
}

func waitRelayReaped(t *testing.T, pid int) {
	t.Helper()
	if err := tstest.WaitFor(10*time.Second, func() error {
		err := unix.Kill(pid, 0)
		if errors.Is(err, unix.ESRCH) {
			return nil
		}
		return fmt.Errorf("relay %d still exists after client close: %v", pid, err)
	}); err != nil {
		t.Fatal(err)
	}
}

// TestFwdFullStackUnixChannelClose checks the whole closure chain: SSH channel
// EOF preserves the relay for a response, but CHANNEL_CLOSE must end it even
// when the service stays silent and the SSH transport remains connected.
func TestFwdFullStackUnixChannelClose(t *testing.T) {
	for _, mode := range []string{"half-close-then-close", "buffered-close"} {
		t.Run(mode, func(t *testing.T) {
			testFwdFullStackUnixChannelClose(t, mode)
		})
	}
}

func testFwdFullStackUnixChannelClose(t *testing.T, mode string) {
	lu := fwdTestIdentity(t)
	exe := makeExecutableReachable(t)
	t.Setenv("TS_TEST_SSH_FWD_PREFIX", strings.Join(testFwdPrefix, " "))
	tstest.Replace(t, &monitorSpawnPrefix, testMonitorPrefix)
	path := filepath.Join(fwdTmpDir(t), "silent.sock")
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	if err := os.Chmod(path, 0o666); err != nil {
		t.Fatal(err)
	}
	if err := ln.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatal(err)
	}
	s := &server{
		logf: tstest.WhileTestRunningLogger(t), tailscaledPath: exe,
		lb: &localState{
			sshEnabled: true, varRoot: t.TempDir(),
			matchingRule: &tailcfg.SSHRule{
				SSHUsers:   map[string]string{"alice": lu.Username},
				Action:     &tailcfg.SSHAction{Accept: true, AllowLocalPortForwarding: true},
				Principals: []*tailcfg.SSHPrincipal{{Any: true}},
			},
		},
	}
	defer s.Shutdown()
	sc, dc := memnet.NewTCPConn(netip.MustParseAddrPort("100.100.100.101:2231"), netip.MustParseAddrPort("100.100.100.102:22"), 1024)
	defer sc.Close()
	defer dc.Close()
	if err := sc.SetDeadline(time.Now().Add(20 * time.Second)); err != nil {
		t.Fatal(err)
	}
	handleDone := make(chan error, 1)
	go func() { handleDone <- s.HandleSSHConn(dc) }()
	cl, chans, reqs, err := testssh.NewClientConn(sc, sc.RemoteAddr().String(), &testssh.ClientConfig{
		User: "alice", HostKeyCallback: testssh.InsecureIgnoreHostKey(),
	})
	if err != nil {
		t.Fatal(err)
	}
	client := testssh.NewClient(cl, chans, reqs)
	defer client.Close()
	payload := struct {
		SocketPath string
		Reserved1  string
		Reserved2  uint32
	}{SocketPath: path}
	ch, requests, err := client.OpenChannel("direct-streamlocal@openssh.com", testssh.Marshal(&payload))
	if err != nil {
		t.Fatal(err)
	}
	defer ch.Close()
	go testssh.DiscardRequests(requests)
	service, err := ln.AcceptUnix()
	if err != nil {
		t.Fatal(err)
	}
	defer service.Close()
	if err := service.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatal(err)
	}
	pid := relayPeerPID(t, service)
	if mode == "buffered-close" {
		payload := strings.Repeat("payload", 8<<10)
		if _, err := io.WriteString(ch, payload); err != nil {
			t.Fatal(err)
		}
		if err := ch.Close(); err != nil {
			t.Fatal(err)
		}
		if b, err := io.ReadAll(service); err != nil || string(b) != payload {
			t.Fatalf("drained payload length = %d, err %v; want %d bytes", len(b), err, len(payload))
		}
	} else {
		if _, err := io.WriteString(ch, "request"); err != nil {
			t.Fatal(err)
		}
		if err := ch.CloseWrite(); err != nil {
			t.Fatal(err)
		}
		if b, err := io.ReadAll(service); err != nil || string(b) != "request" {
			t.Fatalf("service read = %q, %v", b, err)
		}
		if _, err := io.WriteString(service, "response"); err != nil {
			t.Fatal(err)
		}
		response := make([]byte, len("response"))
		if _, err := io.ReadFull(ch, response); err != nil || string(response) != "response" {
			t.Fatalf("response after half-close = %q, %v", response, err)
		}
		// Leave the service write side open and silent. No service action can
		// unblock the relay from here onward; only the SSH channel close can.
		if err := ch.Close(); err != nil {
			t.Fatal(err)
		}
	}
	waitRelayReaped(t, pid)
	if _, _, err := client.SendRequest("keepalive@openssh.com", true, nil); err != nil {
		t.Fatalf("SSH transport after relay reaped: %v", err)
	}
	client.Close()
	select {
	case err := <-handleDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("SSH handler did not finish")
	}
}
