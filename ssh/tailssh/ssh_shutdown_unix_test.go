// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build (linux && !android) || (darwin && !ios)

package tailssh

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/creack/pty"
	gliderssh "github.com/tailscale/gliderssh"
	"golang.org/x/crypto/ssh"
	"golang.org/x/sys/unix"
	"tailscale.com/tstest"
)

// TestPTYMaster checks descriptor flags, deadline support, and interruption of
// a pending read separately. Each subtest keeps the PTY child open without writing
// to it, so reads cannot complete from output or terminal hangup.
func TestPTYMaster(t *testing.T) {
	open := func(t *testing.T) (master, ptyChild *os.File, ptyChildNonblocking bool) {
		t.Helper()
		original, ptyChild, err := pty.Open()
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { ptyChild.Close() })
		defer original.Close()
		raw, err := ptyChild.SyscallConn()
		if err != nil {
			t.Fatal(err)
		}
		if err := raw.Control(func(fd uintptr) {
			flags, err := unix.FcntlInt(fd, unix.F_GETFL, 0)
			if err != nil {
				t.Fatal(err)
			}
			ptyChildNonblocking = flags&unix.O_NONBLOCK != 0
		}); err != nil {
			t.Fatal(err)
		}
		master, err = dupPTYMaster(original)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { master.Close() })
		return master, ptyChild, ptyChildNonblocking
	}
	t.Run("flags", func(t *testing.T) {
		master, ptyChild, ptyChildNonblocking := open(t)
		for _, tc := range []struct {
			f           *os.File
			nonblocking bool
		}{{master, true}, {ptyChild, ptyChildNonblocking}} {
			raw, err := tc.f.SyscallConn()
			if err != nil {
				t.Fatal(err)
			}
			if err := raw.Control(func(fd uintptr) {
				flags, err := unix.FcntlInt(fd, unix.F_GETFL, 0)
				if err != nil || (flags&unix.O_NONBLOCK != 0) != tc.nonblocking {
					t.Errorf("%s: status flags = %#x, %v; want nonblocking=%v", tc.f.Name(), flags, err, tc.nonblocking)
				}
				flags, err = unix.FcntlInt(fd, unix.F_GETFD, 0)
				if err != nil || flags&unix.FD_CLOEXEC == 0 {
					t.Errorf("%s: descriptor flags = %#x, %v; want FD_CLOEXEC", tc.f.Name(), flags, err)
				}
			}); err != nil {
				t.Fatal(err)
			}
		}
	})
	t.Run("read-deadline", func(t *testing.T) {
		master, _, _ := open(t)
		if err := master.SetReadDeadline(time.Now().Add(20 * time.Millisecond)); err != nil {
			t.Fatal(err)
		}
		var buf [1]byte
		if _, err := master.Read(buf[:]); !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatalf("Read error = %v; want deadline exceeded", err)
		}
	})
	t.Run("close-interrupts-read", func(t *testing.T) {
		master, _, _ := open(t)
		raw, err := master.SyscallConn()
		if err != nil {
			t.Fatal(err)
		}
		waiting := make(chan struct{})
		done := make(chan error, 1)
		go func() {
			var buf [1]byte
			notified := false
			done <- raw.Read(func(fd uintptr) bool {
				var err error
				for {
					_, err = unix.Read(int(fd), buf[:])
					if !errors.Is(err, unix.EINTR) {
						break
					}
				}
				if !errors.Is(err, unix.EAGAIN) {
					return true
				}
				// The read operation holds the descriptor and has reached EAGAIN.
				if !notified {
					close(waiting)
					notified = true
				}
				return false
			})
		}()
		select {
		case <-waiting:
		case err := <-done:
			t.Fatalf("Read completed without blocking: %v", err)
		case <-time.After(5 * time.Second):
			t.Fatal("Read did not reach EAGAIN")
		}
		master.Close()
		select {
		case err := <-done:
			if err == nil {
				t.Error("pending Read succeeded after Close")
			}
		case <-time.After(5 * time.Second):
			t.Fatal("Close did not interrupt the pending read")
		}
	})
}

// TestSessionMonitorCancellation cancels a live SSH session after its shell
// installs a HUP trap. The trap writes a file outside the terminal, which must
// appear before SIGKILL escalation. The client must receive the cancellation
// message before channel close, and a second session must use the same live
// connection and monitor. Both PTY and pipe-backed sessions are exercised.
func TestSessionMonitorCancellation(t *testing.T) {
	for _, isPTY := range []bool{false, true} {
		t.Run(fmt.Sprintf("pty=%v", isPTY), func(t *testing.T) {
			setShutdownKnob(t, sshHupEscalation, "TS_SSH_HUP_ESCALATION", 30*time.Second)
			sessions := make(chan *sshSession, 1)
			addr := newMonitorSessionServer(t, func(c *conn, s gliderssh.Session) {
				ss := c.newSSHSession(s)
				sessions <- ss
				ss.run()
			})
			client, err := ssh.Dial("tcp", addr, &ssh.ClientConfig{
				HostKeyCallback: ssh.InsecureIgnoreHostKey(),
				Timeout:         10 * time.Second,
			})
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			s, err := client.NewSession()
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			if isPTY {
				if err := s.RequestPty("xterm", 24, 80, nil); err != nil {
					t.Fatal(err)
				}
			}
			stdin, err := s.StdinPipe()
			if err != nil {
				t.Fatal(err)
			}
			defer stdin.Close()
			out, err := s.StdoutPipe()
			if err != nil {
				t.Fatal(err)
			}
			var stderr bytes.Buffer
			s.Stderr = &stderr
			marker := filepath.Join(t.TempDir(), "hup")
			command := fmt.Sprintf("trap 'echo hup > %s; exit 42' HUP; echo ready; while :; do read line; done", marker)
			if err := s.Start(command); err != nil {
				t.Fatal(err)
			}
			if line, err := bufio.NewReader(out).ReadString('\n'); err != nil || strings.TrimSpace(line) != "ready" {
				t.Fatalf("ready marker = %q, %v", line, err)
			}
			ss := <-sessions
			const message = "test session canceled"
			ss.cancelCtx(userVisibleError{error: context.Canceled, msg: message})
			if err := tstest.WaitFor(5*time.Second, func() error {
				b, err := os.ReadFile(marker)
				if err != nil {
					return err
				}
				if strings.TrimSpace(string(b)) != "hup" {
					return fmt.Errorf("HUP marker = %q", b)
				}
				return nil
			}); err != nil {
				t.Fatalf("hangup did not precede escalation: %v", err)
			}
			if err := s.Wait(); err == nil {
				t.Fatal("session exited without a hangup status")
			} else if ee, ok := err.(*ssh.ExitError); !ok || (ee.ExitStatus() != 42 && ee.ExitStatus() != 128+int(unix.SIGHUP)) {
				t.Fatalf("session error = %v; want trap exit 42 or SIGHUP", err)
			}
			if got := strings.Count(stderr.String(), message); got != 1 {
				t.Fatalf("stderr = %q; want one cancellation message", stderr.String())
			}
			next, err := client.NewSession()
			if err != nil {
				t.Fatal(err)
			}
			defer next.Close()
			if out, err := next.CombinedOutput("echo alive"); err != nil || strings.TrimSpace(string(out)) != "alive" {
				t.Fatalf("second session output = %q, %v", out, err)
			}
		})
	}
}

// TestSessionMonitorNormalExit verifies that process completion stops the
// cancellation watcher without waiting for connection closure. Two commands
// on one connection must each deliver output, exit status, EOF, and close.
func TestSessionMonitorNormalExit(t *testing.T) {
	frames := make(chan []string, 1)
	addr := newMonitorSessionServer(t, func(c *conn, s gliderssh.Session) {
		r := &frameRecorder{Session: s}
		c.newSSHSession(r).run()
		frames <- r.got()
	})
	client, err := ssh.Dial("tcp", addr, &ssh.ClientConfig{
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         10 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	for range 2 {
		s, err := client.NewSession()
		if err != nil {
			t.Fatal(err)
		}
		defer s.Close()
		var out []byte
		done := make(chan error, 1)
		go func() {
			var err error
			out, err = s.CombinedOutput("echo output; exit 7")
			done <- err
		}()
		select {
		case err := <-done:
			if ee, ok := err.(*ssh.ExitError); !ok || ee.ExitStatus() != 7 {
				t.Fatalf("session error = %v; want exit 7", err)
			}
		case <-time.After(10 * time.Second):
			t.Fatal("normal exit waited for connection closure")
		}
		if strings.TrimSpace(string(out)) != "output" {
			t.Fatalf("output = %q; want output", out)
		}
		select {
		case got := <-frames:
			if !slices.Equal(got, []string{"exit-status", "eof", "close"}) {
				t.Fatalf("normal exit frames = %v", got)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("session handler did not finish")
		}
	}
}

// TestOutputDrainTimeoutAbortsChannel sends one byte more than the SSH receive
// window without reading client stdout. The child exits, but its final output
// write cannot finish. The server must close the channel without EOF after the
// drain timeout. Reading buffered output afterward verifies that the receive
// window was full rather than the command failing before the pending write.
func TestOutputDrainTimeoutAbortsChannel(t *testing.T) {
	setShutdownKnob(t, sshIODrainTimeout, "TS_SSH_IO_DRAIN_TIMEOUT", 100*time.Millisecond)
	result := make(chan []string, 1)
	addr := newMonitorSessionServer(t, func(c *conn, session gliderssh.Session) {
		frames := &frameRecorder{Session: session}
		c.newSSHSession(frames).run()
		result <- frames.got()
	})
	client, err := ssh.Dial("tcp", addr, &ssh.ClientConfig{
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         10 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	s, err := client.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	out, err := s.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Start("head -c 2097153 /dev/zero"); err != nil {
		t.Fatal(err)
	}
	select {
	case frames := <-result:
		if slices.Contains(frames, "eof") {
			t.Fatalf("drain timeout sent EOF with a pending write: %v", frames)
		}
		if len(frames) < 2 || frames[0] != "exit-status" || frames[1] != "close" {
			t.Fatalf("timeout frames = %v; want exit-status then close", frames)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("output drain timeout did not abort the session")
	}
	if n, err := io.Copy(io.Discard, out); err != nil || n != 2<<20 {
		t.Fatalf("received %d bytes, %v; want the full 2 MiB window", n, err)
	}
	if err := s.Wait(); err != nil {
		t.Fatal(err)
	}
}

// TestResizeWindowCancellation keeps the resize channel open and cancels the
// session context. The resize worker must close its master descriptor and exit
// without waiting for another window-change request.
func TestResizeWindowCancellation(t *testing.T) {
	master, ptyChild, err := pty.Open()
	if err != nil {
		t.Fatal(err)
	}
	defer master.Close()
	defer ptyChild.Close()
	f, err := dupPTYMaster(master)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan struct{})
	go func() {
		defer close(done)
		resizeWindow(ctx, f, make(chan gliderssh.Window))
	}()
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("resize worker did not stop on cancellation")
	}
	if _, err := f.Stat(); !errors.Is(err, os.ErrClosed) {
		t.Fatalf("resize descriptor Stat error = %v; want os.ErrClosed", err)
	}
}
