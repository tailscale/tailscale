// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build integrationtest

package tailssh

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"tailscale.com/tstest"
)

// init fail-fasts any missing invariant (TAILSCALED_PATH, test user,
// login shell) so CI failures point at the broken piece instead of
// cryptic mid-test crashes. Logs the minimum context (GOOS, ssh
// version, resolved user shell) needed to attribute a failure.
func init() {
	log.Printf("preflight: GOOS=%s GOARCH=%s euid=%d", runtime.GOOS, runtime.GOARCH, os.Geteuid())

	if p := os.Getenv("TAILSCALED_PATH"); p != "" {
		fi, err := os.Stat(p)
		if err != nil {
			log.Fatalf("preflight: TAILSCALED_PATH=%q not usable: %v", p, err)
		}
		if fi.Mode()&0111 == 0 {
			log.Fatalf("preflight: TAILSCALED_PATH=%q is not executable (mode %v)", p, fi.Mode())
		}
	}

	if _, err := exec.LookPath("ssh"); err == nil {
		if out, err := exec.Command("ssh", "-V").CombinedOutput(); err == nil {
			log.Printf("preflight: ssh -V: %s", bytes.TrimSpace(out))
		}
	}

	username := exitCodeTestUser()
	if _, err := user.Lookup(username); err != nil {
		log.Fatalf("preflight: user.Lookup(%q) failed: %v", username, err)
	}
	um, err := userLookup(username)
	if err != nil {
		log.Fatalf("preflight: userLookup(%q) failed: %v", username, err)
	}
	shell := um.LoginShell()
	if shell == "" {
		log.Fatalf("preflight: empty login shell for %q", username)
	}
	if _, err := os.Stat(shell); err != nil {
		log.Fatalf("preflight: login shell %q for user %q not usable: %v", shell, username, err)
	}
	log.Printf("preflight: user=%q shell=%q", username, shell)
}

// exitCodeTestUser is the local OS user the exit-code tests run as,
// overridable via TS_SSH_INTEGRATION_TEST_USER (testuser on Linux
// docker, runner on macOS CI).
func exitCodeTestUser() string {
	if u := os.Getenv("TS_SSH_INTEGRATION_TEST_USER"); u != "" {
		return u
	}
	return "testuser"
}

// dialTestClientForUser returns the dial error rather than t.Fatal'ing,
// so retry-aware tests can distinguish transport noise from assertion
// failure.
func dialTestClientForUser(t *testing.T, username string, forceV1Behavior, allowSendEnv bool, authMethods ...ssh.AuthMethod) (*ssh.Client, error) {
	t.Helper()
	addr := testServer(t, username, forceV1Behavior, allowSendEnv)
	return ssh.Dial("tcp", addr, &ssh.ClientConfig{
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Auth:            authMethods,
		Timeout:         15 * time.Second,
	})
}

// dumpIncubatorLogOnFail prints /tmp/tailscalessh.log on subtest
// failure. The incubator runs in its own process; its log doesn't
// reach t.Log otherwise.
func dumpIncubatorLogOnFail(t *testing.T) {
	t.Helper()
	if !t.Failed() {
		return
	}
	b, err := os.ReadFile("/tmp/tailscalessh.log")
	if err != nil {
		t.Logf("incubator log unreadable: %v", err)
		return
	}
	if len(b) == 0 {
		t.Logf("incubator log empty (no incubator launched, or log rotated)")
		return
	}
	t.Logf("---- /tmp/tailscalessh.log (%d bytes) ----\n%s\n---- end ----", len(b), b)
}

// TestIntegrationExitCodes pins the SSH exit-status frame end-to-end
// through the real server stack (gliderssh + tailssh + incubator) with
// a Go x/crypto/ssh client. Transport noise (dial, pre-exec) is retried
// via tstest.WaitFor; an exit-code mismatch is the assertion and never
// retries.
func TestIntegrationExitCodes(t *testing.T) {
	username := exitCodeTestUser()

	tests := []struct {
		name     string
		cmd      string
		wantCode int
	}{
		{"success", "true", 0},
		{"exit_code_passthrough", "exit 42", 42},
		// 127 = command-not-found, POSIX shell convention.
		// https://pubs.opengroup.org/onlinepubs/9699919799/utilities/V3_chap02.html#tag_18_08_02
		{"command_not_found", "/nonexistent/binary", 127},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer dumpIncubatorLogOnFail(t)

			runOnce := func() (gotCode int, transportErr error, out []byte) {
				cl, dialErr := dialTestClientForUser(t, username, false, false)
				if dialErr != nil {
					return -1, dialErr, nil
				}
				defer cl.Close()
				s, err := cl.NewSession()
				if err != nil {
					return -1, fmt.Errorf("NewSession: %w", err), nil
				}
				defer s.Close()

				type result struct {
					out []byte
					err error
				}
				done := make(chan result, 1)
				go func() {
					o, e := s.CombinedOutput(tt.cmd)
					done <- result{o, e}
				}()

				var res result
				select {
				case res = <-done:
				case <-time.After(20 * time.Second):
					return -1, errors.New("ssh command timed out"), nil
				}

				if res.err == nil {
					return 0, nil, res.out
				}
				var ee *ssh.ExitError
				if errors.As(res.err, &ee) {
					return ee.ExitStatus(), nil, res.out
				}
				// EOF before exit-status, channel teardown, etc. — treat as
				// transport noise so the retry loop can act. The bug we're
				// catching only surfaces as a wrong ExitStatus().
				return -1, fmt.Errorf("non-exit ssh error: %w", res.err), res.out
			}

			// tstest.WaitFor retries on transport noise; a definitive
			// exit-code observation returns nil so the assertion runs
			// once, after WaitFor.
			var gotCode int
			var lastOut []byte
			err := tstest.WaitFor(5*time.Second, func() error {
				code, transportErr, out := runOnce()
				lastOut = out
				if transportErr != nil {
					t.Logf("transport failure: %v; output:\n%s", transportErr, out)
					return transportErr
				}
				gotCode = code
				return nil
			})
			if err != nil {
				t.Fatalf("ssh command %q never completed cleanly: %v; last output:\n%s",
					tt.cmd, err, lastOut)
			}
			if gotCode != tt.wantCode {
				t.Fatalf("exit code = %d, want %d; output:\n%s", gotCode, tt.wantCode, lastOut)
			}
		})
	}
}

// TestOpenSSHExitCodes is TestIntegrationExitCodes against the system
// ssh binary, which is what users of #18256 are actually running
// (macOS ships a LibreSSL fork). Auth pinned to "none" with every
// other method explicitly disabled so OpenSSH can't fall back to
// a different path on different versions.
func TestOpenSSHExitCodes(t *testing.T) {
	sshPath, err := exec.LookPath("ssh")
	if err != nil {
		t.Skipf("skipping without OpenSSH client: %v", err)
	}
	username := exitCodeTestUser()

	if out, err := exec.Command(sshPath, "-V").CombinedOutput(); err == nil {
		t.Logf("OpenSSH version: %s", bytes.TrimSpace(out))
	}
	t.Logf("OpenSSH test user: %s", username)

	addr := testServer(t, username, false, false)
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("tailssh server listening on %s", addr)

	exitStatus := func(t *testing.T, err error) int {
		t.Helper()
		if err == nil {
			return 0
		}
		var ee *exec.ExitError
		if !errors.As(err, &ee) {
			t.Fatalf("want *exec.ExitError, got %T: %v", err, err)
		}
		return ee.ExitCode()
	}

	// OpenSSH rc=255 is "ssh internal error" (connect/auth fail before
	// the remote command runs); treat as transport, not the assertion.
	// https://man.openbsd.org/ssh.1#EXIT_STATUS
	isTransport := func(rc int) bool { return rc == 255 }

	tests := []struct {
		name     string
		cmd      string
		wantCode int
	}{
		{"success", "true", 0},
		{"exit_code_passthrough", "exit 42", 42},
		{"command_not_found", "/nonexistent/binary", 127},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer dumpIncubatorLogOnFail(t)

			runOnce := func() (rc int, out []byte) {
				ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
				defer cancel()
				cmd := exec.CommandContext(ctx, sshPath,
					"-vvv",
					"-F", "/dev/null",
					"-T",
					"-o", "BatchMode=yes",
					"-o", "ConnectTimeout=15",
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
					username+"@"+host,
					tt.cmd,
				)
				o, err := cmd.CombinedOutput()
				if ctx.Err() == context.DeadlineExceeded {
					t.Logf("ssh command timed out; output:\n%s", o)
					return 255, o
				}
				return exitStatus(t, err), o
			}

			var gotRC int
			var lastOut []byte
			err := tstest.WaitFor(5*time.Second, func() error {
				rc, out := runOnce()
				lastOut = out
				if isTransport(rc) && rc != tt.wantCode {
					t.Logf("transport failure (rc=255); output:\n%s", out)
					return fmt.Errorf("ssh rc=%d (transport)", rc)
				}
				gotRC = rc
				return nil
			})
			if err != nil {
				t.Fatalf("ssh command %q never returned a non-transport exit status: %v; last output:\n%s",
					tt.cmd, err, lastOut)
			}
			if gotRC != tt.wantCode {
				t.Fatalf("ssh exit code = %d, want %d; output:\n%s", gotRC, tt.wantCode, lastOut)
			}
		})
	}
}

// TestLocalUnixForwardingHalfClose: after the client closes its write
// side, the server's still-in-flight response must arrive. The old
// cancel-on-first-direction bicopy tore the channel down too early.
func TestLocalUnixForwardingHalfClose(t *testing.T) {
	debugTest.Store(true)
	t.Cleanup(func() { debugTest.Store(false) })

	socketDir, err := os.MkdirTemp("", "tailssh-test-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(socketDir) })
	socketPath := filepath.Join(socketDir, "halfclose.sock")

	ul, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ul.Close() })

	// Delayed-response service: read everything, sleep, then write.
	const response = "delayed-response-after-client-closes-write"
	go func() {
		for {
			conn, err := ul.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				io.ReadAll(conn)
				time.Sleep(100 * time.Millisecond)
				io.WriteString(conn, response)
			}()
		}
	}()

	addr := testServerWithOpts(t, testServerOpts{
		username:                 "testuser",
		allowLocalPortForwarding: true,
	})

	cl, err := ssh.Dial("tcp", addr, &ssh.ClientConfig{
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cl.Close() })

	conn, err := cl.Dial("unix", socketPath)
	if err != nil {
		t.Fatalf("failed to dial unix socket through SSH: %s", err)
	}
	defer conn.Close()

	// (*ssh.Client).Dial("unix", ...) returns a *chanConn that embeds
	// ssh.Channel; ssh.Channel exposes CloseWrite (RFC 4254 §5.3 EOF).
	// Assert to that capability, not *net.TCPConn.
	if _, err := io.WriteString(conn, "request data"); err != nil {
		t.Fatalf("failed to write: %s", err)
	}
	cw, ok := conn.(interface{ CloseWrite() error })
	if !ok {
		t.Fatalf("conn %T does not implement CloseWrite; cannot test half-close", conn)
	}
	if err := cw.CloseWrite(); err != nil {
		t.Fatalf("CloseWrite: %v", err)
	}

	// *chanConn.SetReadDeadline returns an error, so bound the read in
	// a goroutine: a bicopy regression must fail fast, not hang CI.
	type readResult struct {
		data []byte
		err  error
	}
	done := make(chan readResult, 1)
	go func() {
		got, err := io.ReadAll(conn)
		done <- readResult{got, err}
	}()
	select {
	case res := <-done:
		if res.err != nil {
			t.Fatalf("failed to read response: %s", res.err)
		}
		if string(res.data) != response {
			t.Errorf("got %q, want %q", res.data, response)
		}
	case <-time.After(15 * time.Second):
		t.Fatalf("timed out waiting for response after half-close; bicopy may be tearing down the channel prematurely")
	}
}

// TestIntegrationSIGHUP asserts session teardown delivers SIGHUP (not
// SIGKILL): a bash trap writes a marker file, then we tear down and
// check the file appeared.
func TestIntegrationSIGHUP(t *testing.T) {
	debugTest.Store(true)
	t.Cleanup(func() { debugTest.Store(false) })

	dir := t.TempDir()
	readyFile := filepath.Join(dir, "ready")
	markerFile := filepath.Join(dir, "sighup-received")

	cl := testClient(t, false, false)
	s, err := cl.NewSession()
	if err != nil {
		t.Fatal(err)
	}

	// Touch readyFile after installing the trap so the test can wait
	// on a real condition (trap installed) instead of guessing with a
	// wall-clock sleep.
	cmd := fmt.Sprintf(
		`trap 'echo received > %s; exit 0' HUP; : > %s; sleep 30`,
		markerFile, readyFile,
	)
	if err := s.Start(cmd); err != nil {
		t.Fatalf("failed to start command: %v", err)
	}

	if err := tstest.WaitFor(10*time.Second, func() error {
		_, err := os.Stat(readyFile)
		return err
	}); err != nil {
		t.Fatalf("trap never installed: %v", err)
	}

	s.Close()
	cl.Close()

	if err := tstest.WaitFor(10*time.Second, func() error {
		_, err := os.Stat(markerFile)
		return err
	}); err != nil {
		t.Fatalf("process did not receive SIGHUP: %v", err)
	}
	data, err := os.ReadFile(markerFile)
	if err != nil {
		t.Fatalf("read marker: %v", err)
	}
	if got := strings.TrimSpace(string(data)); got != "received" {
		t.Fatalf("marker content = %q, want %q", got, "received")
	}
}
