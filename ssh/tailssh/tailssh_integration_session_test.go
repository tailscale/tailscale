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
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
	"tailscale.com/envknob"
	"tailscale.com/tstest"
)

// This file contains integration tests of per-session behavior: pty
// setup and resizing, terminal modes, the session environment, exit
// statuses, and the TS_SSH_DISABLE_* envknobs.

// sessionTestTimeout bounds each test's SSH client. When it elapses the
// client is closed, which unblocks any pending session reads or waits.
const sessionTestTimeout = 60 * time.Second

// forEachBehavior runs f as a "v2" subtest and as a "v1" subtest with
// forceV1Behavior set.
func forEachBehavior(t *testing.T, f func(t *testing.T, forceV1Behavior bool)) {
	for _, forceV1Behavior := range []bool{false, true} {
		name := "v2"
		if forceV1Behavior {
			name = "v1"
		}
		t.Run(name, func(t *testing.T) {
			defer dumpIncubatorLogOnFail(t)
			f(t, forceV1Behavior)
		})
	}
}

// dialSessionTestClient starts a test server for testuser configured by
// opts and returns a client connected to it. The client is closed at
// the end of the test or after [sessionTestTimeout], whichever is first.
func dialSessionTestClient(t *testing.T, opts testServerOpts) *ssh.Client {
	t.Helper()
	if opts.username == "" {
		opts.username = "testuser"
	}
	addr := testServerWithOpts(t, opts)
	cl, err := ssh.Dial("tcp", addr, &ssh.ClientConfig{
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         15 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	timer := time.AfterFunc(sessionTestTimeout, func() { cl.Close() })
	t.Cleanup(func() {
		timer.Stop()
		cl.Close()
	})
	return cl
}

// ptyRequest describes the pty-req a test session sends.
type ptyRequest struct {
	term       string
	rows, cols int
	modes      ssh.TerminalModes
}

// defaultPTY is a pty request with echo disabled, so that input sent to
// an interactive shell does not appear in its output.
var defaultPTY = ptyRequest{term: "xterm", rows: 24, cols: 80, modes: ssh.TerminalModes{ssh.ECHO: 0}}

// runPTY runs cmd in a new session of cl with a pty allocated per req.
// It returns the session's stdout and stderr, with carriage returns
// removed, and the error from [ssh.Session.Run].
func runPTY(t *testing.T, cl *ssh.Client, req ptyRequest, cmd string) (stdout, stderr string, err error) {
	t.Helper()
	s, err := cl.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := s.RequestPty(req.term, req.rows, req.cols, req.modes); err != nil {
		t.Fatalf("RequestPty: %v", err)
	}
	var outBuf, errBuf bytes.Buffer
	s.Stdout = &outBuf
	s.Stderr = &errBuf
	err = s.Run(cmd)
	return stripCR(outBuf.String()), stripCR(errBuf.String()), err
}

func stripCR(s string) string {
	return strings.ReplaceAll(s, "\r", "")
}

// exitStatus returns the exit status and exit signal carried by err, the
// result of [ssh.Session.Run] or [ssh.Session.Wait]. A nil err is status 0.
// It fails the test if err is not an [*ssh.ExitError].
func exitStatus(t *testing.T, err error) (code int, signal string) {
	t.Helper()
	if err == nil {
		return 0, ""
	}
	ee, ok := errors.AsType[*ssh.ExitError](err)
	if !ok {
		t.Fatalf("got %T (%v), want *ssh.ExitError", err, err)
	}
	return ee.ExitStatus(), ee.Signal()
}

// ptyShell is an interactive login shell session with a pty.
type ptyShell struct {
	s     *ssh.Session
	stdin io.WriteCloser
	out   lockedBuffer // stdout and stderr
	waitc chan error   // receives the result of [ssh.Session.Wait]
}

// startPTYShell starts an interactive shell on cl with a pty allocated
// per req.
func startPTYShell(t *testing.T, cl *ssh.Client, req ptyRequest) *ptyShell {
	t.Helper()
	s, err := cl.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	p := &ptyShell{s: s, waitc: make(chan error, 1)}
	if p.stdin, err = s.StdinPipe(); err != nil {
		t.Fatal(err)
	}
	s.Stdout = &p.out
	s.Stderr = &p.out
	if err := s.RequestPty(req.term, req.rows, req.cols, req.modes); err != nil {
		t.Fatalf("RequestPty: %v", err)
	}
	if err := s.Shell(); err != nil {
		t.Fatalf("Shell: %v", err)
	}
	go func() { p.waitc <- s.Wait() }()
	return p
}

// send writes line and a newline to the shell's stdin.
func (p *ptyShell) send(t *testing.T, line string) {
	t.Helper()
	if _, err := io.WriteString(p.stdin, line+"\n"); err != nil {
		t.Fatalf("writing %q to shell: %v", line, err)
	}
}

// query repeatedly sends cmd to the shell until its output contains want.
// Sending more than once tolerates input discarded while login sets up
// the terminal, and state changes that the server applies asynchronously.
func (p *ptyShell) query(t *testing.T, cmd, want string) {
	t.Helper()
	err := tstest.WaitFor(20*time.Second, func() error {
		if strings.Contains(p.output(), want) {
			return nil
		}
		p.send(t, cmd)
		return fmt.Errorf("output does not contain %q", want)
	})
	if err != nil {
		t.Fatalf("%v; output so far:\n%s", err, p.output())
	}
}

// output returns the shell's output so far, with carriage returns removed.
func (p *ptyShell) output() string {
	return stripCR(p.out.String())
}

// queryValue sends cmd to the shell until it prints a line of the form
// "key=value", and returns the value. The value must not contain spaces.
func (p *ptyShell) queryValue(t *testing.T, cmd, key string) string {
	t.Helper()
	re := regexp.MustCompile(`(?m)(?:^|\$ )` + regexp.QuoteMeta(key) + `=(\S*)$`)
	var val string
	err := tstest.WaitFor(20*time.Second, func() error {
		if m := re.FindStringSubmatch(p.output()); m != nil {
			val = m[1]
			return nil
		}
		p.send(t, cmd)
		return fmt.Errorf("output has no %s= line", key)
	})
	if err != nil {
		t.Fatalf("%v; output so far:\n%s", err, p.output())
	}
	return val
}

// parentCmd prints the command name of the shell's parent process.
const parentCmd = `printf 'parent=%s\n' "$(cat /proc/$PPID/comm)"`

// loginWaitsForShell reports whether the shell's parent process is
// login(1). That is the case when login forks the shell and waits for
// it, as the shadow-utils login on Ubuntu and the BusyBox login on
// Alpine do, rather than exec'ing it. Both exit 0 whatever the shell's
// exit status.
func (p *ptyShell) loginWaitsForShell(t *testing.T) bool {
	t.Helper()
	return p.queryValue(t, parentCmd, "parent") == "login"
}

// isBusyBoxLogin reports whether the login command is BusyBox's. Unlike
// the shadow-utils login, it keeps the terminal modes it starts with.
func isBusyBoxLogin() bool {
	path, err := exec.LookPath("login")
	if err != nil {
		return false
	}
	resolved, err := filepath.EvalSymlinks(path)
	return err == nil && filepath.Base(resolved) == "busybox"
}

// wait waits for the shell session to end and returns its exit status.
func (p *ptyShell) wait(t *testing.T) (code int, signal string) {
	t.Helper()
	select {
	case err := <-p.waitc:
		return exitStatus(t, err)
	case <-time.After(20 * time.Second):
		t.Fatalf("timeout waiting for shell to exit; output:\n%s", p.out.String())
	}
	panic("unreachable")
}

// sttySizeCmd prints the pty size prefixed by "size=", so that the
// expected output never matches the command text if it is echoed.
const sttySizeCmd = `printf 'size=%s\n' "$(stty size)"`

func TestIntegrationPTYInitialSize(t *testing.T) {
	forEachBehavior(t, func(t *testing.T, forceV1Behavior bool) {
		cl := dialSessionTestClient(t, testServerOpts{forceV1Behavior: forceV1Behavior})
		for _, size := range [][2]int{{24, 80}, {53, 191}} {
			req := ptyRequest{term: "xterm", rows: size[0], cols: size[1]}
			out, _, err := runPTY(t, cl, req, sttySizeCmd)
			if err != nil {
				t.Fatalf("stty size: %v; output: %q", err, out)
			}
			if want := fmt.Sprintf("size=%d %d\n", size[0], size[1]); !strings.Contains(out, want) {
				t.Errorf("output = %q, want %q", out, want)
			}
		}
	})
}

func TestIntegrationPTYWindowResize(t *testing.T) {
	forEachBehavior(t, func(t *testing.T, forceV1Behavior bool) {
		cl := dialSessionTestClient(t, testServerOpts{forceV1Behavior: forceV1Behavior})
		p := startPTYShell(t, cl, defaultPTY)
		p.query(t, sttySizeCmd, "size=24 80\n")
		for _, size := range [][2]int{{50, 132}, {30, 100}} {
			if err := p.s.WindowChange(size[0], size[1]); err != nil {
				t.Fatalf("WindowChange: %v", err)
			}
			p.query(t, sttySizeCmd, fmt.Sprintf("size=%d %d\n", size[0], size[1]))
		}
		p.send(t, "exit 0")
		if code, sig := p.wait(t); code != 0 || sig != "" {
			t.Errorf("exit status = %d, signal %q; want 0", code, sig)
		}
	})
}

func TestIntegrationPTYTerminalModes(t *testing.T) {
	// sttyFlags returns the set of boolean flags (like "echo" or
	// "-echo") in the output of "stty -a".
	sttyFlags := func(out string) []string {
		var flags []string
		for f := range strings.FieldsSeq(out) {
			if !strings.ContainsAny(f, "=;") {
				flags = append(flags, f)
			}
		}
		return flags
	}
	tests := []struct {
		modes ssh.TerminalModes
		want  []string
	}{
		{ssh.TerminalModes{ssh.ECHO: 0, ssh.ICRNL: 0, ssh.ISIG: 1, ssh.IUTF8: 1}, []string{"-echo", "-icrnl", "isig", "iutf8"}},
		{ssh.TerminalModes{ssh.ECHO: 1, ssh.ICRNL: 1, ssh.ISIG: 0, ssh.IUTF8: 0}, []string{"echo", "icrnl", "-isig", "-iutf8"}},
	}
	check := func(t *testing.T, modes ssh.TerminalModes, want []string, out string) {
		t.Helper()
		flags := sttyFlags(out)
		for _, w := range want {
			if !slices.Contains(flags, w) {
				t.Errorf("modes %v: stty -a output lacks %q:\n%s", modes, w, out)
			}
		}
	}
	forEachBehavior(t, func(t *testing.T, forceV1Behavior bool) {
		cl := dialSessionTestClient(t, testServerOpts{forceV1Behavior: forceV1Behavior})
		t.Run("exec", func(t *testing.T) {
			for _, tt := range tests {
				out, _, err := runPTY(t, cl, ptyRequest{term: "xterm", rows: 24, cols: 80, modes: tt.modes}, "stty -a")
				if err != nil {
					t.Fatalf("stty -a: %v; output: %q", err, out)
				}
				check(t, tt.modes, tt.want, out)
			}
		})
		t.Run("shell", func(t *testing.T) {
			for _, tt := range tests {
				p := startPTYShell(t, cl, ptyRequest{term: "xterm", rows: 24, cols: 80, modes: tt.modes})
				if p.loginWaitsForShell(t) && !isBusyBoxLogin() {
					t.Skip("KNOWN BUG: shadow-utils login resets the client's terminal modes")
				}
				out := p.queryValue(t, `printf 'modes=%s\n' "$(stty -a | tr ' \n' ',,')"`, "modes")
				p.send(t, "exit")
				check(t, tt.modes, tt.want, strings.ReplaceAll(out, ",", " "))
			}
		})
	})
}

// TestIntegrationPTYExec tests running a command with a pty, like
// "ssh -t host cmd".
func TestIntegrationPTYExec(t *testing.T) {
	forEachBehavior(t, func(t *testing.T, forceV1Behavior bool) {
		cl := dialSessionTestClient(t, testServerOpts{forceV1Behavior: forceV1Behavior})
		stdout, stderr, err := runPTY(t, cl, defaultPTY,
			`[ -t 0 ] && [ -t 1 ] && [ -t 2 ] && echo all-tty; echo to-stdout; echo to-stderr >&2; exit 3`)
		if code, sig := exitStatus(t, err); code != 3 || sig != "" {
			t.Errorf("exit status = %d, signal %q; want 3", code, sig)
		}
		for _, want := range []string{"all-tty\n", "to-stdout\n", "to-stderr\n"} {
			if !strings.Contains(stdout, want) {
				t.Errorf("stdout = %q, want it to contain %q", stdout, want)
			}
		}
		if stderr != "" {
			t.Errorf("stderr = %q, want empty: the pty carries stderr", stderr)
		}
	})
}

// TestIntegrationPTYTerm tests that the pty request's terminal type is
// the session's $TERM, both for commands and for login shells.
func TestIntegrationPTYTerm(t *testing.T) {
	const cmd = `printf 'term=%s\n' "$TERM"`
	forEachBehavior(t, func(t *testing.T, forceV1Behavior bool) {
		cl := dialSessionTestClient(t, testServerOpts{forceV1Behavior: forceV1Behavior})
		t.Run("exec", func(t *testing.T) {
			req := defaultPTY
			req.term = "vt220"
			out, _, err := runPTY(t, cl, req, cmd)
			if err != nil {
				t.Fatalf("%v; output: %q", err, out)
			}
			if !strings.Contains(out, "term=vt220\n") {
				t.Errorf("output = %q, want term=vt220", out)
			}
		})
		t.Run("shell", func(t *testing.T) {
			req := defaultPTY
			req.term = "screen-256color"
			p := startPTYShell(t, cl, req)
			p.query(t, cmd, "term=screen-256color\n")
			p.send(t, "exit")
			p.wait(t)
		})
	})
}

// TestIntegrationSessionEnv tests the environment of a non-pty session.
// It replaces the unit test TestSSH/env, which is skipped in CI (#4051).
func TestIntegrationSessionEnv(t *testing.T) {
	um, err := userLookup("testuser")
	if err != nil {
		t.Fatal(err)
	}
	forEachBehavior(t, func(t *testing.T, forceV1Behavior bool) {
		cl := dialSessionTestClient(t, testServerOpts{forceV1Behavior: forceV1Behavior})
		s, err := cl.NewSession()
		if err != nil {
			t.Fatal(err)
		}
		defer s.Close()
		// LANG and LC_* are accepted by default, like OpenSSH's
		// AcceptEnv. Other variables need the policy's AcceptEnv.
		for k, v := range map[string]string{"LANG": "C.UTF-8", "LC_TIME": "C", "NOT_ACCEPTED": "x"} {
			if err := s.Setenv(k, v); err != nil {
				t.Fatalf("Setenv(%q): %v", k, err)
			}
		}
		out, err := s.CombinedOutput(`env; printf 'cwd=%s\n' "$(pwd)"; ` + parentCmd)
		if err != nil {
			t.Fatalf("%v; output:\n%s", err, out)
		}
		env := map[string]string{}
		for line := range strings.Lines(string(out)) {
			if k, v, ok := strings.Cut(strings.TrimSuffix(line, "\n"), "="); ok {
				env[k] = v
			}
		}

		wantDir := um.HomeDir
		if os.Getenv("SKIP_FILE_OPS") == "1" {
			wantDir = "/"
		} else if _, err := os.Stat(um.HomeDir); err != nil {
			// The session starts in / if the home directory doesn't
			// exist. On Ubuntu, pam_mkhomedir creates it during su
			// sessions, but the in-process path doesn't run PAM.
			wantDir = "/"
		}
		wantEnv := map[string]string{
			"USER":    "testuser",
			"LOGNAME": "testuser",
			"HOME":    um.HomeDir,
			"SHELL":   um.LoginShell(),
			"LANG":    "C.UTF-8",
			"LC_TIME": "C",
			"cwd":     wantDir,
		}
		if env["parent"] == "tailscaled" {
			// The incubator ran the shell itself rather than via su,
			// and its environment (see envForUser) lacks LOGNAME.
			// TODO: set LOGNAME, as OpenSSH's sshd does.
			t.Logf("KNOWN BUG: in-process session lacks LOGNAME; LOGNAME = %q", env["LOGNAME"])
			delete(wantEnv, "LOGNAME")
		}
		for k, want := range wantEnv {
			if got := env[k]; got != want {
				t.Errorf("%s = %q, want %q", k, got, want)
			}
		}
		if got, ok := env["PWD"]; ok && got != env["cwd"] {
			t.Errorf("PWD = %q, but working directory is %q", got, env["cwd"])
		}
		if path := strings.Split(env["PATH"], ":"); !slices.Contains(path, "/usr/bin") || !slices.Contains(path, "/bin") {
			t.Errorf("PATH = %q, want it to contain /usr/bin and /bin", env["PATH"])
		}
		if v, ok := env["NOT_ACCEPTED"]; ok {
			t.Errorf("NOT_ACCEPTED = %q, want unset", v)
		}
		if t.Failed() {
			t.Logf("session output:\n%s", out)
		}
	})
}

func TestIntegrationDisablePTYEnvknob(t *testing.T) {
	envknob.SetenvForTest(t, "TS_SSH_DISABLE_PTY", "true")
	forEachBehavior(t, func(t *testing.T, forceV1Behavior bool) {
		cl := dialSessionTestClient(t, testServerOpts{forceV1Behavior: forceV1Behavior})

		// The pty request itself is accepted, but the session refuses to
		// start anything and exits with status 1.
		out, _, err := runPTY(t, cl, defaultPTY, "echo ran-with-pty")
		if strings.Contains(out, "ran-with-pty") {
			t.Errorf("command ran with a pty despite TS_SSH_DISABLE_PTY; output: %q", out)
		}
		if code, sig := exitStatus(t, err); code != 1 || sig != "" {
			t.Errorf("exit status = %d, signal %q; want 1", code, sig)
		}

		// Sessions without a pty still work, on the same connection.
		s, err := cl.NewSession()
		if err != nil {
			t.Fatal(err)
		}
		defer s.Close()
		if out, err := s.CombinedOutput("echo no-pty-ok"); err != nil || string(out) != "no-pty-ok\n" {
			t.Errorf("non-pty session: output %q, err %v; want %q", out, err, "no-pty-ok\n")
		}
	})
}

func TestIntegrationDisableSFTPEnvknob(t *testing.T) {
	envknob.SetenvForTest(t, "TS_SSH_DISABLE_SFTP", "true")
	forEachBehavior(t, func(t *testing.T, forceV1Behavior bool) {
		cl := dialSessionTestClient(t, testServerOpts{forceV1Behavior: forceV1Behavior})
		if scl, err := sftp.NewClient(cl); err == nil {
			scl.Close()
			t.Fatal("sftp.NewClient succeeded despite TS_SSH_DISABLE_SFTP")
		}

		// The server accepts the subsystem request, then explains the
		// refusal on stderr and closes the channel.
		s, err := cl.NewSession()
		if err != nil {
			t.Fatal(err)
		}
		defer s.Close()
		stderr, err := s.StderrPipe()
		if err != nil {
			t.Fatal(err)
		}
		if err := s.RequestSubsystem("sftp"); err != nil {
			t.Fatalf("RequestSubsystem: %v", err)
		}
		if got, err := io.ReadAll(stderr); err != nil || !strings.Contains(string(got), "sftp disabled") {
			t.Errorf("sftp subsystem stderr = %q, %v; want it to contain %q", got, err, "sftp disabled")
		}

		s2, err := cl.NewSession()
		if err != nil {
			t.Fatal(err)
		}
		defer s2.Close()
		if out, err := s2.CombinedOutput("echo exec-ok"); err != nil || string(out) != "exec-ok\n" {
			t.Errorf("exec session: output %q, err %v; want %q", out, err, "exec-ok\n")
		}
	})
}

// TestIntegrationX11Rejected tests that X11 forwarding, which Tailscale
// SSH does not support, is refused without breaking the session.
func TestIntegrationX11Rejected(t *testing.T) {
	// x11Request is the "x11-req" payload from RFC 4254, section 6.3.1.
	type x11Request struct {
		SingleConnection bool
		AuthProtocol     string
		AuthCookie       string
		ScreenNumber     uint32
	}
	payload := ssh.Marshal(x11Request{
		AuthProtocol: "MIT-MAGIC-COOKIE-1",
		AuthCookie:   "0123456789abcdef0123456789abcdef",
	})
	forEachBehavior(t, func(t *testing.T, forceV1Behavior bool) {
		cl := dialSessionTestClient(t, testServerOpts{forceV1Behavior: forceV1Behavior})
		for _, withPTY := range []bool{false, true} {
			s, err := cl.NewSession()
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			if withPTY {
				if err := s.RequestPty("xterm", 24, 80, ssh.TerminalModes{}); err != nil {
					t.Fatalf("RequestPty: %v", err)
				}
			}
			ok, err := s.SendRequest("x11-req", true, payload)
			if err != nil {
				t.Fatalf("x11-req: %v", err)
			}
			if ok {
				t.Errorf("x11-req accepted (pty=%v), want rejection", withPTY)
			}
			out, err := s.CombinedOutput(`printf 'display=%s\n' "${DISPLAY:-unset}"`)
			if err != nil {
				t.Fatalf("command after x11-req (pty=%v): %v; output: %q", withPTY, err, out)
			}
			if got := stripCR(string(out)); !strings.Contains(got, "display=unset\n") {
				t.Errorf("output after x11-req (pty=%v) = %q, want display=unset", withPTY, got)
			}
		}
	})
}

// TestIntegrationOpenSSHInteractivePTY drives an interactive login shell
// with the system OpenSSH client and a forced pty ("ssh -tt").
func TestIntegrationOpenSSHInteractivePTY(t *testing.T) {
	sshPath, err := exec.LookPath("ssh")
	if err != nil {
		t.Skipf("skipping without OpenSSH client: %v", err)
	}
	forEachBehavior(t, func(t *testing.T, forceV1Behavior bool) {
		addr := testServerWithOpts(t, testServerOpts{username: "testuser", forceV1Behavior: forceV1Behavior})
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
		defer cancel()
		// The options match TestOpenSSHExitCodes, but with -tt instead
		// of -T. Auth is pinned to "none".
		cmd := exec.CommandContext(ctx, sshPath,
			"-F", "/dev/null",
			"-tt",
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
			"testuser@"+host,
		)
		p := &ptyShell{}
		if p.stdin, err = cmd.StdinPipe(); err != nil {
			t.Fatal(err)
		}
		cmd.Stdout = &p.out
		cmd.Stderr = &p.out
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		waitc := make(chan error, 1)
		go func() { waitc <- cmd.Wait() }()

		if got := p.queryValue(t, `printf 'user=%s\n' "$(id -un)"`, "user"); got != "testuser" {
			t.Errorf("id -un = %q, want testuser", got)
		}
		loginWaits := p.loginWaitsForShell(t)
		p.send(t, "exit 5")

		select {
		case err = <-waitc:
		case <-ctx.Done():
			t.Fatalf("timeout waiting for ssh to exit; output:\n%s", p.output())
		}
		code := 0
		if ee, ok := errors.AsType[*exec.ExitError](err); ok {
			code = ee.ExitCode()
		} else if err != nil {
			t.Fatalf("ssh: %v", err)
		}
		if loginWaits {
			// See TestIntegrationPTYExitStatus.
			t.Logf("KNOWN BUG: login discards the shell's exit status; ssh exit code = %d", code)
		} else if code != 5 {
			t.Errorf("ssh exit code = %d, want 5; output:\n%s", code, p.output())
		}
	})
}

// TestIntegrationPTYExitStatus tests the exit status the server reports
// when a session's shell exits with a code or is killed by a signal.
//
// The server never sends an "exit-signal" message. When the session's
// process dies from a signal, it reports the shell convention of 128
// plus the signal number as the exit status, except on the in-process
// path, which reports 1 with a "[tailscale-ssh: process died: ...]"
// message on stderr.
//
// KNOWN BUG: this pins the current behavior. OpenSSH's sshd sends
// "exit-signal" for a signal death, and the two paths should agree.
func TestIntegrationPTYExitStatus(t *testing.T) {
	// checkSignaled checks the exit status of a session whose shell
	// killed itself with signal number signum.
	checkSignaled := func(t *testing.T, err error, output string, signum int) {
		t.Helper()
		code, sig := exitStatus(t, err)
		if sig != "" {
			t.Errorf("got exit-signal %q; the server is not expected to send one", sig)
		}
		want := 128 + signum
		if strings.Contains(output, "[tailscale-ssh: process died:") {
			want = 1
		}
		if code != want {
			t.Errorf("exit status = %d, want %d; output: %q", code, want, output)
		}
	}
	forEachBehavior(t, func(t *testing.T, forceV1Behavior bool) {
		cl := dialSessionTestClient(t, testServerOpts{forceV1Behavior: forceV1Behavior})
		// startShell starts an interactive shell. It skips the test if
		// the shell runs under a login that exits 0 regardless
		// of how the shell exited.
		startShell := func(t *testing.T) *ptyShell {
			p := startPTYShell(t, cl, defaultPTY)
			if p.loginWaitsForShell(t) {
				t.Skip("KNOWN BUG: login discards the shell's exit status")
			}
			return p
		}
		t.Run("shell_exit_code", func(t *testing.T) {
			p := startShell(t)
			p.send(t, "exit 7")
			if code, sig := p.wait(t); code != 7 || sig != "" {
				t.Errorf("exit status = %d, signal %q; want 7; output:\n%s", code, sig, p.output())
			}
		})
		t.Run("shell_signal", func(t *testing.T) {
			p := startShell(t)
			// Interactive shells ignore SIGTERM, so use SIGKILL.
			p.send(t, "kill -KILL $$")
			select {
			case err := <-p.waitc:
				checkSignaled(t, err, p.output(), 9)
			case <-time.After(20 * time.Second):
				t.Fatalf("timeout waiting for shell to exit; output:\n%s", p.output())
			}
		})
		t.Run("exec_pty_signal", func(t *testing.T) {
			out, _, err := runPTY(t, cl, defaultPTY, "kill -TERM $$")
			checkSignaled(t, err, out, 15)
		})
		t.Run("exec_signal", func(t *testing.T) {
			s, err := cl.NewSession()
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			out, err := s.CombinedOutput("kill -TERM $$")
			checkSignaled(t, err, string(out), 15)
		})
	})
}
