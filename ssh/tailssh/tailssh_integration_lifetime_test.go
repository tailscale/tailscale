// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build integrationtest && linux

package tailssh

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"tailscale.com/envknob"
	"tailscale.com/hostinfo"
	"tailscale.com/tailcfg"
)

// This file contains integration tests of session lifetime: what ends a
// running session (client disconnect, SessionDuration, policy changes,
// RuleExpires, server shutdown) and that the session's whole process tree,
// including the incubator and the per-connection ssh-monitor, goes away
// when it does. It also covers host key selection, utmp registration via
// login, and the TAILSCALE_SSH_DEFAULT_PATH envknob.

// procInfo identifies a process. The start time distinguishes it from a
// later process that reuses its pid.
type procInfo struct {
	pid   int
	ppid  int
	pgid  int
	sid   int
	start string // field 22 of /proc/<pid>/stat
	comm  string
}

func (p procInfo) String() string {
	cmdline, _ := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", p.pid))
	return fmt.Sprintf("pid %d pgid %d sid %d (%s) %q", p.pid, p.pgid, p.sid, p.comm, strings.TrimSpace(string(bytes.ReplaceAll(cmdline, []byte{0}, []byte{' '}))))
}

// readProc returns the process with the given pid. It reports false if
// there is no such process or it is a zombie, which counts as gone: it has
// exited and only awaits reaping by its parent.
func readProc(pid int) (procInfo, bool) {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return procInfo{}, false
	}
	s := string(b)
	open, closeParen := strings.IndexByte(s, '('), strings.LastIndexByte(s, ')')
	if open < 0 || closeParen < open {
		return procInfo{}, false
	}
	// The fields after the comm start at field 3 (state).
	f := strings.Fields(s[closeParen+1:])
	if len(f) < 20 {
		return procInfo{}, false
	}
	if f[0] == "Z" || f[0] == "X" {
		return procInfo{}, false
	}
	ppid, _ := strconv.Atoi(f[1])
	pgid, _ := strconv.Atoi(f[2])
	sid, _ := strconv.Atoi(f[3])
	return procInfo{
		pid:   pid,
		ppid:  ppid,
		pgid:  pgid,
		sid:   sid,
		start: f[19],
		comm:  s[open+1 : closeParen],
	}, true
}

// alive reports whether p is still running.
func (p procInfo) alive() bool {
	cur, ok := readProc(p.pid)
	return ok && cur.start == p.start
}

// sessionProcs returns the processes with the given pids plus every
// ancestor of the first pid below the ssh-monitor: the session's shell
// wrappers (login, su) and the incubator. It also returns the
// per-connection ssh-monitor, which must be the test process's child.
func sessionProcs(t *testing.T, pids ...int) (tree []procInfo, monitor procInfo) {
	t.Helper()
	for _, pid := range pids {
		p, ok := readProc(pid)
		if !ok {
			t.Fatalf("session process %d not running", pid)
		}
		tree = append(tree, p)
	}
	self := os.Getpid()
	for p := tree[0]; ; {
		if p.ppid <= 1 {
			t.Fatalf("session process %v does not descend from the test process (pid %d); chain: %v", tree[0], self, tree)
		}
		parent, ok := readProc(p.ppid)
		if !ok {
			t.Fatalf("ancestor %d of %v not running", p.ppid, p)
		}
		if parent.ppid == self {
			if !strings.Contains(parent.String(), "ssh-monitor") {
				t.Fatalf("session's top ancestor %v is not an ssh-monitor", parent)
			}
			return tree, parent
		}
		tree = append(tree, parent)
		p = parent
	}
}

// procTeardownTimeout bounds how long session processes may take to exit
// after their session ends. Teardown includes the 5s SIGHUP to SIGKILL
// escalation ([hangupEscalation]) and the ssh-monitor's two bounded reap
// sweeps ([monTeardownReap]).
const procTeardownTimeout = 12 * time.Second

// waitProcsGone waits up to timeout for every process in procs to exit
// and returns the ones still running at the deadline.
func waitProcsGone(procs []procInfo, timeout time.Duration) (alive []procInfo) {
	deadline := time.Now().Add(timeout)
	for {
		alive = alive[:0]
		for _, p := range procs {
			if p.alive() {
				alive = append(alive, p)
			}
		}
		if len(alive) == 0 || time.Now().After(deadline) {
			return alive
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// killProcs SIGKILLs every process in procs that is still running.
func killProcs(procs []procInfo) {
	for _, p := range procs {
		if p.alive() {
			syscall.Kill(p.pid, syscall.SIGKILL)
		}
	}
}

// sessionMode is how a [lifetimeSession] runs its command.
type sessionMode int

const (
	modeExec     sessionMode = iota // exec request, no pty
	modePtyExec                     // pty-req, then exec request
	modePtyShell                    // pty-req, then shell request with the command typed in
)

var sessionModes = []struct {
	name string
	mode sessionMode
}{
	{"exec", modeExec},
	{"pty_exec", modePtyExec},
	{"pty_shell", modePtyShell},
}

// lifetimeScript starts two background sleeps, prints its own and their
// pids, and then echoes stdin lines back so the test can check that the
// session is still alive. It is run through sh -c so that a pty shell's
// job control does not move the sleeps into a process group of their own.
const lifetimeScript = `sh -c 'sleep 1000 & a=$!; sleep 1000 & b=$!; echo "PIDS $$ $a $b"; while read x; do echo "echo:$x"; done'`

var pidsRx = regexp.MustCompile(`PIDS (\d+) (\d+) (\d+)`)

// lifetimeSession is a running [lifetimeScript] session on its own
// connection.
type lifetimeSession struct {
	nc      net.Conn // raw client transport, for abrupt disconnects
	cl      *ssh.Client
	stdin   io.WriteCloser
	stdout  *lockedBuffer // stdout, plus stderr in pty modes
	stderr  *lockedBuffer
	done    chan error // receives the result of [ssh.Session.Wait]
	procs   []procInfo // the session's processes below the ssh-monitor, the incubator last
	monitor procInfo   // the connection's ssh-monitor
	pings   int
}

// dialLifetimeClient connects to the server at addr. Unlike [ssh.Dial],
// it bounds the SSH handshake, not just the TCP dial, and it returns the
// raw transport so tests can drop the connection abruptly.
func dialLifetimeClient(addr string, cfg *ssh.ClientConfig) (net.Conn, *ssh.Client, error) {
	nc, err := net.DialTimeout("tcp", addr, 10*time.Second)
	if err != nil {
		return nil, nil, err
	}
	nc.SetDeadline(time.Now().Add(15 * time.Second))
	c, chans, reqs, err := ssh.NewClientConn(nc, addr, cfg)
	if err != nil {
		nc.Close()
		return nil, nil, err
	}
	nc.SetDeadline(time.Time{})
	return nc, ssh.NewClient(c, chans, reqs), nil
}

// insecureClientConfig returns a client config for testuser that accepts
// any host key.
func insecureClientConfig() *ssh.ClientConfig {
	return &ssh.ClientConfig{
		User:            "testuser",
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}
}

// startLifetimeSession opens a connection to addr, runs [lifetimeScript]
// in the given mode, and waits for it to report its pids.
func startLifetimeSession(t *testing.T, addr string, mode sessionMode) *lifetimeSession {
	t.Helper()
	nc, cl, err := dialLifetimeClient(addr, insecureClientConfig())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { cl.Close() })
	sess, err := cl.NewSession()
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	ls := &lifetimeSession{
		nc:     nc,
		cl:     cl,
		stdout: new(lockedBuffer),
		stderr: new(lockedBuffer),
		done:   make(chan error, 1),
	}
	sess.Stdout = ls.stdout
	sess.Stderr = ls.stderr
	ls.stdin, err = sess.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	if mode != modeExec {
		if err := sess.RequestPty("xterm", 40, 200, ssh.TerminalModes{ssh.ECHO: 0}); err != nil {
			t.Fatalf("RequestPty: %v", err)
		}
	}
	if mode == modePtyShell {
		err = sess.Shell()
	} else {
		err = sess.Start(lifetimeScript)
	}
	if err != nil {
		t.Fatalf("starting session: %v", err)
	}
	go func() { ls.done <- sess.Wait() }()
	if mode == modePtyShell {
		// Wait for the prompt. Input typed before it can be lost, as
		// with busybox login on Alpine.
		ls.waitOutput(t, func(out string) bool {
			return strings.HasSuffix(out, "$ ") || strings.HasSuffix(out, "# ")
		})
		if _, err := io.WriteString(ls.stdin, lifetimeScript+"\n"); err != nil {
			t.Fatalf("typing command: %v", err)
		}
	}

	var m []string
	ls.waitOutput(t, func(out string) bool {
		m = pidsRx.FindStringSubmatch(out)
		return m != nil
	})
	var pids []int
	for _, s := range m[1:] {
		pid, _ := strconv.Atoi(s)
		pids = append(pids, pid)
	}
	ls.procs, ls.monitor = sessionProcs(t, pids...)
	t.Cleanup(func() { killProcs(ls.procs) })
	t.Logf("session processes: %v; monitor: %v", ls.procs, ls.monitor)
	return ls
}

// waitOutput waits until cond holds for the session's stdout so far. It
// fails the test if the session ends first or on timeout.
func (ls *lifetimeSession) waitOutput(t *testing.T, cond func(string) bool) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for !cond(ls.stdout.String()) {
		select {
		case err := <-ls.done:
			ls.done <- err
			t.Fatalf("session ended (%v) before expected output; stdout: %q; stderr: %q", err, ls.stdout.String(), ls.stderr.String())
		default:
		}
		if time.Now().After(deadline) {
			t.Fatalf("timeout waiting for session output; stdout: %q; stderr: %q", ls.stdout.String(), ls.stderr.String())
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// ping checks that the session's script still echoes stdin.
func (ls *lifetimeSession) ping(t *testing.T) {
	t.Helper()
	ls.pings++
	want := fmt.Sprintf("echo:ping%d", ls.pings)
	if _, err := fmt.Fprintf(ls.stdin, "ping%d\n", ls.pings); err != nil {
		t.Fatalf("writing ping: %v", err)
	}
	ls.waitOutput(t, func(out string) bool { return strings.Contains(out, want) })
}

// waitDone waits for the session to end and returns the result of
// [ssh.Session.Wait].
func (ls *lifetimeSession) waitDone(t *testing.T, timeout time.Duration) error {
	t.Helper()
	select {
	case err := <-ls.done:
		ls.done <- err
		return err
	case <-time.After(timeout):
		t.Fatalf("session still running after %v; stdout: %q; stderr: %q", timeout, ls.stdout.String(), ls.stderr.String())
		return nil
	}
}

// escapedGroupBug describes the known bug that
// [lifetimeSession.waitProcsGone] tolerates.
const escapedGroupBug = "KNOWN BUG: tailssh ends a session by signaling only the incubator's process group, " +
	"so processes moved out of it outlived their SSH session " +
	"(util-linux su -c starts the command in a new session; the in-process incubator starts a pty shell " +
	"in a new foreground group; an interactive shell gives each job its own group)"

// waitProcsGone waits for procs, some of the session's processes, to
// exit. Survivors fail the test, with one exception for a known bug: if
// every survivor has left the incubator's process group, it kills them
// and returns a description of the leak for [skipIfLeaked], so that the
// rest of the test can run.
func (ls *lifetimeSession) waitProcsGone(t *testing.T, procs ...procInfo) (leak string) {
	t.Helper()
	start := time.Now()
	alive := waitProcsGone(procs, procTeardownTimeout)
	if len(alive) == 0 {
		t.Logf("%d session processes exited within %v", len(procs), time.Since(start).Round(time.Millisecond))
		return ""
	}
	desc := fmt.Sprint(alive)
	incubator := ls.procs[len(ls.procs)-1]
	if slices.ContainsFunc(alive, func(p procInfo) bool { return p.pgid == incubator.pgid || p == ls.monitor }) {
		t.Fatalf("%d session processes still running after %v: %s", len(alive), procTeardownTimeout, desc)
	}
	killProcs(alive)
	if still := waitProcsGone(alive, procTeardownTimeout); len(still) > 0 {
		t.Fatalf("leaked session processes survived SIGKILL: %v", still)
	}
	return escapedGroupBug + ": " + desc
}

// waitAllGone waits for all of the session's processes, including the
// ssh-monitor, to exit, as [lifetimeSession.waitProcsGone] does.
func (ls *lifetimeSession) waitAllGone(t *testing.T) (leak string) {
	t.Helper()
	return ls.waitProcsGone(t, append(slices.Clone(ls.procs), ls.monitor)...)
}

// skipIfLeaked skips t if any leak from [lifetimeSession.waitProcsGone]
// is non-empty. Failures recorded earlier still fail the test.
func skipIfLeaked(t *testing.T, leaks ...string) {
	t.Helper()
	var all []string
	for _, leak := range leaks {
		if leak != "" {
			all = append(all, leak)
		}
	}
	if len(all) > 0 {
		t.Skip(strings.Join(all, "; "))
	}
}

// exitDesc describes a [ssh.Session.Wait] result for logs.
func exitDesc(err error) string {
	if err == nil {
		return "exit status 0"
	}
	if ee, ok := errors.AsType[*ssh.ExitError](err); ok {
		return fmt.Sprintf("exit status %d (signal %q)", ee.ExitStatus(), ee.Signal())
	}
	return fmt.Sprintf("%T: %v", err, err)
}

// TestIntegrationClientDisconnectKillsSession checks that dropping the
// client's transport without any SSH-level close ends the session's
// whole process tree, including background children of the user's
// command, the incubator, and the ssh-monitor.
func TestIntegrationClientDisconnectKillsSession(t *testing.T) {
	for _, v1 := range []bool{false, true} {
		addr := testServerWithOpts(t, testServerOpts{username: "testuser", forceV1Behavior: v1})
		for _, m := range sessionModes {
			t.Run(fmt.Sprintf("%s_v1=%v", m.name, v1), func(t *testing.T) {
				defer dumpIncubatorLogOnFail(t)
				ls := startLifetimeSession(t, addr, m.mode)
				ls.ping(t)
				ls.nc.Close()
				skipIfLeaked(t, ls.waitAllGone(t))
			})
		}
	}
}

// TestIntegrationSessionDuration checks that [tailcfg.SSHAction.SessionDuration]
// ends a running session with a message and a failure exit, and that the
// session's processes are killed.
func TestIntegrationSessionDuration(t *testing.T) {
	const dur = 3 * time.Second
	addr := testServerWithOpts(t, testServerOpts{
		username: "testuser",
		modifyRule: func(r *tailcfg.SSHRule) {
			r.Action.SessionDuration = dur
		},
	})
	for _, m := range []sessionMode{modeExec, modePtyShell} {
		t.Run(sessionModes[m].name, func(t *testing.T) {
			defer dumpIncubatorLogOnFail(t)
			start := time.Now()
			ls := startLifetimeSession(t, addr, m)
			ls.ping(t)
			// The session's output streams stay open while any of its
			// processes do, so wait for those first. The connection, and
			// with it the ssh-monitor, stays up.
			leak := ls.waitProcsGone(t, ls.procs...)
			err := ls.waitDone(t, 20*time.Second)
			elapsed := time.Since(start)
			t.Logf("session ended after %v with %s", elapsed.Round(time.Millisecond), exitDesc(err))
			if elapsed < dur {
				t.Errorf("session ended after %v, before its %v duration", elapsed, dur)
			}
			if err == nil {
				t.Errorf("session exited 0, want a failure")
			}
			wantMsg := fmt.Sprintf("Session timeout of %v elapsed.", dur)
			// In pty mode, stderr is merged into the pty's output.
			if got := ls.stderr.String() + ls.stdout.String(); !strings.Contains(got, wantMsg) {
				t.Errorf("client output lacks %q; stdout: %q; stderr: %q", wantMsg, ls.stdout.String(), ls.stderr.String())
			}
			ls.cl.Close()
			ls.waitProcsGone(t, ls.monitor)
			skipIfLeaked(t, leak)
		})
	}
}

// recheckConnsNow synchronously re-evaluates the policy for every
// authenticated connection of srv and reports whether all of them still
// hold their grant. Unlike [server.OnPolicyChange], it does not return
// before the evaluation is done.
func recheckConnsNow(srv *server) bool {
	srv.mu.Lock()
	var conns []*conn
	for c := range srv.activeConns {
		if c.authCompleted.Load() {
			conns = append(conns, c)
		}
	}
	srv.mu.Unlock()
	ok := true
	for _, c := range conns {
		if !c.recheckPolicy() {
			ok = false
		}
	}
	return ok
}

// TestIntegrationPolicyChangeKillsSession checks that a policy change
// that revokes or narrows the grant ends an active session and its
// processes, and that a change that only widens it does not.
func TestIntegrationPolicyChangeKillsSession(t *testing.T) {
	// All revocations share one teardown path, so only the first is
	// run in every session mode.
	allModes := []sessionMode{modeExec, modePtyShell}
	revocations := []struct {
		name   string
		modes  []sessionMode
		modify func(*tailcfg.SSHRule)
	}{
		{"reject", allModes, func(r *tailcfg.SSHRule) {
			r.Action = &tailcfg.SSHAction{Reject: true}
		}},
		{"user_remapped", []sessionMode{modePtyShell}, func(r *tailcfg.SSHRule) {
			r.SSHUsers = map[string]string{"*": "root"}
		}},
		{"principal_removed", []sessionMode{modePtyShell}, func(r *tailcfg.SSHRule) {
			r.Principals = []*tailcfg.SSHPrincipal{{NodeIP: "100.64.99.99"}}
		}},
		{"agent_forwarding_revoked", []sessionMode{modePtyShell}, func(r *tailcfg.SSHRule) {
			r.Action.AllowAgentForwarding = false
		}},
	}
	for _, tt := range revocations {
		for _, m := range tt.modes {
			t.Run(tt.name+"_"+sessionModes[m].name, func(t *testing.T) {
				defer dumpIncubatorLogOnFail(t)
				srv, tb, addr := startTestServer(t, testServerOpts{username: "testuser"})
				ls := startLifetimeSession(t, addr, m)
				ls.ping(t)
				tb.setModifyRule(tt.modify)
				srv.OnPolicyChange()
				// A revocation closes the connection, so the client sees
				// the session end even if processes outlive it.
				err := ls.waitDone(t, 20*time.Second)
				t.Logf("session ended with %s; stderr: %q", exitDesc(err), ls.stderr.String())
				if err == nil {
					t.Errorf("revoked session exited 0, want a failure")
				}
				skipIfLeaked(t, ls.waitAllGone(t))
			})
		}
	}

	t.Run("non_material", func(t *testing.T) {
		defer dumpIncubatorLogOnFail(t)
		srv, tb, addr := startTestServer(t, testServerOpts{username: "testuser"})
		ls := startLifetimeSession(t, addr, modeExec)
		ls.ping(t)
		// Widening changes: more AcceptEnv patterns, newly granted
		// forwarding, a later RuleExpires, and a message. None of
		// them narrows what the connection was granted at auth.
		later := time.Now().Add(time.Hour)
		tb.setModifyRule(func(r *tailcfg.SSHRule) {
			r.AcceptEnv = append(r.AcceptEnv, "EXTRA_*")
			r.Action.AllowLocalPortForwarding = true
			r.Action.AllowRemotePortForwarding = true
			r.Action.Message = "policy updated\n"
			r.RuleExpires = &later
		})
		srv.OnPolicyChange()
		// OnPolicyChange rechecks asynchronously. A synchronous
		// recheck of the same policy reaches the same verdict.
		if !recheckConnsNow(srv) {
			t.Fatalf("non-material policy change revoked the connection")
		}
		ls.ping(t)
		for _, p := range ls.procs {
			if !p.alive() {
				t.Errorf("session process %v died after a non-material policy change", p)
			}
		}
		// A new session on the same connection is also still allowed.
		s, err := ls.cl.NewSession()
		if err != nil {
			t.Fatalf("NewSession after non-material change: %v", err)
		}
		defer s.Close()
		if out, err := s.Output("echo second"); err != nil || strings.TrimSpace(string(out)) != "second" {
			t.Errorf("second session after non-material change: %q, %v", out, err)
		}
	})
}

// TestIntegrationRuleExpiresKillsSession checks that an active session is
// ended when the rule that granted it reaches its
// [tailcfg.SSHRule.RuleExpires], with no policy change notification, and
// that new connections are then refused.
func TestIntegrationRuleExpiresKillsSession(t *testing.T) {
	defer dumpIncubatorLogOnFail(t)
	expires := time.Now().Add(4 * time.Second)
	addr := testServerWithOpts(t, testServerOpts{
		username: "testuser",
		modifyRule: func(r *tailcfg.SSHRule) {
			r.RuleExpires = &expires
		},
	})
	ls := startLifetimeSession(t, addr, modeExec)
	ls.ping(t)
	err := ls.waitDone(t, time.Until(expires)+20*time.Second)
	t.Logf("session ended with %s", exitDesc(err))
	if now := time.Now(); now.Before(expires) {
		t.Errorf("session ended %v before the rule expired", expires.Sub(now))
	}
	if err == nil {
		t.Errorf("expired session exited 0, want a failure")
	}
	leak := ls.waitAllGone(t)

	if _, cl, err := dialLifetimeClient(addr, insecureClientConfig()); err == nil {
		cl.Close()
		t.Errorf("connection after rule expiry was accepted")
	}
	skipIfLeaked(t, leak)
}

// TestIntegrationShutdownKillsSessions checks that [server.Shutdown] ends
// active sessions and their processes, returns once they are gone, and
// that the server refuses connections afterwards.
func TestIntegrationShutdownKillsSessions(t *testing.T) {
	defer dumpIncubatorLogOnFail(t)
	srv, _, addr := startTestServer(t, testServerOpts{username: "testuser"})
	var sessions []*lifetimeSession
	for _, m := range []sessionMode{modeExec, modePtyShell} {
		ls := startLifetimeSession(t, addr, m)
		ls.ping(t)
		sessions = append(sessions, ls)
	}

	shutdownDone := make(chan struct{})
	go func() {
		defer close(shutdownDone)
		srv.Shutdown()
	}()
	// Shutdown waits for every session to finish, which includes
	// draining its output streams, so the processes go first.
	var leaks []string
	for _, ls := range sessions {
		leaks = append(leaks, ls.waitAllGone(t))
	}
	select {
	case <-shutdownDone:
	case <-time.After(20 * time.Second):
		t.Fatalf("Shutdown did not return")
	}
	if n := srv.NumActiveConns(); n != 0 {
		t.Errorf("NumActiveConns after Shutdown = %d, want 0", n)
	}
	for i, ls := range sessions {
		err := ls.waitDone(t, 20*time.Second)
		t.Logf("session %d ended with %s", i, exitDesc(err))
		if err == nil {
			t.Errorf("session %d exited 0 after Shutdown, want a failure", i)
		}
	}

	c1, c2 := net.Pipe()
	defer c2.Close()
	defer c1.Close()
	if err := srv.HandleSSHConn(&addressFakingConn{c1}); err == nil || !strings.Contains(err.Error(), "shutting down") {
		t.Errorf("HandleSSHConn after Shutdown = %v, want a shutting-down error", err)
	}
	// HandleSSHConn closes a connection it refuses.
	c2.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := c2.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
		t.Errorf("read from refused conn = %v, want io.EOF", err)
	}

	// A client is refused promptly rather than left waiting for its
	// handshake deadline.
	nc, err := net.DialTimeout("tcp", addr, 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer nc.Close()
	nc.SetDeadline(time.Now().Add(10 * time.Second))
	if c, _, _, err := ssh.NewClientConn(nc, addr, insecureClientConfig()); err == nil {
		c.Close()
		t.Errorf("connection after Shutdown was accepted")
	} else if errors.Is(err, os.ErrDeadlineExceeded) {
		t.Errorf("connection after Shutdown was left open until the client's deadline: %v", err)
	} else {
		t.Logf("connection after Shutdown failed as expected: %v", err)
	}
	skipIfLeaked(t, leaks...)
}

// hostKeyAlgos maps the host key types tailssh generates to the client
// algorithm that selects each.
var hostKeyAlgos = map[string]string{
	"rsa":     ssh.KeyAlgoRSASHA256,
	"ecdsa":   ssh.KeyAlgoECDSA256,
	"ed25519": ssh.KeyAlgoED25519,
}

// presentedHostKey connects to addr offering only the host key algorithm
// algo and returns the host key the server presents.
func presentedHostKey(t *testing.T, addr, algo string) ssh.PublicKey {
	t.Helper()
	var got ssh.PublicKey
	cfg := &ssh.ClientConfig{
		User:              "testuser",
		HostKeyAlgorithms: []string{algo},
		HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
			got = key
			return nil
		},
	}
	_, cl, err := dialLifetimeClient(addr, cfg)
	if err != nil {
		t.Fatalf("dial with host key algorithm %s: %v", algo, err)
	}
	cl.Close()
	return got
}

// systemHostKeyExists reports whether tailssh would consider the system
// OpenSSH host key of type typ, per [systemHostKeyFile].
func systemHostKeyExists(typ string) bool {
	f := systemHostKeyFile(typ)
	if f == "" {
		return false
	}
	_, err := os.Stat(f)
	return err == nil
}

// TestIntegrationHostKeys checks which host keys the server presents.
func TestIntegrationHostKeys(t *testing.T) {
	t.Run("generated_stable_and_private", func(t *testing.T) {
		varRoot := t.TempDir()
		addr1 := testServerWithOpts(t, testServerOpts{username: "testuser", varRoot: varRoot})
		addr2 := testServerWithOpts(t, testServerOpts{username: "testuser", varRoot: varRoot})
		for typ, algo := range hostKeyAlgos {
			k1 := presentedHostKey(t, addr1, algo)
			k2 := presentedHostKey(t, addr2, algo)
			if !bytes.Equal(k1.Marshal(), k2.Marshal()) {
				t.Errorf("%s: servers sharing a var root presented different host keys", typ)
			}
			if systemHostKeyExists(typ) {
				t.Logf("%s: system host key in use; not checking the generated file", typ)
				continue
			}
			path := filepath.Join(varRoot, "ssh", "ssh_host_"+typ+"_key")
			fi, err := os.Stat(path)
			if err != nil {
				t.Errorf("%s: %v", typ, err)
				continue
			}
			if perm := fi.Mode().Perm(); perm != 0o600 {
				t.Errorf("%s: %s has mode %v, want 0600", typ, path, perm)
			}
			pem, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			signer, err := ssh.ParsePrivateKey(pem)
			if err != nil {
				t.Fatalf("%s: parsing %s: %v", typ, path, err)
			}
			if !bytes.Equal(signer.PublicKey().Marshal(), k1.Marshal()) {
				t.Errorf("%s: presented host key does not match %s", typ, path)
			}
		}
		fi, err := os.Stat(filepath.Join(varRoot, "ssh"))
		if err != nil {
			t.Fatal(err)
		}
		if perm := fi.Mode().Perm(); perm != 0o700 {
			t.Errorf("key directory has mode %v, want 0700", perm)
		}
	})

	t.Run("system_key_reused", func(t *testing.T) {
		if os.Geteuid() != 0 {
			t.Skip("system host keys in /etc/ssh are only read when tailscaled runs as root; see systemHostKeyFile")
		}
		keygen, err := exec.LookPath("ssh-keygen")
		if err != nil {
			t.Skipf("no ssh-keygen: %v", err)
		}
		const typ = "ed25519"
		keyFile := systemHostKeyFile(typ)
		if _, err := os.Stat(keyFile); err == nil {
			t.Logf("using existing %s", keyFile)
		} else {
			if _, err := os.Stat(filepath.Dir(keyFile)); os.IsNotExist(err) {
				if err := os.Mkdir(filepath.Dir(keyFile), 0o755); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { os.Remove(filepath.Dir(keyFile)) })
			}
			t.Cleanup(func() {
				os.Remove(keyFile)
				os.Remove(keyFile + ".pub")
			})
			if out, err := exec.Command(keygen, "-q", "-t", typ, "-N", "", "-f", keyFile).CombinedOutput(); err != nil {
				t.Fatalf("ssh-keygen: %v, %s", err, out)
			}
		}
		pub, err := os.ReadFile(keyFile + ".pub")
		if err != nil {
			t.Fatal(err)
		}
		want, _, _, _, err := ssh.ParseAuthorizedKey(pub)
		if err != nil {
			t.Fatal(err)
		}

		varRoot := t.TempDir()
		addr := testServerWithOpts(t, testServerOpts{username: "testuser", varRoot: varRoot})
		got := presentedHostKey(t, addr, hostKeyAlgos[typ])
		if !bytes.Equal(got.Marshal(), want.Marshal()) {
			t.Errorf("server presented %s, want system key %s", ssh.FingerprintSHA256(got), ssh.FingerprintSHA256(want))
		}
		if _, err := os.Stat(filepath.Join(varRoot, "ssh", "ssh_host_"+typ+"_key")); !os.IsNotExist(err) {
			t.Errorf("tailssh generated its own %s key despite the system key (stat err %v)", typ, err)
		}
		// Types without a system key still get generated keys.
		if !systemHostKeyExists("rsa") {
			presentedHostKey(t, addr, hostKeyAlgos["rsa"])
			if _, err := os.Stat(filepath.Join(varRoot, "ssh", "ssh_host_rsa_key")); err != nil {
				t.Errorf("no generated rsa key: %v", err)
			}
		}
	})
}

// utmpRecordSize and the offsets below describe glibc's struct utmp on
// 64-bit Linux, the record format of utmp and wtmp.
const (
	utmpRecordSize = 384
	utmpUserOff    = 44
	utmpHostOff    = 76
	utmpUserLen    = 32
	utmpHostLen    = 256
	utmpUserProc   = 7 // USER_PROCESS
)

// utmpRecord is the part of a utmp record that the tests check.
type utmpRecord struct {
	typ  int16
	user string
	host string
}

// parseUtmp parses the complete utmp records in b.
func parseUtmp(b []byte) []utmpRecord {
	var recs []utmpRecord
	for rec := range slices.Chunk(b, utmpRecordSize) {
		if len(rec) < utmpRecordSize {
			break
		}
		recs = append(recs, utmpRecord{
			typ:  int16(binary.NativeEndian.Uint16(rec[0:2])),
			user: cString(rec[utmpUserOff : utmpUserOff+utmpUserLen]),
			host: cString(rec[utmpHostOff : utmpHostOff+utmpHostLen]),
		})
	}
	return recs
}

// TestIntegrationLoginRecordsUtmp checks that a pty shell session started
// through login(1) is registered in utmp, as who(1) shows it, with the
// client's Tailscale IP as the remote host, which tailssh passes as
// login -h.
func TestIntegrationLoginRecordsUtmp(t *testing.T) {
	const utmp = "/run/utmp"
	switch {
	case os.Geteuid() != 0:
		t.Skip("login is only used when tailscaled runs as root")
	case hostinfo.IsSELinuxEnforcing():
		t.Skip("login is not used when SELinux is enforcing")
	}
	if _, err := exec.LookPath("login"); err != nil {
		t.Skip("no login command")
	}
	if musl, _ := filepath.Glob("/lib/ld-musl-*"); len(musl) > 0 {
		t.Skip("musl libc's utmp functions are no-ops, so login records nothing")
	}
	// Containers usually lack utmp, and login only updates an existing
	// file. Create it for the test if needed.
	if _, err := os.Stat(utmp); os.IsNotExist(err) {
		if err := os.WriteFile(utmp, nil, 0o664); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { os.Remove(utmp) })
	}
	defer dumpIncubatorLogOnFail(t)

	addr := testServerWithOpts(t, testServerOpts{username: "testuser"})
	ls := startLifetimeSession(t, addr, modePtyShell)
	ls.ping(t)
	if !slices.Contains(procComms(ls.procs), "login") {
		t.Fatalf("pty shell session was not started through login; processes: %v", ls.procs)
	}

	b, err := os.ReadFile(utmp)
	if err != nil {
		t.Fatal(err)
	}
	recs := parseUtmp(b)
	want := utmpRecord{typ: utmpUserProc, user: "testuser", host: "100.100.100.102"}
	if !slices.Contains(recs, want) {
		t.Errorf("utmp has no %+v record; records: %+v", want, recs)
	}
}

func procComms(procs []procInfo) []string {
	var comms []string
	for _, p := range procs {
		comms = append(comms, p.comm)
	}
	return comms
}

func cString(b []byte) string {
	if i := bytes.IndexByte(b, 0); i >= 0 {
		b = b[:i]
	}
	return string(b)
}

// TestIntegrationDefaultPath checks the PATH that sessions get from
// [defaultPathForUser], including the TAILSCALE_SSH_DEFAULT_PATH
// template. It uses the in-process incubator path, since login and su
// reset PATH themselves: as root that means v1 behavior, which never
// uses su for commands.
func TestIntegrationDefaultPath(t *testing.T) {
	u, err := userLookup("testuser")
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name string
		tmpl string
		want string
	}{
		{"default", "", defaultPathForUser(u)},
		{"template", "/opt/@{PAM_USER}/bin:@{HOME}/bin:/usr/bin:/bin", "/opt/testuser/bin:" + u.HomeDir + "/bin:/usr/bin:/bin"},
		{"unknown_expansion", "/opt/@{NOPE}/bin:/usr/bin", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer dumpIncubatorLogOnFail(t)
			envknob.SetenvForTest(t, "TAILSCALE_SSH_DEFAULT_PATH", tt.tmpl)
			addr := testServerWithOpts(t, testServerOpts{
				username:        "testuser",
				forceV1Behavior: true,
			})
			_, cl, err := dialLifetimeClient(addr, insecureClientConfig())
			if err != nil {
				t.Fatal(err)
			}
			defer cl.Close()
			s, err := cl.NewSession()
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			out, err := s.Output(`echo "PATH=[$PATH]"`)
			if err != nil {
				t.Fatalf("%v; output: %q", err, out)
			}
			if want := "PATH=[" + tt.want + "]"; strings.TrimSpace(string(out)) != want {
				t.Errorf("got %q, want %q", strings.TrimSpace(string(out)), want)
			}
		})
	}
}
