// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build (linux && !android) || (darwin && !ios)

// Session-through-the-monitor tests: a real gliderssh session served by
// a real tailssh conn whose child is spawned by a real ssh-monitor
// process. Both are re-exec'd through the self-exec seams. The tests
// pin the exit-status wire ordering (exit-status before output before EOF) and
// the exit-notification plumbing on the new path.

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
	"os/exec"
	"os/user"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	gliderssh "github.com/tailscale/gliderssh"
	gossh "golang.org/x/crypto/ssh"
	"golang.org/x/sys/unix"
	"tailscale.com/tailcfg"
	"tailscale.com/tailcfg/nodecap"
	"tailscale.com/tstest"
)

// testIncubatorPrefix re-execs the test binary, selecting only the helper
// test, with the incubator's argv following "--" (the testing framework's
// flag parsing stops there). -test.timeout=0: the incubator child serves a
// full session, not a test with its own deadline. In tailscaled the argv
// prefix is "be-child ssh" (childproc dispatch); the monitor execs the
// prefix after the executable path.
var testIncubatorPrefix = []string{"-test.run=^TestSSHIncubatorHelperProcess$", "-test.timeout=0", "--", "ssh"}

// incubFdsDumpMarker gates the incubator's fd-table dump: only the
// session whose argv carries this marker, as INCUB-FDS-DUMP=<path>,
// dumps to <path>, so a concurrently live pty session is not confused
// with the assertion target. The path travels in the exec request's
// argv.
const incubFdsDumpMarker = "INCUB-FDS-DUMP"

// incubatorChildArgv shapes a test child's argv the way launchViaMonitor
// sends it: an incubator invocation, carrying the identity flags the
// monitor requires and rewrites to its spawn-bound identity. The values
// are placeholders; the monitor overwrites them, so these test children
// need not carry the real connection identity.
func incubatorChildArgv(argv []string) []string {
	return append(slices.Clone(argv),
		"--uid=1", "--gid=1", "--groups=1", "--local-user=test-user")
}

// incubDumpArg extracts the INCUB-FDS-DUMP=<path> dump target from the
// incubator's argv, or returns "".
func incubDumpArg(args []string) string {
	prefix := incubFdsDumpMarker + "="
	joined := strings.Join(args, " ")
	i := strings.Index(joined, prefix)
	if i < 0 {
		return ""
	}
	rest := joined[i+len(prefix):]
	if j := strings.IndexAny(rest, " \"'\t\r\n"); j >= 0 {
		rest = rest[:j]
	}
	return rest
}

// TestSSHIncubatorHelperProcess is not a test; it is the entry point
// of the re-exec'd session child, the incubator. It acts only when the
// binary is exec'd with the prefix above, and returns immediately
// otherwise.
func TestSSHIncubatorHelperProcess(t *testing.T) {
	for i, a := range os.Args {
		if a == "--" && i+2 < len(os.Args) && os.Args[i+1] == "ssh" {
			// Declared-fds pin for the session child: when this
			// child's argv carries the marker, dump the exec-inherited
			// fd table (stdio, the --env-fd pipe at 3) before the
			// incubator starts.
			if path := incubDumpArg(os.Args[i+2:]); path != "" {
				dumpChildFdsTo(path, "incubator")
			}
			if err := beIncubator(os.Args[i+2:]); err != nil {
				fmt.Fprintln(os.Stderr, "ssh incubator child:", err)
				os.Exit(1)
			}
			// beIncubator exec'd away (login/su) or ran the command
			// in-process; handleSSHInProcess exits with the child's code.
			os.Exit(0)
		}
	}
}

// monitorSessionSeams routes the monitor and incubator spawns to the
// self-exec helper tests and returns nothing. Cleanup restores both.
func monitorSessionSeams(t *testing.T) {
	t.Helper()
	oldMon, oldInc := monitorSpawnPrefix, incubatorSpawnPrefix
	monitorSpawnPrefix = testMonitorPrefix
	incubatorSpawnPrefix = testIncubatorPrefix
	t.Cleanup(func() { monitorSpawnPrefix, incubatorSpawnPrefix = oldMon, oldInc })
}

// newMonitorSessionServer is newMonitorSessionServerFor with the
// existing defaults: the current local user, the SSHBehaviorV1 cap, no
// policy grant (sessions only; the Handler bypasses the recheck gates),
// and no forwarding seams.
func newMonitorSessionServer(t *testing.T, handler func(c *conn, s gliderssh.Session)) string {
	t.Helper()
	return newMonitorSessionServerFor(t, nil, nil, nil, false, handler)
}

// newMonitorSessionServerFor is newMonitorSessionServer with the conn's
// bound identity, node caps, policy grant, and forwarding seams
// parametrized, for the fd-isolation tests (the PTY-master leak
// regression) and the fwd-child declared-fds pin:
//
//   - lu: the conn's local user; nil = the current user (the default
//     above). Under root runs the fd-isolation tests bind the conn to the
//     non-root sshfwda test user, so the session children run as a
//     different uid than the pty-holding test process, the cross-user
//     shape of the original injection scenario.
//   - caps: node caps; nil = [SSHBehaviorV1] (the V1 pin also keeps the
//     incubator on the in-process branch: no login/su, no PAM).
//   - rule: lb.matchingRule, the policy grant whose action and accept-env
//     latching the conn uses for the forwarding gates' recheckPolicy
//     (AllowLocalPortForwarding for a unix -L dial through this conn);
//     nil = none (sessions only).
//   - fwdSeams: route the conn's one-shot fwd children through the
//     re-exec'd helper (the seam env crossing the exec boundary into
//     the monitor process).
//
// handler serves each session channel; it receives the owning conn so it
// can call conn.newSSHSession(...).run().
func newMonitorSessionServerFor(
	t *testing.T,
	lu *userMeta,
	caps []nodecap.Cap,
	rule *tailcfg.SSHRule,
	fwdSeams bool,
	handler func(c *conn, s gliderssh.Session),
) string {
	t.Helper()
	if lu == nil {
		u, err := user.Current()
		if err != nil {
			t.Fatal(err)
		}
		lu, err = userLookup(u.Username)
		if err != nil {
			t.Fatal(err)
		}
	}
	if caps == nil {
		caps = []nodecap.Cap{nodecap.SSHBehaviorV1}
	}
	monitorSessionSeams(t)
	// The session children are exec'd from tailscaledPath by the root
	// monitor, and the fwd children (fwdSeams) run as the bound user:
	// both need the reachable copy of the test binary under a root run.
	exe := makeExecutableReachable(t)
	if fwdSeams {
		t.Setenv("TS_TEST_SSH_FWD_PREFIX", strings.Join(testFwdPrefix, " "))
	}
	if rule != nil && rule.SSHUsers["test"] == "" {
		rule.SSHUsers["test"] = lu.Username
	}
	logf := tstest.WhileTestRunningLogger(t)

	srv := &server{
		lb: &localState{
			sshEnabled:   true,
			varRoot:      t.TempDir(),
			caps:         caps,
			matchingRule: rule,
		},
		logf:           logf,
		tailscaledPath: exe,
	}
	sc, err := srv.newConn()
	if err != nil {
		t.Fatal(err)
	}
	// Tear the conn's monitor down with the conn (HandleConn is driven
	// directly below, so HandleSSHConn's teardown does not run).
	t.Cleanup(sc.closeFwdMonitor)

	sc.insecureSkipTailscaleAuth = true

	um, err := userLookup(lu.Username)
	if err != nil {
		t.Fatal(err)
	}
	// /bin/sh: a predictable direct child of the incubator.
	um.loginShellCached = "/bin/sh"
	sc.localUser = um
	// The bound user's groups, like clientAuth would have captured them
	// (the incubator argv's --groups must be non-empty): for a conn bound
	// to another uid use that user's own primary group, not the test
	// process's (root-run) groups.
	if um.Uid == strconv.Itoa(os.Getuid()) {
		for _, g := range testGroups(t) {
			sc.userGroupIDs = append(sc.userGroupIDs, strconv.Itoa(g))
		}
	} else {
		sc.userGroupIDs = []string{um.Gid}
	}
	sc.info = &sshConnInfo{
		sshUser: "test",
		src:     netip.MustParseAddrPort("1.2.3.4:32342"),
		dst:     netip.MustParseAddrPort("1.2.3.5:22"),
		node:    (&tailcfg.Node{}).View(),
		uprof:   tailcfg.UserProfile{},
	}
	action := &tailcfg.SSHAction{Accept: true}
	if rule != nil {
		action = rule.Action
		sc.acceptEnv = rule.AcceptEnv
		// The fwd gates' recheckPolicy paths need Principals to match the
		// synthetic conn info (any principal, like the fwd conn tests).
		if len(rule.Principals) == 0 {
			rule.Principals = []*tailcfg.SSHPrincipal{{Any: true}}
		}
	}
	sc.action0 = action
	sc.finalAction = action
	sc.authCompleted.Store(true)
	sc.Handler = func(s gliderssh.Session) {
		handler(sc, s)
	}

	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go sc.HandleConn(c)
		}
	}()
	return ln.Addr().String()
}

// TestSessionMonitorExitStatusOrder is the monitor-path version of
// TestExitStatusPrecedesEOF: a session whose child is exec'd by the
// per-connection ssh-monitor must keep the teardown wire order
// (exit-status, remaining output, EOF, CHANNEL_CLOSE) even though the
// child's exit arrives as an async monitor notification instead of
// cmd.Wait. The child produces output on both streams and exits 7; the
// client must see the output and the exit status, in that order.
func TestSessionMonitorExitStatusOrder(t *testing.T) {
	recCh := make(chan *frameRecorder, 1)
	addr := newMonitorSessionServer(t, func(c *conn, s gliderssh.Session) {
		rec := &frameRecorder{Session: s}
		select {
		case recCh <- rec:
		default:
		}
		c.newSSHSession(rec).run()
	})

	cl, err := gossh.Dial("tcp", addr, &gossh.ClientConfig{
		HostKeyCallback: gossh.InsecureIgnoreHostKey(),
		Timeout:         15 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer cl.Close()
	s, err := cl.NewSession()
	if err != nil {
		t.Fatal(err)
	}

	// Separate buffers: the client serves stdout and stderr from distinct
	// goroutines, so they must not share an unsynchronized writer.
	var stdout, stderr bytes.Buffer
	s.Stdout = &stdout
	s.Stderr = &stderr
	err = s.Run("echo out; echo err 1>&2; exit 7")
	var ee *gossh.ExitError
	if !errors.As(err, &ee) {
		t.Fatalf("want *gossh.ExitError, got %T: %v", err, err)
	}
	if got := ee.ExitStatus(); got != 7 {
		t.Fatalf("exit status = %d, want 7", got)
	}
	// The session's output must have arrived before the teardown frames.
	if got, want := stdout.String(), "out\n"; got != want {
		t.Errorf("session stdout = %q; want %q", got, want)
	}
	if got, want := stderr.String(), "err\n"; got != want {
		t.Errorf("session stderr = %q; want %q", got, want)
	}

	var rec *frameRecorder
	select {
	case rec = <-recCh:
	case <-time.After(10 * time.Second):
		t.Fatal("session never started")
	}
	var got []string
	if err := tstest.WaitFor(5*time.Second, func() error {
		got = rec.got()
		if len(got) < 3 {
			return errNotAllFrames
		}
		return nil
	}); err != nil {
		t.Fatalf("only saw frames %v, want 3", got)
	}
	want := []string{"exit-status", "eof", "close"}
	if !slices.Equal(got, want) {
		t.Errorf("frame order = %v, want %v", got, want)
	}
}

// TestSessionMonitorPTY drives a pty session through the monitor: the
// slave fds travel to the monitor via SCM_RIGHTS, the monitor applies
// Setsid+Setctty (slave as fd 0), and the client's window-change requests
// are applied by the resizeWindow goroutine's own master descriptor. The
// client requests a pty at 10x40, the child reports its size, then the
// window is changed to 24x80 and the child reports the new size, pinning
// the resize path end to end, and the exit status is delivered.
func TestSessionMonitorPTY(t *testing.T) {
	addr := newMonitorSessionServer(t, func(c *conn, s gliderssh.Session) {
		c.newSSHSession(s).run()
	})

	cl, err := gossh.Dial("tcp", addr, &gossh.ClientConfig{
		HostKeyCallback: gossh.InsecureIgnoreHostKey(),
		Timeout:         15 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer cl.Close()
	s, err := cl.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := s.RequestPty("xterm", 10, 40, gossh.TerminalModes{gossh.ECHO: 0}); err != nil {
		t.Fatal(err)
	}
	stdin, err := s.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	deadlineTimer := time.AfterFunc(15*time.Second, func() { cl.Close() })
	defer deadlineTimer.Stop()

	// stdout is served by a client goroutine; guard the buffer.
	var out sessTestBuffer
	s.Stdout = &out
	s.Stderr = &out
	const command = `
stty size
read ready
while [ "$(stty size)" != "24 80" ]; do
	sleep 0.05
done
stty size
exit 3
`
	if err := s.Start(command); err != nil {
		t.Fatal(err)
	}

	// Wait until the first stty ran: the pty is up and resizeWindow is
	// draining window changes (gliderssh's winch channel is buffered
	// at one).
	deadline := time.Now().Add(10 * time.Second)
	for !strings.Contains(out.String(), "10 40") {
		if time.Now().After(deadline) {
			t.Fatalf("no initial stty output; got %q", out.String())
		}
		time.Sleep(50 * time.Millisecond)
	}

	// The window change must be applied to THIS session's master (the
	// resize goroutine's own descriptor) and be observable
	// to the child.
	if err := s.WindowChange(24, 80); err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(stdin, "ready\n"); err != nil {
		t.Fatal(err)
	}

	err = s.Wait()
	var ee *gossh.ExitError
	if !errors.As(err, &ee) {
		t.Fatalf("want *gossh.ExitError, got %T: %v", err, err)
	}
	if got := ee.ExitStatus(); got != 3 {
		t.Fatalf("exit status = %d, want 3", got)
	}
	// "rows cols" per stty(1): first the requested 10x40, then 24x80
	// after the window change.
	if got, want := strings.Fields(out.String()), []string{"10", "40", "24", "80"}; !slices.Equal(got, want) {
		t.Errorf("stty size outputs = %q; want %q", got, want)
	}
}

// TestSessionMonitorConnCloseKillsHupImmuneChild pins the teardown
// escalation on the conn-close paths, revocation, Shutdown, and plain
// teardown: the monitor's own teardown must SIGKILL the HUP-immune
// group, in both orderings of the session's own HUP escalation against
// the conn teardown (kick-then-close and close-without-kick).
func TestSessionMonitorConnCloseKillsHupImmuneChild(t *testing.T) {
	for _, mode := range []string{"kick-then-close", "close-without-kick"} {
		t.Run(mode, func(t *testing.T) {
			lu := fwdTestIdentity(t)
			c := newFwdTestConn(t, lu, &tailcfg.SSHAction{Accept: true})
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			ss := &sshSession{
				ctx:  ctx,
				conn: c,
				logf: t.Logf,
			}

			// An HUP-immune child, like TestSessionMonitorHangupEscalation:
			// sh traps (ignores) SIGHUP, so only the group SIGKILL ends it.
			// The marker gates on the trap being installed.
			cmd := exec.Command("/bin/sh", "-c", "trap '' HUP; echo ready; while :; do sleep 1; done")
			cmd.Args = incubatorChildArgv(cmd.Args)
			stdin, stdinKeep, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			defer stdinKeep.Close()
			stdout, stdoutW, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			defer stdout.Close()
			stderr, stderrW, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			defer stderr.Close()
			if err := ss.launchViaMonitor(cmd, nil, []*os.File{stdin, stdoutW, stderrW}, false); err != nil {
				t.Fatalf("launchViaMonitor: %v", err)
			}
			stdoutW.Close()
			stderrW.Close()
			if err := stdout.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
				t.Fatal(err)
			}
			marker := make([]byte, len("ready\n"))
			if _, err := io.ReadFull(stdout, marker); err != nil {
				t.Fatalf("reading ready marker: %v", err)
			}
			if string(marker) != "ready\n" {
				t.Fatalf("child output = %q; want ready (the HUP trap is installed)", marker)
			}
			pid := ss.monChild.PID

			if mode == "kick-then-close" {
				// The revocation kick (what killProcessOnContextDone does
				// when the session ctx is canceled); its escalation timer
				// races the conn teardown, which closes the monitor.
				ss.hangupMonitorProcess()
			}
			// The conn teardown: every conn-close path funnels here
			// (HandleSSHConn's deferred closeFwdMonitor). Close waits for
			// the monitor to exit, so on return the teardown sweeps
			// (HUP, then SIGKILL for survivors) have run.
			c.closeFwdMonitor()

			// The child must be dead and reaped by the monitor's own
			// teardown: signal 0 returns ESRCH once the monitor has reaped
			// it. Bound: the teardown's two sweeps (≤2s each) inside
			// Close's 5s monitor-exit wait, plus slack.
			deadline := time.Now().Add(monTeardownReap*2 + 5*time.Second)
			for {
				if err := unix.Kill(pid, 0); err != nil {
					return // reaped and gone
				}
				if time.Now().After(deadline) {
					t.Fatalf("HUP-immune child %d survived monitor teardown", pid)
				}
				time.Sleep(100 * time.Millisecond)
			}
		})
	}
}

// TestSessionMonitorTeardownKillsSamePgidStraggler pins the teardown
// SIGKILL's scope: a HUP-immune member of the session child's own
// process group whose leader dies to the teardown SIGHUP must be
// killed via the pgid set snapshot taken at teardown entry, not via
// surviving table entries.
func TestSessionMonitorTeardownKillsSamePgidStraggler(t *testing.T) {
	lu := fwdTestIdentity(t)
	c := newFwdTestConn(t, lu, &tailcfg.SSHAction{Accept: true})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ss := &sshSession{
		ctx:  ctx,
		conn: c,
		logf: t.Logf,
	}

	// The leader (sh) dies to the group SIGHUP. The nohup'd member of
	// its group ignores HUP (nohup's SIG_IGN survives exec) and would
	// survive the teardown under the entry-keyed SIGKILL: the first reap
	// sweep reaps the leader and drops the table entry, so only the
	// snapshot pgid set still names the group. The inner sh prints its
	// own pid first so the test can watch it.
	cmd := exec.Command("/bin/sh", "-c",
		"nohup sh -c 'echo $$; exec sleep 300' & echo ready; wait")
	cmd.Args = incubatorChildArgv(cmd.Args)
	stdin, stdinKeep, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer stdinKeep.Close()
	stdout, stdoutW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer stdout.Close()
	stderr, stderrW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer stderr.Close()
	if err := ss.launchViaMonitor(cmd, nil, []*os.File{stdin, stdoutW, stderrW}, false); err != nil {
		t.Fatalf("launchViaMonitor: %v", err)
	}
	stdoutW.Close()
	stderrW.Close()
	if err := stdout.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatal(err)
	}
	// Read until both markers arrived: "ready" (the leader is running)
	// and the straggler's pid line (the nohup'd member is up).
	straggler := 0
	sawReady := false
	var buf []byte
	deadline := time.Now().Add(10 * time.Second)
	for !(sawReady && straggler != 0) {
		if time.Now().After(deadline) {
			t.Fatalf("child markers never arrived; got %q", buf)
		}
		chunk := make([]byte, 256)
		n, err := stdout.Read(chunk)
		if n > 0 {
			buf = append(buf, chunk[:n]...)
		}
		if err != nil && !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatalf("reading child output: %v", err)
		}
		for _, line := range strings.Fields(string(buf)) {
			if line == "ready" {
				sawReady = true
			}
			if p, err := strconv.Atoi(line); err == nil && p > 1 {
				straggler = p
			}
		}
	}

	// The conn teardown: closeFwdMonitor runs the monitor's teardown,
	// group SIGHUP (kills the leader, sweep reaps it, entry dropped),
	// then the SIGKILL pass over the snapshot pgid set.
	c.closeFwdMonitor()

	// The straggler must be dead and gone. Bound: the teardown's two
	// sweeps (≤2s each) inside Close's 5s monitor-exit wait, plus slack.
	// A killed straggler whose parent is gone can linger as a zombie
	// adopted by a PID 1 that does not reap (the privileged CI
	// container); kill(pid, 0) succeeds for zombies, so liveness is
	// checked through the /proc state on linux, where a Z state counts
	// as gone. Elsewhere the adopter reaps promptly and kill(pid, 0)
	// suffices.
	deadline = time.Now().Add(monTeardownReap*2 + 5*time.Second)
	for {
		if pidGone(straggler) {
			return // reaped and gone (or a reaped-pending zombie)
		}
		if time.Now().After(deadline) {
			t.Fatalf("HUP-immune group member %d survived monitor teardown", straggler)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// pidGone reports whether pid no longer names a live process. On linux
// it reads /proc: a missing entry or a zombie (state Z) means gone.
// Elsewhere kill(pid, 0) is the check; the platforms in this file's
// build tag reap orphans promptly, so a lingering zombie is not
// expected there.
func pidGone(pid int) bool {
	if runtime.GOOS == "linux" {
		b, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
		if err != nil {
			return true // gone
		}
		// The state field follows the comm field, which may contain
		// spaces and parentheses; take the field after the last ')'.
		i := bytes.LastIndexByte(b, ')')
		if i < 0 || i+2 >= len(b) {
			return false
		}
		return b[i+2] == 'Z'
	}
	return unix.Kill(pid, 0) != nil
}

// TestWaitMonitorProcessExitNotificationWins checks priority and repeatable
// reads when exit and monitor death occur before or during the wait.
func TestWaitMonitorProcessExitNotificationWins(t *testing.T) {
	for i := range 100 {
		dead := make(chan struct{})
		exit := newMonExitStatus()
		notify := func() {
			exit.complete(42)
			close(dead)
		}
		if i%2 == 0 {
			notify()
		} else {
			go notify()
		}
		ss := &sshSession{monExit: exit, monDead: dead}
		for range 2 {
			code, ok, err := ss.waitMonitorProcess()
			if !ok || err != nil || code != 42 {
				t.Fatalf("waitMonitorProcess = (%d, %v, %v); want (42, true, nil)", code, ok, err)
			}
		}
	}
}

// TestSessionPtyTermWiring pins the pty TERM wiring: a pty request
// whose TERM fails acceptEnvPair's value rule is dropped, and a valid
// environ-sourced TERM survives the pty request.
func TestSessionPtyTermWiring(t *testing.T) {
	addr := newMonitorSessionServer(t, func(c *conn, s gliderssh.Session) {
		c.newSSHSession(s).run()
	})

	// The echo rides behind a leading sleep and is read through a poll
	// loop (the shape TestSessionMonitorPTY uses): output written while
	// the pty's termios is still settling races the capture.
	check := func(setTermEnv bool) string {
		t.Helper()
		cl, err := gossh.Dial("tcp", addr, &gossh.ClientConfig{
			HostKeyCallback: gossh.InsecureIgnoreHostKey(),
			Timeout:         15 * time.Second,
		})
		if err != nil {
			t.Fatal(err)
		}
		defer cl.Close()
		s, err := cl.NewSession()
		if err != nil {
			t.Fatal(err)
		}
		defer s.Close()
		if setTermEnv {
			// A valid environ-sourced TERM: accepted by acceptEnvPair's
			// value rule and placed in the incubator env by incubatorEnv.
			if err := s.Setenv("TERM", "dumb"); err != nil {
				t.Fatal(err)
			}
		}
		// A pty TERM that is a path: rejected by the value rule, dropped.
		if err := s.RequestPty("x/bad-term", 24, 80, gossh.TerminalModes{}); err != nil {
			t.Fatal(err)
		}
		var out sessTestBuffer
		s.Stdout = &out
		s.Stderr = &out
		if err := s.Start(`sleep 1; echo "TERM=${TERM-unset}"; exit 3`); err != nil {
			t.Fatal(err)
		}
		deadline := time.Now().Add(10 * time.Second)
		for !strings.Contains(out.String(), "TERM=") {
			if time.Now().After(deadline) {
				t.Fatalf("no TERM line from the child; got %q", out.String())
			}
			time.Sleep(50 * time.Millisecond)
		}
		err = s.Wait()
		var ee *gossh.ExitError
		if !errors.As(err, &ee) || ee.ExitStatus() != 3 {
			t.Fatalf("session Wait = %v; want exit status 3", err)
		}
		return out.String()
	}

	// No environ TERM: the bad pty TERM is dropped, so the child has no
	// TERM from us (not the bad value, not a sanitized one). What the
	// child's shell then does with an absent TERM is the shell's own
	// business: macOS's /bin/sh (bash 3.2) initializes TERM=dumb itself
	// when the environment lacks one, while other shells leave it unset.
	// The pinned invariant is the absence of the rejected value.
	wantDropped := "x/bad-term"
	wantLine := "TERM=unset\r"
	if runtime.GOOS == "darwin" {
		wantLine = "TERM=dumb\r" // /bin/sh initializes it; see above
	}
	if got := check(false); strings.Contains(got, wantDropped) || !strings.Contains(got, wantLine) {
		t.Errorf("child TERM after rejecting PTY TERM = %q; want %q", got, wantLine)
	}
	// A valid environ-sourced TERM is not overridden by the bad pty TERM
	// (the old last-wins inversion).
	if got := check(true); !strings.Contains(got, "TERM=dumb\r") {
		t.Errorf("child TERM after rejecting PTY TERM = %q; want TERM=dumb", got)
	}
}

// sessTestBuffer is a concurrency-safe bytes.Buffer: the client serves
// stdout and stderr from distinct goroutines (the integration-tagged suite
// has its own lockedBuffer; this one is local to the monitor session tests).
type sessTestBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (out *sessTestBuffer) Write(p []byte) (int, error) {
	out.mu.Lock()
	defer out.mu.Unlock()
	return out.b.Write(p)
}

func (out *sessTestBuffer) String() string {
	out.mu.Lock()
	defer out.mu.Unlock()
	return out.b.String()
}

// TestSessionMonitorHangupEscalation pins the teardown escalation: a
// session child group that survives the teardown SIGHUP is SIGKILLed
// after hangupEscalation, and its exit code is 128+SIGKILL, the shell
// convention.
func TestSessionMonitorHangupEscalation(t *testing.T) {
	lu := fwdTestIdentity(t)
	c := newFwdTestConn(t, lu, &tailcfg.SSHAction{Accept: true})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ss := &sshSession{
		ctx:  ctx,
		conn: c,
		logf: t.Logf,
	}

	// An HUP-immune child: sh traps (ignores) SIGHUP and its own children
	// re-spawn, so only the group SIGKILL ends it. The marker gates the
	// hangup on the trap being installed.
	cmd := exec.Command("/bin/sh", "-c", "trap '' HUP; echo ready; while :; do sleep 1; done")
	cmd.Args = incubatorChildArgv(cmd.Args)
	stdin, stdinKeep, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer stdinKeep.Close()
	stdout, stdoutW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer stdout.Close()
	stderr, stderrW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer stderr.Close()
	if err := ss.launchViaMonitor(cmd, nil, []*os.File{stdin, stdoutW, stderrW}, false); err != nil {
		t.Fatalf("launchViaMonitor: %v", err)
	}
	stdoutW.Close()
	stderrW.Close()
	// Read just the marker (the child never exits, so no EOF read here).
	if err := stdout.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	marker := make([]byte, len("ready\n"))
	if _, err := io.ReadFull(stdout, marker); err != nil {
		t.Fatalf("reading ready marker: %v", err)
	}
	if string(marker) != "ready\n" {
		t.Fatalf("child output = %q; want ready (the HUP trap is installed)", marker)
	}

	ss.hangupMonitorProcess()

	// The child must die via the SIGKILL escalation (128+9) within the
	// escalation window plus slack.
	deadline := time.Now().Add(hangupEscalation + 5*time.Second)
	for {
		select {
		case <-ss.monExit.done:
			code := ss.monExit.code
			if want := 128 + int(unix.SIGKILL); code != want {
				t.Fatalf("exit code = %d, want %d (128+SIGKILL)", code, want)
			}
			return
		case <-time.After(100 * time.Millisecond):
			if time.Now().After(deadline) {
				t.Fatalf("child survived SIGHUP by %v", hangupEscalation+5*time.Second)
			}
		}
	}
}

// TestLaunchViaMonitorRefusesCanceledContext pins the pre-flight ctx
// refusal at the top of launchViaMonitor: a session whose ctx is
// already canceled must refuse the launch before the exec op is
// written, without spawning a monitor to do it.
func TestLaunchViaMonitorRefusesCanceledContext(t *testing.T) {
	lu := fwdTestIdentity(t)
	c := newFwdTestConn(t, lu, &tailcfg.SSHAction{Accept: true})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	ss := &sshSession{
		ctx:  ctx,
		conn: c,
		logf: t.Logf,
	}

	stdin, stdinKeep, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer stdinKeep.Close()
	stdout, stdoutW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer stdout.Close()
	stderr, stderrW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer stderr.Close()
	cmd := exec.Command("/bin/sh", "-c", "echo doomed; sleep 30")
	cmd.Args = incubatorChildArgv(cmd.Args)
	err = ss.launchViaMonitor(cmd, nil, []*os.File{stdin, stdoutW, stderrW}, false)
	stdoutW.Close()
	stderrW.Close()
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("launchViaMonitor = %v; want context.Canceled", err)
	}
	if mc := c.fwdMonitorIfAny(); mc != nil {
		t.Fatal("launchViaMonitor spawned a monitor for a canceled session")
	}
}

// TestHangupMonitorProcessAfterMonitorClosed checks that teardown neither
// recreates the monitor nor signals an unrelated process with a reused PID.
func TestHangupMonitorProcessAfterMonitorClosed(t *testing.T) {
	lu := fwdTestIdentity(t)
	c := newFwdTestConn(t, lu, &tailcfg.SSHAction{Accept: true})
	if _, err := c.fwdMonitor(); err != nil {
		t.Fatal(err)
	}
	c.closeFwdMonitor()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "cat")
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	cmd.Stdout = &output
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		cmd.Process.Kill()
		cmd.Wait()
	}()
	ss := &sshSession{
		ctx:      ctx,
		conn:     c,
		logf:     t.Logf,
		monChild: monitorProcess{PID: cmd.Process.Pid, ID: 1},
	}
	if !ss.hangupMonitorProcess() {
		t.Fatal("monitor session took the direct hangup path")
	}
	if got := c.fwdMonitorIfAny(); got != nil {
		t.Fatal("hangup recreated a closed monitor")
	}
	if _, err := io.WriteString(stdin, "alive\n"); err != nil {
		t.Fatal(err)
	}
	stdin.Close()
	if err := cmd.Wait(); err != nil {
		t.Fatalf("unrelated process was signaled: %v", err)
	}
	if output.String() != "alive\n" {
		t.Fatalf("unrelated process output = %q", output.String())
	}
}
