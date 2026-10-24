// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build (linux && !android) || (darwin && !ios) || freebsd || openbsd

// Tests for the ssh-monitor process and its client. They drive a
// real monitor child. spawnMonitor re-exec's the current test binary
// through the monitorSpawnPrefix seam, and the helper test below
// dispatches to beMonitor, the same child dispatch
// "tailscaled be-child ssh-monitor" performs in production, minus
// cmd/tailscaled's beChild layer.

package tailssh

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// testMonitorPrefix re-execs the test binary, selecting only the helper
// test, with the monitor's argv following "--", where the testing
// framework's flag parsing stops. -test.timeout=0 because the monitor
// child is a long-lived process, not a test with its own deadline.
var testMonitorPrefix = []string{"-test.run=^TestSSHMonitorHelperProcess$", "-test.timeout=0", "--", "ssh-monitor"}

// TestSSHMonitorHelperProcess is not a test. It is the entry point of
// the re-exec'd monitor child process. It only acts when the binary is
// exec'd with the prefix above. In a normal test run there is no "--"
// in os.Args and it returns immediately.
func TestSSHMonitorHelperProcess(t *testing.T) {
	var args []string
	for i, a := range os.Args {
		if a == "--" && i+2 < len(os.Args) && os.Args[i+1] == "ssh-monitor" {
			args = os.Args[i+2:]
			break
		}
	}
	if args == nil {
		return
	}
	if err := beMonitor(args); err != nil {
		fmt.Fprintln(os.Stderr, "ssh-monitor child:", err)
		os.Exit(1)
	}
	// RPC-EOF teardown completed. Exit cleanly, like the real be-child.
	os.Exit(0)
}

// startTestMonitor spawns a real monitor child bound to the given identity
// and registers cleanup that closes it, idempotent with an explicit
// Close.
func startTestMonitor(t *testing.T, uid, gid int, groups []int) *monitorClient {
	t.Helper()
	old := monitorSpawnPrefix
	monitorSpawnPrefix = testMonitorPrefix
	t.Cleanup(func() { monitorSpawnPrefix = old })
	mc, err := spawnMonitor(monitorExe(t), uint32(uid), uint32(gid), intToU32s(groups), "testuser")
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

// intToU32s widens a group list to the 32-bit ABI form the monitor's
// identity carries. Test identities come from os.Getgroups, which is
// int-typed.
func intToU32s(gids []int) []uint32 {
	out := make([]uint32, len(gids))
	for i, g := range gids {
		out[i] = uint32(g)
	}
	return out
}

func testGroups(t *testing.T) []int {
	t.Helper()
	g, err := os.Getgroups()
	if err != nil {
		t.Fatalf("os.Getgroups: %v", err)
	}
	return g
}

func testCtx() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), 10*time.Second)
}

// trueExe returns an absolute path to a true binary for monitor
// children, which require an absolute argv[0]. macOS has no /bin/true;
// it ships the binary only in /usr/bin.
func trueExe(t *testing.T) string {
	t.Helper()
	p, err := exec.LookPath("true")
	if err != nil {
		t.Skipf("no true binary on PATH: %v", err)
	}
	return p
}

type exitNote struct {
	pid  monitorProcess
	code int
}

// collectExits registers an exit callback that appends to a buffered
// channel, so the monitor's reader goroutine never blocks delivering a
// notification.
func collectExits(mc *monitorClient) chan exitNote {
	ch := make(chan exitNote, 8)
	mc.SetExitCallback(func(pid monitorProcess, code int) { ch <- exitNote{pid, code} })
	return ch
}

// readAllWithDeadline reads f to EOF under a read deadline. The timeout
// surfaces as t.Fatal rather than a hang.
func readAllWithDeadline(t *testing.T, f *os.File, timeout time.Duration) string {
	t.Helper()
	if err := f.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	defer f.SetReadDeadline(time.Time{})
	var sb strings.Builder
	buf := make([]byte, 4096)
	for {
		n, err := f.Read(buf)
		sb.Write(buf[:n])
		if err == io.EOF {
			return sb.String()
		}
		if err != nil {
			t.Fatalf("read %s: %v", f.Name(), err)
		}
	}
}

// runChild execs argv on the monitor with the given env, passes pipes as
// the child's stdio, and returns the child's stdout, fully drained
// until EOF so the child must exit.
func runChild(t *testing.T, mc *monitorClient, argv, env []string) string {
	t.Helper()
	// stdin: read end handed to the child. Nothing is written to it.
	stdin, stdinKeep, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer stdinKeep.Close()
	stdout, stdoutW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	stderr, stderrW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := testCtx()
	defer cancel()
	pid, err := mc.Exec(ctx, argv, env, "/", false, nil, stdin, stdoutW, stderrW)
	if err != nil {
		t.Fatalf("exec %v: %v", argv, err)
	}
	if pid.PID <= 0 {
		t.Fatalf("exec %v: pid %v, want > 0", argv, pid)
	}
	// The monitor closed its copies. Drop ours so reads see EOF once the
	// child exits.
	stdoutW.Close()
	stderrW.Close()
	out := readAllWithDeadline(t, stdout, 5*time.Second)
	if e := readAllWithDeadline(t, stderr, 5*time.Second); e != "" {
		t.Logf("child %v stderr: %s", argv, e)
	}
	stdout.Close()
	stderr.Close()
	return out
}

func waitExitNote(t *testing.T, ch chan exitNote, timeout time.Duration) exitNote {
	t.Helper()
	select {
	case n := <-ch:
		return n
	case <-time.After(timeout):
		t.Fatalf("no exit notification within %v", timeout)
		return exitNote{}
	}
}

// waitExitNoteAny waits for a notification on any of the channels. The
// delivery time, not the subscription time, decides which callback
// receives it.
func waitExitNoteAny(t *testing.T, timeout time.Duration, chs ...chan exitNote) exitNote {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		for _, ch := range chs {
			select {
			case n := <-ch:
				return n
			default:
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("no exit notification within %v", timeout)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestMonitorPingRoundTrip(t *testing.T) {
	mc := startTestMonitor(t, os.Getuid(), os.Getgid(), testGroups(t))
	ctx, cancel := testCtx()
	defer cancel()
	if err := mc.Ping(ctx); err != nil {
		t.Fatalf("ping: %v", err)
	}
}

func TestMonitorExecRoundTrip(t *testing.T) {
	mc := startTestMonitor(t, os.Getuid(), os.Getgid(), testGroups(t))
	exits := collectExits(mc)

	// A second subscriber replaces the first only after the exec reply
	// returns, while the child is still running. The notification is
	// unsolicited, not tied to the call that spawned it.
	out := runChild(t, mc, []string{"/bin/sh", "-c", "sleep 0.3; echo hi; exit 0"}, nil)
	if got := strings.TrimSpace(out); got != "hi" {
		t.Fatalf("child output = %q, want %q", got, "hi")
	}
	exits2 := collectExits(mc) // subscribes after spawn, before exit
	n := waitExitNoteAny(t, 5*time.Second, exits, exits2)
	if n.code != 0 {
		t.Fatalf("exit notification code = %d, want 0", n.code)
	}

	// A failing child reports its code.
	runChild(t, mc, []string{"/bin/sh", "-c", "exit 7"}, nil)
	n = waitExitNote(t, exits2, 5*time.Second)
	if n.code != 7 {
		t.Fatalf("exit notification code = %d, want 7", n.code)
	}
}

func TestMonitorExecNoStdio(t *testing.T) {
	// Zero passed descriptors means the child's stdio maps to /dev/null.
	mc := startTestMonitor(t, os.Getuid(), os.Getgid(), testGroups(t))
	exits := collectExits(mc)
	ctx, cancel := testCtx()
	defer cancel()
	trueExe := trueExe(t)
	pid, err := mc.Exec(ctx, []string{trueExe}, nil, "/", false, nil)
	if err != nil {
		t.Fatalf("exec %s: %v", trueExe, err)
	}
	n := waitExitNote(t, exits, 5*time.Second)
	if n.pid != pid || n.code != 0 {
		t.Fatalf("exit notification = pid %d code %d, want pid %d code 0", n.pid, n.code, pid)
	}
}

// TestMonitorExecEmptyEnv pins the env contract: an exec request with
// no env gives the child an empty environment, never the monitor's
// own environment. In tests that is the test process's environment.
func TestMonitorExecEmptyEnv(t *testing.T) {
	envExe, err := exec.LookPath("env")
	if err != nil {
		t.Skipf("no env binary on PATH: %v", err)
	}
	mc := startTestMonitor(t, os.Getuid(), os.Getgid(), testGroups(t))
	out := runChild(t, mc, []string{envExe}, nil)
	if out != "" {
		t.Fatalf("child environment = %q, want empty (the monitor's env must not leak)", out)
	}
}

// TestMonitorExecChildInheritsNoFds pins the CLOEXEC hygiene. The
// monitor must not leak its inherited RPC fd, or anything else, into
// exec'd children. The child lists its own fds by having ls enumerate
// the shell's fd directory.
func TestMonitorExecChildInheritsNoFds(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("/proc/<pid>/fd listing is linux-only")
	}
	mc := startTestMonitor(t, os.Getuid(), os.Getgid(), testGroups(t))
	out := runChild(t, mc, []string{"/bin/sh", "-c", "ls -1 /proc/$$/fd"}, nil)
	assertChildHasStdioOnly(t, out)
}

// TestMonitorScrubbedSpawnStrays pins the entry scrub. The monitor may
// inherit non-close-on-exec descriptors from its parent: tailscaled
// cannot guarantee the state of its whole descriptor table. Even so,
// the monitor must exec children with a clean descriptor table.
func TestMonitorScrubbedSpawnStrays(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("/proc/<pid>/fd listing is linux-only")
	}
	// A pipe without close-on-exec, inherited by the monitor child and,
	// unscrubbed, by everything it execs.
	stray := make([]int, 2)
	if err := unix.Pipe(stray); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		unix.Close(stray[0])
		unix.Close(stray[1])
	})
	mc := startTestMonitor(t, os.Getuid(), os.Getgid(), testGroups(t))
	out := runChild(t, mc, []string{"/bin/sh", "-c", "ls -1 /proc/$$/fd"}, nil)
	assertChildHasStdioOnly(t, out)
}

// assertChildHasStdioOnly fails if the child's /proc/<pid>/fd listing
// shows anything beyond stdio.
func assertChildHasStdioOnly(t *testing.T, out string) {
	t.Helper()
	for _, f := range strings.Fields(out) {
		n, err := strconv.Atoi(f)
		if err != nil {
			t.Fatalf("child output %q: unexpected listing entry %q: %v", out, f, err)
		}
		if n > 2 {
			t.Fatalf("child inherited fd %d (output %q): monitor leaked a descriptor", n, out)
		}
	}
}

// TestCheckAgentSocketPath pins the shape the agent-forwarding socket
// path must have. The path comes from the child and steers a root-run
// directory removal on the session side, so anything beyond the shape
// the child is supposed to produce is rejected.
func TestCheckAgentSocketPath(t *testing.T) {
	for _, tt := range []struct {
		path  string
		valid bool
	}{
		{"/tmp/auth-agent123456/listener.sock", true},
		{"/tmp/auth-agent/listener.sock", true},
		{"/tmp/auth-agent123/inner/listener.sock", false},     // nested dir
		{"/home/u/auth-agent123/listener.sock", false},        // outside agentDirRoot
		{"/var/run/auth-agent123/listener.sock", false},       // outside agentDirRoot
		{"tmp/auth-agent123/listener.sock", false},            // not absolute
		{"/tmp/auth-agent123/other.sock", false},              // wrong file name
		{"/tmp/other123/listener.sock", false},                // wrong dir name
		{"/tmp/auth-agent123/../../etc/listener.sock", false}, // traversal
		{"/etc/passwd", false},                                // nothing like a socket path
	} {
		err := checkAgentSocketPath(tt.path)
		if got := err == nil; got != tt.valid {
			t.Errorf("checkAgentSocketPath(%q) err = %v, want valid=%v", tt.path, err, tt.valid)
		}
	}
}

// runIncubatorChild execs argv on the monitor as an incubator request
// and returns the child's stdout, fully drained until EOF so the child
// must exit.
func runIncubatorChild(t *testing.T, mc *monitorClient, argv []string) string {
	t.Helper()
	// stdin: read end handed to the child. Nothing is written to it.
	stdin, stdinKeep, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer stdinKeep.Close()
	stdout, stdoutW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	stderr, stderrW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := testCtx()
	defer cancel()
	pid, err := mc.ExecIncubator(ctx, argv, nil, "/", false, nil, stdin, stdoutW, stderrW)
	if err != nil {
		t.Fatalf("incubator exec %v: %v", argv, err)
	}
	if pid.PID <= 0 {
		t.Fatalf("incubator exec %v: pid %v, want > 0", argv, pid)
	}
	stdoutW.Close()
	stderrW.Close()
	out := readAllWithDeadline(t, stdout, 5*time.Second)
	if e := readAllWithDeadline(t, stderr, 5*time.Second); e != "" {
		t.Logf("child %v stderr: %s", argv, e)
	}
	stdout.Close()
	stderr.Close()
	return out
}

// TestMonitorExecIncubatorIdentityBinding pins the identity contract of
// incubator execs: the monitor rewrites the request's identity flags to
// its spawn-bound identity whatever the request claims, and refuses an
// incubator argv that is missing any of them. The child prints the
// arguments it was exec'd with, after the monitor's rewrite.
func TestMonitorExecIncubatorIdentityBinding(t *testing.T) {
	groups := testGroups(t)
	mc := startTestMonitor(t, os.Getuid(), os.Getgid(), groups)

	argv := []string{"/bin/sh", "-c", `printf '%s\n' "$@"`, "sh",
		"--uid=1", "--gid=1", "--groups=1,2", "--local-user=not-us"}
	out := runIncubatorChild(t, mc, argv)
	want := strings.Join([]string{
		"--uid=" + formatID(uint32(os.Getuid())),
		"--gid=" + formatID(uint32(os.Getgid())),
		"--groups=" + joinGids(intToU32s(groups)),
		"--local-user=testuser",
	}, "\n") + "\n"
	if out != want {
		t.Fatalf("incubator argv after the monitor's rewrite = %q, want %q", out, want)
	}
}

// TestMonitorExecIncubatorIdentityRequired pins that an incubator exec
// missing an identity flag is refused before any child is spawned: the
// incubator's own flag defaults would otherwise run the child as root.
func TestMonitorExecIncubatorIdentityRequired(t *testing.T) {
	mc := startTestMonitor(t, os.Getuid(), os.Getgid(), testGroups(t))
	argv := []string{"/bin/sh", "-c", "echo spawned", "sh", "--uid=1"}
	ctx, cancel := testCtx()
	defer cancel()
	if _, err := mc.ExecIncubator(ctx, argv, nil, "/", false, nil); err == nil {
		t.Fatal("incubator exec without --gid, --groups, and --local-user flags was accepted")
	}
}

func TestMonitorSignal(t *testing.T) {
	mc := startTestMonitor(t, os.Getuid(), os.Getgid(), testGroups(t))
	exits := collectExits(mc)

	pid, err := mc.Exec(mustCtx(t), []string{"/bin/sleep", "30"}, nil, "/", false, nil)
	if err != nil {
		t.Fatalf("exec sleep: %v", err)
	}

	// Signaling an unknown pid must be refused.
	if err := mc.Signal(mustCtx(t), monitorProcess{PID: pid.PID + 1000000, ID: pid.ID}, "SIGTERM"); err == nil {
		t.Fatal("signal of a pid that is not a monitor child should fail")
	}
	// A bad signal name is an error too.
	if err := mc.Signal(mustCtx(t), pid, "SIGFAKE"); err == nil {
		t.Fatal("signal with unknown name should fail")
	}

	if err := mc.Signal(mustCtx(t), pid, "SIGTERM"); err != nil {
		t.Fatalf("signal: %v", err)
	}
	n := waitExitNote(t, exits, 5*time.Second)
	if n.pid != pid {
		t.Fatalf("exit notification pid = %d, want %d", n.pid, pid)
	}
	if want := 128 + int(unix.SIGTERM); n.code != want {
		t.Fatalf("exit notification code = %d, want %d (128+SIGTERM)", n.code, want)
	}
}

func mustCtx(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := testCtx()
	t.Cleanup(cancel)
	return ctx
}

// TestMonitorExecEnvFD pins the exec op's fourth descriptor: an envfd
// exec carries stdin/stdout/stderr plus the env-fd pipe, which the
// monitor maps to the child's fd 3, os/exec ExtraFiles slot 0, the
// fd the incubator's --env-fd names.
func TestMonitorExecEnvFD(t *testing.T) {
	mc := startTestMonitor(t, os.Getuid(), os.Getgid(), testGroups(t))
	exits := collectExits(mc)

	// The payload pipe: what launchProcess's forwardedEnvFile builds.
	envR, envW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		defer envW.Close()
		envW.Write([]byte(`["FORWARDED=pair"]`))
	}()

	stdout, stdoutW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer stdout.Close()
	ctx, cancel := testCtx()
	defer cancel()
	// The child asserts the pair is visible on fd 3, and that its
	// stdin, fd 0, is a separate stream, the /dev/null fd the request
	// carried.
	devNull, err := os.OpenFile(os.DevNull, os.O_RDONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer devNull.Close()
	argv := []string{"/bin/sh", "-c", `v=$(cat <&3); [ "$v" = '["FORWARDED=pair"]' ] && echo fd3-ok || echo fd3-bad:$v`}
	pid, err := mc.Exec(ctx, argv, nil, "/", false, envR, devNull, stdoutW, stdoutW)
	if err != nil {
		t.Fatalf("exec envfd: %v", err)
	}
	// The monitor closed its copies; drop ours so EOF arrives when the
	// child exits.
	stdoutW.Close()
	envR.Close()
	out := readAllWithDeadline(t, stdout, 5*time.Second)
	if got := strings.TrimSpace(out); got != "fd3-ok" {
		t.Errorf("child output = %q; want fd3-ok", got)
	}
	n := waitExitNote(t, exits, 5*time.Second)
	if n.pid != pid || n.code != 0 {
		t.Errorf("exit notification = pid %d code %d; want pid %d code 0", n.pid, n.code, pid)
	}
}

// TestMonitorBadExec asserts error propagation for unspawnable and
// malformed exec requests.
func TestMonitorBadExec(t *testing.T) {
	mc := startTestMonitor(t, os.Getuid(), os.Getgid(), testGroups(t))
	ctx, cancel := testCtx()
	defer cancel()

	for _, argv := range [][]string{
		{"/nonexistent/binary/definitely-not-here"},
		{"sh", "-c", "echo hi"}, // relative argv[0] must be refused
		{},
	} {
		if _, err := mc.Exec(ctx, argv, nil, "/", false, nil); err == nil {
			t.Fatalf("exec %v: unexpectedly succeeded", argv)
		}
	}
	// The channel still works after the errors.
	if err := mc.Ping(ctx); err != nil {
		t.Fatalf("ping after failed execs: %v", err)
	}
}

// TestMonitorTeardown closes the client and asserts the teardown path.
// The monitor exits promptly, through EOF, group SIGHUP, reaping,
// SIGKILL of survivors, and exit 0. Its children die with it.
func TestMonitorTeardown(t *testing.T) {
	mc := startTestMonitor(t, os.Getuid(), os.Getgid(), testGroups(t))
	exits := collectExits(mc)

	pid, err := mc.Exec(mustCtx(t), []string{"/bin/sleep", "30"}, nil, "/", false, nil)
	if err != nil {
		t.Fatalf("exec sleep: %v", err)
	}

	start := time.Now()
	if err := mc.Close(); err != nil {
		t.Fatalf("close: monitor did not exit cleanly: %v", err)
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Errorf("monitor teardown took %v, want < 2s", d)
	}

	// The sleep child must be dead. The monitor was its parent, so it is
	// not our child. Check its liveness directly: gone or a reaped
	// zombie on linux. On other platforms probe with signal 0.
	deadline := time.Now().Add(5 * time.Second)
	for !processDead(pid.PID) {
		if time.Now().After(deadline) {
			t.Fatalf("child %d still alive %v after monitor teardown", pid, time.Since(start))
		}
		time.Sleep(20 * time.Millisecond)
	}
	// The peer is gone; drain whatever exit notifications arrived, if
	// any.
	select {
	case n := <-exits:
		t.Logf("exit notification during teardown: %+v", n)
	default:
	}
}

// TestMonitorSIGHUPTeardown pins the external-restart path. A SIGHUP
// sent directly to the monitor process triggers the same teardown as
// RPC EOF. The ping first guarantees the monitor's loop and its SIGHUP
// handler are up.
func TestMonitorSIGHUPTeardown(t *testing.T) {
	mc := startTestMonitor(t, os.Getuid(), os.Getgid(), testGroups(t))
	ctx, cancel := testCtx()
	defer cancel()
	if err := mc.Ping(ctx); err != nil {
		t.Fatalf("ping: %v", err)
	}
	if err := unix.Kill(mc.Pid(), unix.SIGHUP); err != nil {
		t.Fatalf("kill monitor SIGHUP: %v", err)
	}
	start := time.Now()
	if err := mc.Close(); err != nil {
		t.Fatalf("close: monitor did not exit cleanly: %v", err)
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Errorf("monitor SIGHUP teardown took %v, want < 2s", d)
	}
}

// processDead reports whether pid is dead, either gone or a zombie
// awaiting reaping by its re-parented parent.
func processDead(pid int) bool {
	if runtime.GOOS == "linux" {
		b, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
		if err != nil {
			return true // gone: reaped
		}
		// The state char follows the closing paren of the comm field.
		if i := strings.LastIndexByte(string(b), ')'); i >= 0 && i+2 < len(b) {
			switch string(b)[i+2] {
			case 'Z', 'X': // zombie / dead
				return true
			}
		}
		return false
	}
	return errors.Is(unix.Kill(pid, 0), unix.ESRCH)
}

// TestMonitorIdentityBinding pins that the monitor's spawn-bound identity
// is the identity its children run under, and that no request content can
// influence it. The exec request carries identity-looking environment
// values and the child still reports the bound uid.
//
// Helper children in these tests inherit the monitor's credentials, so
// the binding is exercised with the monitor bound to the current uid,
// which works both under root and non-root test runs.
func TestMonitorIdentityBinding(t *testing.T) {
	uid := os.Getuid()
	mc := startTestMonitor(t, uid, os.Getgid(), testGroups(t))
	exits := collectExits(mc)
	env := []string{
		"HOME=/",
		"PATH=/",
		"USER=root",
		"LOGNAME=root",
		"UID=9999",
	}
	out := runChild(t, mc, []string{"/usr/bin/id", "-u"}, env)
	if got := strings.TrimSpace(out); got != strconv.Itoa(uid) {
		t.Fatalf("child id -u = %q, want bound uid %d", got, uid)
	}
	waitExitNote(t, exits, 5*time.Second)
}

// monitorExe is the test-side monitor executable, the test binary. The
// spawn-prefix seam routes it to the helper.
func monitorExe(t *testing.T) string {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	return exe
}
