// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build (linux && !android) || (darwin && !ios)

// Regression tests for the PTY-master descriptor leak into later
// sessions: a pty-master dup made without FD_CLOEXEC shows up in a
// later session child's fdinfo as a tty-index matching the earlier
// session's pty. Both session-path dups are atomic F_DUPFD_CLOEXEC,
// and on the monitor route the session children are exec'd by the
// per-conn monitor process from a clean fd table.
//
// Two properties are pinned:
//
//   - Two concurrent sessions through one conn's monitor, the first
//     with a pty, the second dumping its fd table and /proc/self/fdinfo:
//     the second child holds no tty-index matching the first session's
//     pty and nothing beyond the declared set.
//   - The declared-fds-only rule for every child class: the monitor
//     session child with the --env-fd pipe as fd 3, the one-shot fwd
//     child dialed through the same conn's monitor while a pty session
//     is live, and the direct path with tailscaledPath set to "" (the
//     session child is exec'd by this process from its inherited fd
//     table).
//
// Root runs bind the monitor-route conns to the non-root sshfwda test
// user, so the later children run as another uid than the test process
// holding the pty master. Non-root runs assert the same fd isolation
// between same-uid sessions.
//
// All fd-listing assertions take the listing from an external process
// such as ls, or, for the helper-children dumps in dumpChildFdsTo, by
// an explicitly numbered dirfd whose transient number is excluded (the
// /proc/self/fd false-leak lesson from TestMonitorExecChildInheritsNoFds).

package tailssh

import (
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/user"
	"path/filepath"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	gliderssh "github.com/tailscale/gliderssh"
	gossh "golang.org/x/crypto/ssh"
	"tailscale.com/tailcfg"
	"tailscale.com/tailcfg/nodecap"
	"tailscale.com/tstest"
)

// sessionFdsDumpCmd is the fd-table dump run by the session child's
// shell. The fd listing is taken by ls, an external process, so the
// transient opendir descriptor belongs to ls, not to the listed
// process; the fdinfo phase globs the shell's fdinfo files in-process
// and cats each with an external cat. An inherited pty master shows up
// twice, as an fd beyond the declared set and as a tty-index line
// matching the earlier session's /dev/pts/N.
const sessionFdsDumpCmd = `
echo FDLIST-BEGIN
ls -1 /proc/$$/fd
echo FDLIST-END
for f in /proc/$$/fd/*; do
	echo ==FDTARGET ${f##*/}
	readlink "$f"
done
echo FDTARGET-END
for f in /proc/$$/fdinfo/*; do
	echo ==FDINFO $f
	cat $f
done
echo FDINFO-END`

// ptyMasterLeakFatalf fails the test when the isolation assertion trips.
// The cause is a leaked descriptor or another fd-hygiene bug of the same
// class, not a broken test.
func ptyMasterLeakFatalf(t *testing.T, format string, args ...any) {
	t.Helper()
	t.Fatalf("pty-master fd leak into later sessions: "+format, args...)
}

// waitSessionPtsIndex polls a pty session's output until the child's tty
// line appears and returns the pty's pts index. A leaked master fd
// would report this index in the fdinfo dump of a later session's child.
func waitSessionPtsIndex(t *testing.T, out *sessTestBuffer, timeout time.Duration) int {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		for _, line := range strings.Fields(out.String()) {
			if pts, ok := strings.CutPrefix(line, "/dev/pts/"); ok {
				n, err := strconv.Atoi(pts)
				if err == nil {
					return n
				}
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("pty session never reported its tty (got %q)", out.String())
	return -1
}

// sessionFdsDump holds the parsed output of sessionFdsDumpCmd. Fds is
// the set of fds the session child's shell holds, taken only from the
// external ls listing. TtyIdx holds every tty-index value the fdinfo
// exposed; kernels without the tty-index fdinfo line expose none, and
// the fd-count assertion is then the effective one.
type sessionFdsDump struct {
	fds       map[int]bool
	ttyIdx    map[int]bool   // tty-index values seen on any fd
	targets   map[int]string // per-fd readlink targets, when dumped
	sawFdinfo bool
}

// parseSessionFdsDump parses sessionFdsDumpCmd's output, the fd listing
// between the FDLIST markers and the fdinfo sections' tty-index lines.
// fdinfo lines are tab-separated, so this parses line-wise rather than
// by whitespace fields. An fdinfo section whose cat produced nothing is
// ignored: its ENOENT is the fdinfo glob's own transient fd, closed by
// cat time.
func parseSessionFdsDump(t *testing.T, out string) sessionFdsDump {
	t.Helper()
	d := sessionFdsDump{fds: map[int]bool{}, ttyIdx: map[int]bool{}, targets: map[int]string{}}
	inList, inInfo, inTarget := false, false, false
	lastTargetFD := -1
	for _, raw := range strings.Split(out, "\n") {
		line := strings.TrimSpace(raw)
		switch {
		case line == "FDLIST-BEGIN":
			inList, inInfo, inTarget = true, false, false
			continue
		case line == "FDLIST-END":
			inList, inInfo = false, false
			continue
		case strings.HasPrefix(line, "==FDTARGET"):
			inList, inInfo, inTarget = false, false, true
			if v, ok := strings.CutPrefix(line, "==FDTARGET "); ok {
				lastTargetFD, _ = strconv.Atoi(strings.TrimSpace(v))
			}
			continue
		case line == "FDTARGET-END":
			inList, inInfo, inTarget = false, false, false
			continue
		case strings.HasPrefix(line, "==FDINFO"):
			// A new section begins. Sections whose content lines never
			// arrive below were transient, closed before cat could read.
			inList, inInfo, inTarget = false, true, false
			continue
		case line == "FDINFO-END":
			inList, inInfo = false, false
			continue
		}
		if inList {
			if line == "" {
				continue
			}
			if fd, err := strconv.Atoi(line); err == nil {
				d.fds[fd] = true
			} else {
				t.Fatalf("fd listing line %q: not a number", line)
			}
		}
		if inTarget && line != "" && lastTargetFD >= 0 {
			d.targets[lastTargetFD] = line
		}
		if inInfo && line != "" {
			d.sawFdinfo = true
			if v, ok := strings.CutPrefix(line, "tty-index:"); ok {
				n, err := strconv.Atoi(strings.TrimSpace(v))
				if err == nil {
					d.ttyIdx[n] = true
				}
			}
		}
	}
	return d
}

// runFdsDumpSession opens the session that runs sessionFdsDumpCmd (with
// any extraArg appended) and returns its raw output. gossh Run returns
// at the exit-status frame, which this server may send before the final
// output frames, so the caller-readable buffer is polled until the
// dump's FDINFO-END terminator arrives before the output is parsed.
func runFdsDumpSession(t *testing.T, cl *gossh.Client, extraArg string, configure func(*gossh.Session)) string {
	t.Helper()
	s, err := cl.NewSession()
	if err != nil {
		t.Fatalf("new dump session: %v", err)
	}
	if configure != nil {
		configure(s)
	}
	var out sessTestBuffer
	s.Stdout = &out
	s.Stderr = &out
	if err := s.Run(sessionFdsDumpCmd + extraArg); err != nil {
		t.Fatalf("fd dump session: %v (output %q)", err, out.String())
	}
	deadline := time.Now().Add(10 * time.Second)
	for {
		if strings.Contains(out.String(), "FDINFO-END") {
			return out.String()
		}
		if time.Now().After(deadline) {
			t.Fatalf("fd dump output never completed (got %q)", out.String())
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// TestParseSessionFdsDumpDetectsTtyIndex proves the fdinfo parse half
// of the isolation assertions detects the leak's mechanism: a synthetic
// dump in the byte-for-byte shape the shell emits yields the fd set
// and the tty-index.
func TestParseSessionFdsDumpDetectsTtyIndex(t *testing.T) {
	out := "FDLIST-BEGIN\n4\n0\n1\n2\nFDLIST-END\n" +
		"==FDINFO /proc/999/fdinfo/4\npos:\t0\nflags:\t02100002\nmnt_id:\t19\nino:\t89\ntty-index:\t17\n" +
		"==FDINFO /proc/999/fdinfo/0\npos:\t0\nflags:\t02\n\n" +
		"FDINFO-END\n"
	d := parseSessionFdsDump(t, out)
	want := map[int]bool{0: true, 1: true, 2: true, 4: true}
	if !reflect.DeepEqual(d.fds, want) {
		t.Fatalf("parsed fd set = %v, want %v", d.fds, want)
	}
	if !d.sawFdinfo {
		t.Fatal("fdinfo sections not seen")
	}
	if wantIdx := map[int]bool{17: true}; !reflect.DeepEqual(d.ttyIdx, wantIdx) {
		t.Fatalf("parsed tty-index set = %v, want %v (the leaked-master line)", d.ttyIdx, wantIdx)
	}
}

// ambientFds snapshots the test process's fd table before the test
// creates anything. A CI runner's process chain can hold inherited
// non-close-on-exec pipes; every descendant inherits them, so they
// show up in every session child's fd dump without being session
// leaks. Snapshot fd numbers persist for the process lifetime, since
// an open descriptor keeps its number, so a dump-time fd present here
// is ambient inheritance rather than something this test's sessions
// acquired.
func ambientFds(t *testing.T) map[int]bool {
	t.Helper()
	ents, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Logf("ambient fd snapshot unavailable (%v); beyond-set detection runs unfiltered", err)
		return nil
	}
	m := make(map[int]bool, len(ents))
	for _, ent := range ents {
		if n, err := strconv.Atoi(ent.Name()); err == nil {
			m[n] = true
		}
	}
	return m
}

// assertSessionFdsIsolated asserts the fd isolation properties for
// one session child's fd dump against a live pty session at pts index
// ptsIdx: the dump holds exactly the declared fds 0, 1 and 2 (the
// env-fd 3 is not passed to the shell), with no tty-index collision
// with the live pty's master. A beyond-set fd that was already open in
// the test process when the test started is runner-inherited ambient
// state and is reported, not failed; a beyond-set fd acquired since,
// or any fd targeting the live pty's master or slave, fails.
func assertSessionFdsIsolated(
	t *testing.T,
	dump sessionFdsDump,
	ptsIdx int,
	crossUserNote string,
	ambient map[int]bool,
) {
	t.Helper()
	for fd := range dump.fds {
		if fd >= 0 && fd <= 3 {
			continue
		}
		if ambient[fd] {
			t.Logf("session child inherited ambient fd %d -> %q", fd, dump.targets[fd])
			continue
		}
		ptyMasterLeakFatalf(t,
			"unexpected fd %d -> %q: fds=%v tty-indexes=%v targets=%v live-pty=pts/%d (%s)",
			fd, dump.targets[fd], dump.fds, dump.ttyIdx, dump.targets, ptsIdx, crossUserNote)
	}
	for fd, target := range dump.targets {
		if target == "/dev/ptmx" || target == fmt.Sprintf("/dev/pts/%d", ptsIdx) {
			ptyMasterLeakFatalf(t,
				"session child inherited PTY fd %d -> %s: live-pty=pts/%d ambient=%v",
				fd, target, ptsIdx, ambient)
		}
	}
	if dump.ttyIdx[ptsIdx] {
		ptyMasterLeakFatalf(t,
			"session child inherited live PTY master pts/%d: fds=%v (%s)",
			ptsIdx, dump.fds, crossUserNote)
	}
	t.Logf("session child fds=%v tty-indexes=%v live-pty=pts/%d (%s)",
		dump.fds, dump.ttyIdx, ptsIdx, crossUserNote)
}

// ptyLeakCrossUserNote describes the uid relationship the test proves.
// Under root, the session children run as the bound non-root user while
// the test process holds the pty master as root. Otherwise both run
// under the same uid.
func ptyLeakCrossUserNote() string {
	if uid := os.Getuid(); uid != 0 {
		return fmt.Sprintf("same-uid pin: tailscaled-proxy uid %d is also the bound user", uid)
	}
	return "test process runs as root; session children run as the bound non-root user"
}

// startPtyLeakSession opens the long-lived pty session, session 1 of
// the isolation tests. Its child reports its tty, then sleeps. The
// master stays open in the test process until the client closes it,
// for the whole duration of the second session's dump.
func startPtyLeakSession(t *testing.T, cl *gossh.Client) (*gossh.Session, *sessTestBuffer, int) {
	t.Helper()
	s, err := cl.NewSession()
	if err != nil {
		t.Fatalf("new pty session: %v", err)
	}
	if err := s.RequestPty("xterm", 10, 40, gossh.TerminalModes{}); err != nil {
		t.Fatalf("request pty: %v", err)
	}
	var out sessTestBuffer
	s.Stdout = &out
	s.Stderr = &out
	if err := s.Start("tty; sleep 25"); err != nil {
		t.Fatalf("start pty session child: %v", err)
	}
	return s, &out, waitSessionPtsIndex(t, &out, 15*time.Second)
}

// TestSessionPTYMasterNotInheritedByLaterSessions is the targeted
// pty-leak regression of two concurrent sessions through one conn's
// monitor. Session 1 holds a live pty whose master lives in the
// tailscaled-proxy process, which is this test process; session 2
// dumps its fd table and fdinfo. The second child must hold only its
// declared fds 0, 1 and 2 and no fd whose tty-index matches the first
// session's pty.
//
// The SSHBehaviorV1 cap pins the incubator to the in-process children
// branch, as in TestSessionMonitorExitStatusOrder.
func TestSessionPTYMasterNotInheritedByLaterSessions(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("fd-table / fdinfo assertions read /proc; linux-only")
	}
	lu := fwdTestIdentity(t) // root runs: the non-root sshfwda user
	addr := newMonitorSessionServerFor(t, lu, nil, nil, false, func(c *conn, s gliderssh.Session) {
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

	ambient := ambientFds(t)
	s1, _, ptsIdx := startPtyLeakSession(t, cl)
	defer s1.Close()

	raw := runFdsDumpSession(t, cl, "", nil)
	dump := parseSessionFdsDump(t, raw)
	note := ptyLeakCrossUserNote()
	assertSessionFdsIsolated(t, dump, ptsIdx, note, ambient)
	declared := map[int]bool{0: true, 1: true, 2: true}
	live := map[int]bool{}
	for fd := range dump.fds {
		if fd <= 3 || !ambient[fd] {
			// The child's declared stdio is its own; only beyond-set
			// fds are candidates for ambient inheritance.
			live[fd] = true
		}
	}
	if !reflect.DeepEqual(live, declared) {
		t.Errorf("session child fds=%v ambient=%v; want declared fds=%v",
			dump.fds, ambient, declared)
	}
	if !dump.sawFdinfo {
		t.Fatalf("fdinfo sections produced no content (raw %q)", raw)
	}
}

// TestSessionChildDeclaredFdsIncludeOnlyEnvFD pins the
// declared-fds rule for the monitor's session child
// with the --env-fd present. A session whose client-forwarded env pair
// is accepted travels to the incubator as a fourth descriptor, fd 3.
// The incubator child, exec'd by the conn's monitor, must hold exactly
// {0,1,2,3}, fd 3 being the env pipe. The incubator dump runs in the
// helper-test entry before the incubator drops privileges.
func TestSessionChildDeclaredFdsIncludeOnlyEnvFD(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("fd-table / fdinfo assertions read /proc; linux-only")
	}
	lu := fwdTestIdentity(t)
	dumpPath := filepath.Join(t.TempDir(), "incub-fds.dump")
	ambient := ambientFds(t)

	rule := &tailcfg.SSHRule{
		SSHUsers:  map[string]string{"test": lu.Username},
		Action:    &tailcfg.SSHAction{Accept: true},
		AcceptEnv: []string{"TERM"},
		Principals: []*tailcfg.SSHPrincipal{
			{Any: true},
		},
	}
	caps := []nodecap.Cap{
		nodecap.SSHBehaviorV1,
		nodecap.SSHEnvironmentVariables,
	}
	addr := newMonitorSessionServerFor(t, lu, caps, rule, false, func(c *conn, s gliderssh.Session) {
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

	s1, _, ptsIdx := startPtyLeakSession(t, cl)
	defer s1.Close()

	// The trailing marker carries the dump path in the incubator's
	// argv. Setenv must run on the same session the dump does;
	// runFdsDumpSession's configure callback applies it before the
	// command starts.
	raw := runFdsDumpSession(t, cl, " ; echo "+incubFdsDumpMarker+"="+dumpPath, func(s *gossh.Session) {
		if err := s.Setenv("TERM", "leakcheck"); err != nil {
			t.Fatalf("Setenv: %v", err)
		}
	})

	// The shell holds the declared std only, after the privilege drop
	// and after the env pipe is closed.
	dump := parseSessionFdsDump(t, raw)
	assertSessionFdsIsolated(t, dump, ptsIdx, ptyLeakCrossUserNote(), ambient)

	// The incubator's fd table at exec time, straight from the
	// monitor's handoff, holds fd 3 plus stdio.
	blocks := parseFDumpBlocks(t, dumpPath)
	if len(blocks) != 1 {
		t.Fatalf("incubator fd dump has %d blocks, want 1: %v", len(blocks), blocks)
	}
	assertHelperChildDeclaredFds(t, blocks[0], ptsIdx, "pipe:", "monitor session child (incubator)", ambient)
	t.Logf("incubator child fds at exec: %v", blocks[0])
}

// TestFwdChildHoldsOnlyDeclaredFds pins the declared-fds rule for
// the one-shot forwarding child. While a pty session is live
// on the same conn, its master held by the tailscaled-proxy test
// process, a unix -L dial through the same conn's monitor spawns the
// fwd child. The helper dumps the child's exec-inherited fd table at
// entry: exactly {0,1,2,3}, stdio from the monitor plus the
// result-channel socketpair end.
func TestFwdChildHoldsOnlyDeclaredFds(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("the helper fd dump reads /proc; linux-only")
	}
	lu := fwdTestIdentity(t)
	dumpPath := filepath.Join(fwdTmpDir(t), "fwd-fds.dump")
	t.Setenv("TS_TEST_SSH_FWD_FDINFO", dumpPath)
	ambient := ambientFds(t)

	rule := &tailcfg.SSHRule{
		SSHUsers: map[string]string{"test": lu.Username},
		Action: &tailcfg.SSHAction{
			Accept:                   true,
			AllowLocalPortForwarding: true,
		},
		Principals: []*tailcfg.SSHPrincipal{
			{Any: true},
		},
	}
	connCh := make(chan *conn, 1)
	addr := newMonitorSessionServerFor(t, lu, nil, rule, true, func(c *conn, s gliderssh.Session) {
		select {
		case connCh <- c:
		default:
		}
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

	s1, _, ptsIdx := startPtyLeakSession(t, cl)
	defer s1.Close()

	// The dial target is a socket the bound user can open, in the
	// allowlist.
	svcDir := fwdTmpDir(t)
	svcPath := filepath.Join(svcDir, "svc.sock")
	ln, err := net.Listen("unix", svcPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	if err := os.Chmod(svcPath, 0o666); err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			sc, err := ln.Accept()
			if err != nil {
				return
			}
			go sc.Close()
		}
	}()

	// Dial through the same conn's monitor while the pty session is live.
	sc := <-connCh
	gctx, cancel := fwdTestCtxTimeout(30 * time.Second)
	defer cancel()
	uc, err := sc.mayForwardLocalUnixTo(gctx, svcPath)
	if err != nil {
		t.Fatalf("unix -L dial through the session conn's monitor: %v", err)
	}
	uc.Close()

	blocks := parseFDumpBlocks(t, dumpPath)
	if len(blocks) < 1 {
		t.Fatalf("no fwd child dumped its fd table (dial went through, so a fwd child ran)")
	}
	for _, b := range blocks {
		assertHelperChildDeclaredFds(t, b, ptsIdx, "socket:", "fwd child", ambient)
	}
	t.Logf("forwarding child fd tables: count=%d newest=%v live-pty=pts/%d (%s)",
		len(blocks), blocks[len(blocks)-1], ptsIdx, ptyLeakCrossUserNote())
}

// newDirectSessionServer is newMonitorSessionServerFor's shape with
// tailscaledPath set to "", the direct-exec fallback used when no
// tailscaled binary exists, as in tsnet. The session child is exec'd
// by this process with its inherited fd table, so a regression to a
// non-CLOEXEC dup of the pty master is caught by a later session's
// child seeing the master.
//
// Under root the conn binds to root itself: the direct path has no
// privilege-dropping incubator, and directExecAllowed refuses a root
// process running another user's session. Under non-root it binds to the
// current user, and the fd-isolation assertions are same-uid.
func newDirectSessionServer(t *testing.T, handler func(c *conn, s gliderssh.Session)) string {
	t.Helper()
	username := "root"
	if os.Getuid() != 0 {
		u, err := user.Current()
		if err != nil {
			t.Fatal(err)
		}
		username = u.Username
	}
	um, err := userLookup(username)
	if err != nil {
		t.Fatal(err)
	}
	um.loginShellCached = "/bin/sh"

	logf := tstest.WhileTestRunningLogger(t)
	srv := &server{
		lb: &localState{
			sshEnabled: true,
			varRoot:    t.TempDir(),
		},
		logf: logf,
	}
	sc, err := srv.newConn()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(sc.closeConnMonitor)
	sc.insecureSkipTailscaleAuth = true
	sc.localUser = um
	sc.mappedLocalUser = um.Username
	for _, g := range testGroups(t) {
		sc.userGroupIDs = append(sc.userGroupIDs, strconv.Itoa(g))
	}
	sc.info = &sshConnInfo{
		sshUser: "test",
		src:     netip.MustParseAddrPort("1.2.3.4:32342"),
		dst:     netip.MustParseAddrPort("1.2.3.5:22"),
		node:    (&tailcfg.Node{}).View(),
		uprof:   tailcfg.UserProfile{},
	}
	sc.action0 = &tailcfg.SSHAction{Accept: true}
	sc.finalAction = sc.action0
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

// TestDirectPathSessionInheritsNoPtyMaster pins the declared-fds
// rule for the direct path, where the session child is exec'd from
// the fd-holding process itself. With a pty session live, whose master
// and both CLOEXEC dups are held by this test process, a later
// non-pty session's child must hold exactly {0,1,2} and no tty-index
// collision with the live pty.
func TestDirectPathSessionInheritsNoPtyMaster(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("fd-table / fdinfo assertions read /proc; linux-only")
	}
	if os.Geteuid() == 0 && os.Getuid() != 0 {
		t.Skip("elevated-but-not-root execution is not a supported direct-path configuration")
	}
	ambient := ambientFds(t)
	addr := newDirectSessionServer(t, func(c *conn, s gliderssh.Session) {
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

	s1, _, ptsIdx := startPtyLeakSession(t, cl)
	defer s1.Close()

	raw := runFdsDumpSession(t, cl, "", nil)
	dump := parseSessionFdsDump(t, raw)
	note := "direct path: the session child is exec'd from the fd-holding process itself"
	if os.Getuid() == 0 {
		note += "; root run, sessions as root (the direct path cannot drop privileges)"
	}
	assertSessionFdsIsolated(t, dump, ptsIdx, note, ambient)
	live := map[int]bool{}
	for fd := range dump.fds {
		if fd <= 3 || !ambient[fd] {
			// The child's declared stdio is its own; only beyond-set
			// fds are candidates for ambient inheritance.
			live[fd] = true
		}
	}
	want := map[int]bool{0: true, 1: true, 2: true}
	if !reflect.DeepEqual(live, want) {
		t.Errorf("direct session child fds=%v ambient=%v; want declared fds=%v",
			dump.fds, ambient, want)
	}
	if !dump.sawFdinfo {
		t.Fatalf("fdinfo sections produced no content (raw %q)", raw)
	}
}

// fdDumpEntry is one dumped descriptor: its readlink target and the
// FD_CLOEXEC state parsed from its fdinfo flags field.
type fdDumpEntry struct {
	target  string
	cloexec bool
}

// parseFDumpBlocks parses the BEGIN/END-delimited blocks of
// "fd <n> flags <oct> -> <target>" lines in a dumpChildFdsTo file.
func parseFDumpBlocks(t *testing.T, path string) []map[int]fdDumpEntry {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read fd dump: %v", err)
	}
	var blocks []map[int]fdDumpEntry
	var cur map[int]fdDumpEntry
	for _, line := range strings.Split(string(b), "\n") {
		switch {
		case strings.HasPrefix(line, "BEGIN "):
			cur = map[int]fdDumpEntry{}
		case strings.HasPrefix(line, "END "):
			if cur != nil {
				blocks = append(blocks, cur)
				cur = nil
			}
		case strings.HasPrefix(line, "fd "):
			if cur == nil {
				t.Fatalf("fd dump line %q outside a BEGIN/END block", line)
			}
			rest := strings.TrimPrefix(line, "fd ")
			fdS, rest2, ok := strings.Cut(rest, " ")
			if !ok {
				t.Fatalf("fd dump line %q: not an fd entry", line)
			}
			fd, err := strconv.Atoi(fdS)
			if err != nil {
				t.Fatalf("fd dump line %q: %v", line, err)
			}
			flags := ""
			if before, after, ok := strings.Cut(rest2, " -> "); ok {
				rest2 = after
				if v, ok := strings.CutPrefix(before, "flags "); ok {
					flags = strings.TrimSpace(v)
				}
			}
			cloexec := false
			if fv, err := strconv.ParseUint(flags, 8, 32); err == nil {
				cloexec = fv&0o2000000 != 0 // O_CLOEXEC is visible in fdinfo's flags
			}
			cur[fd] = fdDumpEntry{target: rest2, cloexec: cloexec}
		}
	}
	return blocks
}

// assertHelperChildDeclaredFds asserts the declared-fds rule for a
// re-exec'd helper child's dumped fd table, the fwd child or the
// incubator with its --env-fd pipe: fds 0 to 2 and fd 3, the declared
// pipe or socket end, must be present, every fd beyond the declared
// set must be FD_CLOEXEC, and no descriptor may resolve to a pty end
// while another session's pty is live. The observee's own runtime
// bookkeeping, its epoll and eventfd pair, is created after exec and
// always carries the flag, unlike an exec-inherited stray from a
// non-CLOEXEC dup.
func assertHelperChildDeclaredFds(
	t *testing.T,
	block map[int]fdDumpEntry,
	ptsIdx int,
	fd3WantPrefix, classDesc string,
	ambient map[int]bool,
) {
	t.Helper()
	for fd := 0; fd <= 3; fd++ {
		if _, ok := block[fd]; !ok {
			t.Fatalf("%s: declared fd %d missing from fd table %v", classDesc, fd, block)
		}
	}
	if !strings.HasPrefix(block[3].target, fd3WantPrefix) {
		t.Errorf("%s: fd 3 = %q, want a %s descriptor", classDesc, block[3].target, fd3WantPrefix)
	}
	for fd, e := range block {
		if strings.Contains(e.target, "/dev/ptmx") || strings.HasPrefix(e.target, "/dev/pts/") {
			ptyMasterLeakFatalf(t, "%s inherited PTY fd %d -> %s: live-pty=pts/%d",
				classDesc, fd, e.target, ptsIdx)
		}
		if fd > 3 && !e.cloexec {
			if ambient[fd] {
				t.Logf("%s inherited ambient fd %d -> %q", classDesc, fd, e.target)
				continue
			}
			ptyMasterLeakFatalf(t, "%s has unexpected fd %d -> %s without CLOEXEC: live-pty=pts/%d",
				classDesc, fd, e.target, ptsIdx)
		}
	}
}
