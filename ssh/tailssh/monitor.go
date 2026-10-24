// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build (linux && !android) || (darwin && !ios) || freebsd || openbsd

// The per-connection privileged ssh-monitor process. tailscaled spawns
// it, as "tailscaled be-child ssh-monitor", once a connection is
// authorized, and speaks the protocol of monitor_rpc.go over the
// socketpair fd it inherits at spawn.
//
// The connection's identity, the uid, gid, and groups of its
// localUser, is fixed in argv at spawn. Only the event loop touches
// the RPC channel, the child table, and file descriptors.
//
// RPC EOF or an external SIGHUP tears the connection down. Every child
// group is SIGHUPed, then a bounded reap sweep runs, and surviving
// groups are SIGKILLed before the monitor exits.

package tailssh

import (
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

const (
	// monExecOpDeadline bounds the exec op's spawn-and-reply phase. It
	// does not bound the child's lifetime. monDialOpDeadline bounds a
	// one-shot op from spawn to result.
	monDialOpDeadline = 10 * time.Second
	monExecOpDeadline = 30 * time.Second

	// monTeardownReap bounds each reap sweep in teardown. A child still
	// alive after the SIGKILL sweep is uninterruptible. It is left in
	// its own group and abandoned.
	monTeardownReap = 2 * time.Second
)

// monChild is one entry of the monitor's child table, keyed by pid.
// Every child leads its own group, so pgid equals pid.
type monChild struct {
	pgid int // the child's process group. Equal to its pid.
}

// monitor is the running ssh-monitor process state, owned entirely by
// the event loop goroutine.
type monitor struct {
	conn     *rpcConn
	args     monitorArgs // the spawn-bound identity
	children map[int]*monChild
	hup      chan os.Signal
	broken   bool // a reply or notification write failed. Leave the loop.
}

// monitorArgs are the monitor's spawn arguments, in the style of
// incubatorArgs. The identity fields are the connection's bound
// identity, fixed at spawn.
type monitorArgs struct {
	// uid, gid, and gids are the Linux ABI's 32-bit ids, as passed in
	// argv at spawn.
	uid       uint32
	gid       uint32
	gids      []uint32
	localUser string
	rpcFD     int
}

// formatID renders one 32-bit Linux uid or gid as the decimal string
// form the monitor's and the incubator's argv flags carry.
func formatID(v uint32) string {
	return strconv.FormatUint(uint64(v), 10)
}

// parseMonitorArgs parses the arguments following "be-child ssh-monitor".
func parseMonitorArgs(args []string) (monitorArgs, error) {
	var ma monitorArgs
	var uidStr, gidStr, groups string

	flags := flag.NewFlagSet("ssh-monitor", flag.ContinueOnError)
	flags.StringVar(&uidStr, "uid", "", "uid of the connection's local user (bound at spawn)")
	flags.StringVar(&gidStr, "gid", "", "gid of the connection's local user (bound at spawn)")
	flags.StringVar(&groups, "groups", "", "comma-separated supplementary gids of the local user")
	flags.StringVar(&ma.localUser, "local-user", "", "name of the connection's local user")
	flags.IntVar(&ma.rpcFD, "rpc-fd", -1, "inherited AF_UNIX stream fd of the RPC channel")
	if err := flags.Parse(args); err != nil {
		return ma, err
	}
	if uidStr == "" || gidStr == "" {
		return ma, errors.New("--uid and --gid are required")
	}
	if ma.rpcFD < 3 {
		return ma, fmt.Errorf("invalid --rpc-fd %d: must be >= 3 (an ExtraFiles fd)", ma.rpcFD)
	}
	// Ids are parsed at their ABI width: unsigned 32-bit, the full range
	// the kernel's uid_t and gid_t carry.
	u64, err := strconv.ParseUint(uidStr, 10, 32)
	if err != nil {
		return ma, fmt.Errorf("unable to parse uid %q: %w", uidStr, err)
	}
	ma.uid = uint32(u64)
	g64, err := strconv.ParseUint(gidStr, 10, 32)
	if err != nil {
		return ma, fmt.Errorf("unable to parse gid %q: %w", gidStr, err)
	}
	ma.gid = uint32(g64)
	for g := range strings.SplitSeq(groups, ",") {
		if g == "" {
			continue
		}
		gid, err := strconv.ParseUint(g, 10, 32)
		if err != nil {
			return ma, fmt.Errorf("unable to parse group id %q: %w", g, err)
		}
		ma.gids = append(ma.gids, uint32(gid))
	}
	return ma, nil
}

// beMonitor is the entrypoint of the "tailscaled be-child ssh-monitor"
// subcommand, the per-connection privileged monitor process.
func beMonitor(args []string) error {
	ma, err := parseMonitorArgs(args)
	if err != nil {
		return err
	}

	// Scrub every descriptor from 3 up to close-on-exec at entry,
	// before anything else runs. The monitor inherits its parent's
	// whole non-close-on-exec descriptor table, and a privileged
	// monitor must not leak any of it into the children it execs. The
	// RPC fd is included: the root-privileged channel must never
	// survive into an exec'd child either.
	if err := scrubFds(); err != nil {
		return fmt.Errorf("ssh-monitor: scrub fds: %w", err)
	}

	conn, err := wrapUnixConn(ma.rpcFD) // consumes the raw fd
	if err != nil {
		return fmt.Errorf("ssh-monitor: rpc fd: %w", err)
	}

	// An external SIGHUP gets the same teardown as RPC EOF. The loop
	// selects on it between events. Delivery waits for the current op
	// to finish.
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, unix.SIGHUP)
	defer signal.Stop(hup)

	m := &monitor{
		conn:     newRPCConn(conn),
		args:     ma,
		children: make(map[int]*monChild),
		hup:      hup,
	}
	return m.loop()
}

// spawnRPCChild spawns exe with argv. The child receives one end of a
// fresh AF_UNIX SOCK_STREAM socketpair as fd 3. The parent end is
// returned as a *net.UnixConn via wrapUnixConn, along with the started
// child. prefix names the child class in error messages.
//
// Both raw socketpair ends are close-on-exec at creation, as is the
// parent end's wrapUnixConn dup.
//
// env is used exactly as given: a nil env gives the child an empty
// environment, never the spawner's. Callers spawn the privileged
// monitor with the daemon's environment and user-identity children with
// none, so the daemon's environment never reaches a child running as
// the connection's user.
func spawnRPCChild(prefix, exe string, argv, env []string, attr *syscall.SysProcAttr) (*exec.Cmd, *net.UnixConn, error) {
	pair, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	if err != nil {
		return nil, nil, fmt.Errorf("%s: socketpair: %w", prefix, err)
	}
	for _, fd := range pair {
		if _, err := unix.FcntlInt(uintptr(fd), unix.F_SETFD, unix.FD_CLOEXEC); err != nil {
			unix.Close(pair[0])
			unix.Close(pair[1])
			return nil, nil, fmt.Errorf("%s: fcntl(F_SETFD) on socketpair: %w", prefix, err)
		}
	}
	childEnd := os.NewFile(uintptr(pair[1]), prefix+"-child")
	parentConn, err := wrapUnixConn(pair[0]) // consumes the raw parent end
	if err != nil {
		childEnd.Close()
		return nil, nil, fmt.Errorf("%s: parent end: %w", prefix, err)
	}
	cmd := exec.Command(exe, argv...)
	cmd.Env = env
	if cmd.Env == nil {
		cmd.Env = []string{} // nil would inherit the spawner's environment
	}
	cmd.ExtraFiles = []*os.File{childEnd} // lands as fd 3 in the child
	cmd.SysProcAttr = attr
	if err := cmd.Start(); err != nil {
		parentConn.Close()
		childEnd.Close()
		return nil, nil, fmt.Errorf("%s: start: %w", prefix, err)
	}
	// The child has its own dup since Start. Drop ours.
	childEnd.Close()
	return cmd, parentConn, nil
}

// monEvent carries one inbound RPC frame from the reader goroutine to
// the loop. An error ends the channel.
type monEvent struct {
	f   rpcFrame
	fds []int
	err error
}

// loop is the monitor's event loop. A reader goroutine blocks in
// readFrame on the RPC channel. The loop itself waits on inbound
// frames, external SIGHUP, and SIGCHLD, and runs the sole op handler,
// reaper, and teardown.
func (m *monitor) loop() error {
	events := make(chan monEvent, 1)
	go func() {
		for {
			f, fds, err := m.conn.readFrame()
			events <- monEvent{f: f, fds: fds, err: err}
			if err != nil {
				return
			}
		}
	}()

	// Child exits arrive as SIGCHLD. The sweep below reaps the exiting
	// children, so signal coalescing is safe.
	sigchld := make(chan os.Signal, 1)
	signal.Notify(sigchld, syscall.SIGCHLD)
	defer signal.Stop(sigchld)

	for {
		select {
		case <-m.hup:
			m.teardown()
			return nil
		case <-sigchld:
			m.sweep(true)
		case ev := <-events:
			if ev.err != nil {
				// EOF, an I/O error, or a protocol error means the
				// connection is over.
				m.teardown()
				return nil
			}
			m.handle(ev.f, ev.fds)
			if m.broken {
				m.teardown()
				return nil
			}
		}
	}
}

// handle dispatches one request frame. It runs on the loop goroutine.
// Descriptors not consumed by the op are closed here.
func (m *monitor) handle(f rpcFrame, fds []int) {
	if f.ID == 0 {
		// Unsolicited frames are dropped and their descriptors closed.
		closeFds(fds)
		return
	}
	switch f.Op {
	case opPing:
		closeFds(fds)
		m.reply(rpcOKReply(f.ID, opPing))
	case opExec:
		m.handleExec(f, fds)
	case opSignal:
		closeFds(fds)
		m.handleSignal(f)
	case opDial, opListen:
		// Reply a descriptive error rather than ignoring the frame.
		closeFds(fds)
		m.reply(rpcErrReply(f.ID, f.Op, fmt.Errorf("op %q not implemented", f.Op)))
	default:
		closeFds(fds)
		m.reply(rpcErrReply(f.ID, f.Op, fmt.Errorf("unknown op %q", f.Op)))
	}
}

// handleExec spawns one child, mapping the request's file descriptors
// to the child's stdio. monExecOpDeadline bounds the op from dispatch
// to the return of cmd.Start; it does not bound the child's lifetime.
func (m *monitor) handleExec(f rpcFrame, fds []int) {
	start := time.Now()
	fail := func(err error) {
		closeFds(fds)
		m.reply(rpcErrReply(f.ID, opExec, err))
	}
	if len(f.Argv) == 0 {
		fail(errors.New("exec: empty argv"))
		return
	}
	// argv[0] must be an absolute path.
	if !filepath.IsAbs(f.Argv[0]) {
		fail(fmt.Errorf("exec: argv[0] must be an absolute path, got %q", f.Argv[0]))
		return
	}
	cmd := exec.Command(f.Argv[0], f.Argv[1:]...)
	// Env is used exactly as given. An exec request with no env gives
	// the child an empty environment: the monitor's own environment
	// belongs to tailscaled, and a privileged monitor must not leak it
	// into connection children.
	cmd.Env = f.Env
	if cmd.Env == nil {
		cmd.Env = []string{} // nil would inherit the monitor's environment
	}
	cmd.Dir = monChildDir(f.Dir)
	files, err := monStdio(fds)
	if err != nil {
		// monStdio's error path already closed every descriptor. Nil
		// the slice so fail's closeFds is a no-op rather than a double
		// close.
		fds = nil
		fail(err)
		return
	}
	// From here the raw ints in fds are owned by files, each wrapped in
	// an *os.File that closes it exactly once. Clearing the slice makes
	// every later fail() a no-op for them instead of a double close.
	fds = nil
	cmd.Stdin, cmd.Stdout, cmd.Stderr = files[0], files[1], files[2]
	cmd.SysProcAttr = monChildAttr(f.Ctty)
	// Re-scrub before the fork: anything opened or received since entry
	// that missed close-on-exec marking must not reach the child. The
	// stdio descriptors below survive the scrub: the child receives
	// fresh non-close-on-exec dups on 0, 1, and 2.
	if err := scrubFds(); err != nil {
		monCloseFiles(files)
		fail(err)
		return
	}
	if err := cmd.Start(); err != nil {
		monCloseFiles(files)
		fail(err)
		return
	}
	// Close our copies of the stdio descriptors. The child holds its
	// own dups onto 0..2.
	monCloseFiles(files)
	if time.Since(start) > monExecOpDeadline {
		// Kill the child and reply an error instead of ok. The kill is
		// bounded by killGroupAndReap.
		pid := cmd.Process.Pid
		_ = killGroup(pid, unix.SIGKILL)
		killGroupAndReap(pid)
		fail(fmt.Errorf("exec: spawn-and-reply exceeded %s deadline", monExecOpDeadline))
		return
	}
	// Its pgid is its pid. See monChildAttr.
	m.children[cmd.Process.Pid] = &monChild{pgid: cmd.Process.Pid}
	m.reply(rpcExecReply(f.ID, cmd.Process.Pid))
}

// killGroupAndReap reaps a just-SIGKILLed child with wait4(WNOHANG) for
// up to 500ms, surrendering after the budget. It returns whether the
// child was reaped.
func killGroupAndReap(pid int) (reaped bool) {
	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		var ws unix.WaitStatus
		wpid, err := unix.Wait4(pid, &ws, unix.WNOHANG, nil)
		if err != nil || wpid == pid {
			return true
		}
		time.Sleep(10 * time.Millisecond)
	}
	return false
}

// handleSignal signals a child process *group* whose pid is validated
// against the monitor's child table.
func (m *monitor) handleSignal(f rpcFrame) {
	replyErr := func(err error) { m.reply(rpcErrReply(f.ID, opSignal, err)) }
	c, ok := m.children[f.Pid]
	if !ok {
		replyErr(fmt.Errorf("signal: pid %d is not a monitor child", f.Pid))
		return
	}
	sig := unix.SignalNum(f.Sig)
	if sig == 0 {
		replyErr(fmt.Errorf("signal: unknown signal %q", f.Sig))
		return
	}
	if err := killGroup(c.pgid, sig); err != nil {
		replyErr(err)
		return
	}
	m.reply(rpcOKReply(f.ID, opSignal))
}

// killGroup signals the process group pgid with kill(-pgid, sig), so
// a child's descendants, such as a shell's subprocesses, die with it.
func killGroup(pgid int, sig unix.Signal) error {
	return unix.Kill(-pgid, sig)
}

// sweep reaps exited children with wait4(WNOHANG) and drops them from
// the child table. With notify set, it emits one unsolicited exit
// notification per reaped pid.
func (m *monitor) sweep(notify bool) {
	for pid := range m.children {
		var ws unix.WaitStatus
		wpid, err := unix.Wait4(pid, &ws, unix.WNOHANG, nil)
		switch {
		case err != nil:
			// ECHILD means not our child or already reaped. Forget it
			// either way.
			delete(m.children, pid)
		case wpid == pid:
			if notify {
				m.notifyExit(pid, monExitCode(ws))
			}
			delete(m.children, pid)
		}
		// wpid == 0: still running.
	}
}

// monExitCode maps a wait status to the exit notification's code. It
// is the exit status for a normal exit, else the shell convention
// 128+signal for a signaled death.
func monExitCode(ws unix.WaitStatus) int {
	if ws.Exited() {
		return ws.ExitStatus()
	}
	return 128 + int(ws.Signal())
}

// scrubFdsByScan marks every open descriptor listed in dir, a
// /proc-style self-fd directory, close-on-exec from 3 up. It is the
// fallback path for platforms without close_range. Descriptors closed
// concurrently between the directory read and the fcntl are ignored.
func scrubFdsByScan(dir string) error {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	for _, ent := range ents {
		fd, err := strconv.Atoi(ent.Name())
		if err != nil || fd < 3 {
			continue
		}
		if _, err := unix.FcntlInt(uintptr(fd), unix.F_SETFD, unix.FD_CLOEXEC); err != nil && !errors.Is(err, syscall.EBADF) {
			return err
		}
	}
	return nil
}

// reply writes one frame on the loop goroutine. On write failure the
// connection is marked broken and the loop tears down.
func (m *monitor) reply(f rpcFrame) {
	if err := m.conn.writeFrame(f); err != nil {
		m.broken = true
	}
}

func (m *monitor) notifyExit(pid, code int) {
	m.reply(rpcExitNotify(pid, code))
}

// teardown is the monitor's orderly exit path, reached from RPC EOF, a
// protocol error, or an external SIGHUP. It SIGHUPs every child group,
// runs a brief bounded reap sweep, then SIGKILLs every group that
// survived the HUP and reaps again. Children that survive even the
// SIGKILL are abandoned in their own groups.
func (m *monitor) teardown() {
	// Snapshot the pgid set at teardown entry. A group member can
	// outlive its reaped leader, so the SIGKILL pass keys on this
	// remembered set rather than on surviving table entries.
	pgids := make(map[int]struct{}, len(m.children))
	for _, c := range m.children {
		pgids[c.pgid] = struct{}{}
	}
	for _, c := range m.children {
		// ESRCH means already gone and the like. Nothing to do.
		_ = killGroup(c.pgid, unix.SIGHUP)
	}
	deadline := time.Now().Add(monTeardownReap)
	for len(m.children) > 0 && time.Now().Before(deadline) {
		// Silent sweep. The peer is gone or going, so notifications
		// have nowhere to go.
		m.sweep(false)
		if len(m.children) > 0 {
			time.Sleep(20 * time.Millisecond)
		}
	}
	if len(pgids) > 0 {
		// SIGKILL every remembered group, those whose leader survived
		// the HUP and those whose leader died to it, then run one more
		// bounded silent reap sweep. Anything still alive after this is
		// in uninterruptible state and is abandoned, orphaned in its
		// own group.
		for pgid := range pgids {
			_ = killGroup(pgid, unix.SIGKILL)
		}
		deadline = time.Now().Add(monTeardownReap)
		for len(m.children) > 0 && time.Now().Before(deadline) {
			m.sweep(false)
			if len(m.children) > 0 {
				time.Sleep(20 * time.Millisecond)
			}
		}
	}
	m.conn.c.Close()
}

// monStdio maps the request's descriptors onto the child's stdin,
// stdout, and stderr, in order, taking ownership of all of them. On
// success every descriptor in fds is wrapped in an *os.File which the
// caller closes with monCloseFiles; on error every descriptor in fds
// has already been closed and the caller must not touch fds again.
// When fewer than three descriptors arrive, the missing streams map
// to /dev/null so the child always has a valid 0..2.
func monStdio(fds []int) ([]*os.File, error) {
	files := make([]*os.File, 3)
	for i := range files {
		if i < len(fds) {
			files[i] = os.NewFile(uintptr(fds[i]), fmt.Sprintf("ssh-monitor-child-fd%d", i))
			continue
		}
		f, err := os.OpenFile(os.DevNull, os.O_RDWR, 0)
		if err != nil {
			monCloseFiles(files[:i])
			closeFds(fds[i:]) // never wrapped: close them raw, exactly once
			return nil, err
		}
		files[i] = f
	}
	return files, nil
}

func monCloseFiles(files []*os.File) {
	for _, f := range files {
		f.Close()
	}
}

// monChildDir returns the child's working directory, falling back to
// "/" when dir is empty, missing, or not a directory. The check is
// best-effort.
func monChildDir(dir string) string {
	if dir == "" {
		return "/"
	}
	if fi, err := os.Stat(dir); err != nil || !fi.IsDir() {
		return "/"
	}
	return dir
}
