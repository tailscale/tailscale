// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build (linux && !android) || (darwin && !ios) || freebsd || openbsd

// monitorClient is tailscaled's side of the ssh-monitor RPC channel.
// It spawns the per-connection monitor process, re-exec'ing the
// current binary. It multiplexes request IDs, dispatches unsolicited
// exit notifications, and serializes writes.
//
// Dial, Listen, and ListenAgent implement the conn's forwarding socket
// ops.

package tailssh

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"slices"
	"strings"
	"sync"
	"syscall"
	"time"
)

// monitorSpawnPrefix is the argv prefix following the executable path,
// used to spawn the monitor process: "be-child ssh-monitor" in
// tailscaled. Tests override this seam to re-exec the test binary and
// dispatch to beMonitor.
var monitorSpawnPrefix = []string{"be-child", "ssh-monitor"}

// spawnMonitor spawns the per-connection ssh-monitor process and returns
// the connected client. uid/gid/groups/localUser carry the connection's
// bound identity, as documented on monitorArgs.
func spawnMonitor(exe string, uid, gid uint32, groups []uint32, localUser string) (*monitorClient, error) {
	gids := make([]string, len(groups))
	for i, g := range groups {
		gids[i] = formatID(g)
	}
	argv := append(slices.Clone(monitorSpawnPrefix),
		"--uid="+formatID(uid),
		"--gid="+formatID(gid),
		"--groups="+strings.Join(gids, ","),
		"--local-user="+localUser,
		"--rpc-fd=3",
	)
	// The monitor is its own session leader.
	cmd, parentConn, err := spawnRPCChild("ssh-monitor", exe, argv, os.Environ(), &syscall.SysProcAttr{Setsid: true})
	if err != nil {
		return nil, err
	}

	mc := &monitorClient{
		c:       parentConn,
		rpc:     newRPCConn(parentConn),
		pending: make(map[int64]chan *rpcResult),
		cmd:     cmd,
		done:    make(chan struct{}),
	}
	go mc.readLoop()
	return mc, nil
}

// rpcResult is one inbound reply. It holds the frame and, for the
// socket ops, the descriptor the reply carried. Ownership of the
// descriptors passes to the waiting call. If there is none, they are
// closed.
type rpcResult struct {
	f   rpcFrame
	fds []int
}

// monitorClient is tailscaled's connection to one ssh-monitor process.
type monitorClient struct {
	c   *net.UnixConn
	rpc *rpcConn
	cmd *exec.Cmd

	// writeMu serializes writeFrame, so the client has one logical
	// writer.
	writeMu sync.Mutex

	mu      sync.Mutex // guards the fields below
	nextID  int64
	pending map[int64]chan *rpcResult
	onExit  func(pid, code int)
	closed  bool

	// done is closed when the read loop exits, on RPC EOF or a read
	// error. The monitor is gone or the channel broke.
	done chan struct{}
}

// Pid returns the monitor process's pid for diagnostics and tests.
func (mc *monitorClient) Pid() int {
	return mc.cmd.Process.Pid
}

func (mc *monitorClient) readLoop() {
	defer close(mc.done)
	for {
		f, fds, err := mc.rpc.readFrame()
		if err != nil {
			return
		}
		// Acknowledge receipt of any relayed descriptors so the monitor
		// releases its hold on its copies. The recvmsg in readFrame is
		// what transfers ownership; see the monitor_rpc.go header for
		// the darwin kernel behavior the acknowledgment covers. A write
		// failure means the channel is going away; the monitor's
		// teardown closes its parked copies either way.
		if len(fds) > 0 {
			mc.writeMu.Lock()
			_ = mc.rpc.writeFrame(rpcFdAckReq(f.ID))
			mc.writeMu.Unlock()
		}
		mc.dispatch(f, fds)
	}
}

// dispatch routes one inbound frame. Replies, with any carried
// descriptors, go to their waiting call; a reply whose caller gave up
// has its descriptors closed here. Unsolicited exit notifications go
// to the registered callback.
func (mc *monitorClient) dispatch(f rpcFrame, fds []int) {
	if f.ID == 0 {
		closeFds(fds) // notifications never carry descriptors
		if f.Op == opExit {
			mc.mu.Lock()
			h := mc.onExit
			mc.mu.Unlock()
			if h != nil {
				h(f.Pid, f.Code)
			}
		}
		// Other unsolicited frames are ignored.
		return
	}
	mc.mu.Lock()
	ch, ok := mc.pending[f.ID]
	delete(mc.pending, f.ID)
	if ok {
		ch <- &rpcResult{f: f, fds: fds}
	} else {
		// The caller gave up, on ctx done or client death, and nobody
		// will consume the descriptors. Close them here.
		closeFds(fds)
	}
	mc.mu.Unlock()
}

// call sends one request and waits for its reply (with any descriptors it
// carries), the context, or the RPC channel's death. On every path that
// does not hand the descriptors to the caller they are closed exactly
// once. See dispatch for the race-free handoff.
func (mc *monitorClient) call(ctx context.Context, f rpcFrame, fds ...int) (rpcFrame, []int, error) {
	var zero rpcFrame
	mc.mu.Lock()
	if mc.closed {
		mc.mu.Unlock()
		return zero, nil, errors.New("ssh-monitor: client closed")
	}
	mc.nextID++
	id := mc.nextID
	f.ID = id
	ch := make(chan *rpcResult, 1)
	mc.pending[id] = ch
	mc.mu.Unlock()

	mc.writeMu.Lock()
	err := mc.rpc.writeFrame(f, fds...)
	mc.writeMu.Unlock()
	if err != nil {
		mc.mu.Lock()
		delete(mc.pending, id)
		mc.mu.Unlock()
		return zero, nil, fmt.Errorf("ssh-monitor: write %q: %w", f.Op, err)
	}

	select {
	case r := <-ch:
		if !r.f.OK {
			closeFds(r.fds) // an error reply should carry none; be safe
			return r.f, nil, errors.New("ssh-monitor: " + r.f.Err)
		}
		return r.f, r.fds, nil
	case <-ctx.Done():
		// Delete the entry under the lock: after this, dispatch finds no
		// waiter and closes a late reply's descriptors itself. A reply
		// already sitting in the channel is drained here and closed.
		mc.mu.Lock()
		delete(mc.pending, id)
		mc.mu.Unlock()
		select {
		case r := <-ch:
			closeFds(r.fds)
		default:
		}
		return zero, nil, fmt.Errorf("ssh-monitor: op %q: %w", f.Op, ctx.Err())
	case <-mc.done:
		mc.mu.Lock()
		delete(mc.pending, id)
		mc.mu.Unlock()
		select {
		case r := <-ch:
			closeFds(r.fds)
		default:
		}
		return zero, nil, errors.New("ssh-monitor: RPC channel closed")
	}
}

// SetExitCallback registers h for unsolicited exit notifications from the
// monitor, one call per reaped child with the child's pid and exit code.
// It may be replaced at any time. nil disables delivery.
func (mc *monitorClient) SetExitCallback(h func(pid, code int)) {
	mc.mu.Lock()
	mc.onExit = h
	mc.mu.Unlock()
}

// Ping round-trips a ping request.
func (mc *monitorClient) Ping(ctx context.Context) error {
	_, _, err := mc.call(ctx, rpcPingReq(0))
	return err
}

// Exec spawns a child on the monitor with the given stdio descriptors,
// stdin, stdout, and stderr in order. It returns the child's pid. The
// child's exit arrives later via the exit callback.
func (mc *monitorClient) Exec(ctx context.Context, argv, env []string, dir string, ctty bool, stdio ...*os.File) (int, error) {
	fds := make([]int, len(stdio))
	for i, f := range stdio {
		fds[i] = int(f.Fd())
	}
	f := rpcExecReq(0, argv, env, dir, ctty, len(fds))
	r, _, err := mc.call(ctx, f, fds...)
	if err != nil {
		return 0, err
	}
	return r.Pid, nil
}

// Signal asks the monitor to signal a child process group.
func (mc *monitorClient) Signal(ctx context.Context, pid int, sig string) error {
	_, _, err := mc.call(ctx, rpcSignalReq(0, pid, sig))
	return err
}

// Dial dials a unix socket through a one-shot child running with the
// connection's bound identity and returns the connected socket.
// The returned socket is acknowledged to the monitor on receipt, which
// releases the monitor's held copy; see the monitor_rpc.go header.
func (mc *monitorClient) Dial(ctx context.Context, addr string) (*net.UnixConn, error) {
	_, fds, err := mc.call(ctx, rpcDialReq(0, addr))
	if err != nil {
		return nil, err
	}
	if len(fds) != 1 {
		closeFds(fds)
		return nil, fmt.Errorf("ssh-monitor: dial reply carried %d fds, want 1", len(fds))
	}
	return wrapUnixConn(fds[0]) // consumes the descriptor
}

// Listen asks the monitor for a listener bound with the connection's
// bound identity; see fwdchild.go for the umask-at-bind construction
// and the optional if-owned pre-unlink. Closing the returned listener
// does not unlink a unix socket file; a later bind with unlink-if-owned
// removes stale socket files.
func (mc *monitorClient) Listen(ctx context.Context, network, addr string, unlink bool) (net.Listener, error) {
	r, fds, err := mc.call(ctx, rpcListenReq(0, network, addr, unlink, false))
	if err != nil {
		return nil, err
	}
	if len(fds) != 1 {
		closeFds(fds)
		return nil, fmt.Errorf("ssh-monitor: listen reply carried %d fds, want 1", len(fds))
	}
	return wrapListenerFD(fds[0], r.Path)
}

// ListenAgent asks the monitor for the agent-forwarding socket: a
// user-owned 0700 temp dir and, inside it, a 0600 socket at
// listener.sock, created by the bound-identity child. It returns the
// listener and the socket path. Removing the containing directory is
// the caller's job.
func (mc *monitorClient) ListenAgent(ctx context.Context) (ln net.Listener, path string, err error) {
	r, fds, err := mc.call(ctx, rpcListenReq(0, "", "", false, true))
	if err != nil {
		return nil, "", err
	}
	if r.Path == "" {
		closeFds(fds)
		return nil, "", errors.New("ssh-monitor: agent listen reply carried no path")
	}
	if len(fds) != 1 {
		closeFds(fds)
		return nil, "", fmt.Errorf("ssh-monitor: agent listen reply carried %d fds, want 1", len(fds))
	}
	ln, err = wrapListenerFD(fds[0], r.Path)
	if err != nil {
		return nil, "", err
	}
	return ln, r.Path, nil
}

// wrapListenerFD wraps a raw listener descriptor in a net.Listener. fd is
// consumed. net.FileListener dups it into the returned listener with
// close-on-exec set, and the original is closed here exactly once.
func wrapListenerFD(fd int, name string) (net.Listener, error) {
	f := os.NewFile(uintptr(fd), name)
	ln, err := net.FileListener(f)
	f.Close() // exactly-once close of the raw descriptor. The dup in ln is unaffected
	if err != nil {
		return nil, err
	}
	return ln, nil
}

// Close tears the connection down by closing the RPC channel, which
// triggers the monitor's teardown. Close waits for the monitor to
// exit. A wedged monitor is killed after 5 seconds.
func (mc *monitorClient) Close() error {
	mc.mu.Lock()
	if mc.closed {
		mc.mu.Unlock()
		return nil
	}
	mc.closed = true
	mc.mu.Unlock()

	mc.c.Close()
	<-mc.done
	waitErr := make(chan error, 1)
	go func() { waitErr <- mc.cmd.Wait() }()
	select {
	case err := <-waitErr:
		return err
	case <-time.After(5 * time.Second):
		mc.cmd.Process.Kill()
		return <-waitErr
	}
}
