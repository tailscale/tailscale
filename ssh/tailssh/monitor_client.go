// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build (linux && !android) || (darwin && !ios) || freebsd || openbsd

// monitorClient is tailscaled's side of the ssh-monitor RPC channel.
// It spawns the per-connection monitor process, re-exec'ing the
// current binary. It multiplexes request IDs, dispatches unsolicited
// exit notifications, and serializes writes.

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
		pending: make(map[int64]chan *rpcFrame),
		cmd:     cmd,
		done:    make(chan struct{}),
	}
	go mc.readLoop()
	return mc, nil
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
	pending map[int64]chan *rpcFrame
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
		f, _, err := mc.rpc.readFrame()
		if err != nil {
			return
		}
		mc.dispatch(f)
	}
}

// dispatch routes one inbound frame. Replies go to their waiting call,
// unsolicited exit notifications to the registered callback.
func (mc *monitorClient) dispatch(f rpcFrame) {
	if f.ID == 0 {
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
	mc.mu.Unlock()
	if ok {
		ch <- &f // buffered. The waiter is gone at worst briefly.
	}
}

// call sends one request and waits for its reply, the context, or the RPC
// channel's death.
func (mc *monitorClient) call(ctx context.Context, f rpcFrame, fds ...int) (rpcFrame, error) {
	var zero rpcFrame
	mc.mu.Lock()
	if mc.closed {
		mc.mu.Unlock()
		return zero, errors.New("ssh-monitor: client closed")
	}
	mc.nextID++
	id := mc.nextID
	f.ID = id
	ch := make(chan *rpcFrame, 1)
	mc.pending[id] = ch
	mc.mu.Unlock()

	mc.writeMu.Lock()
	err := mc.rpc.writeFrame(f, fds...)
	mc.writeMu.Unlock()
	if err != nil {
		mc.mu.Lock()
		delete(mc.pending, id)
		mc.mu.Unlock()
		return zero, fmt.Errorf("ssh-monitor: write %q: %w", f.Op, err)
	}

	select {
	case r := <-ch:
		if !r.OK {
			return *r, errors.New("ssh-monitor: " + r.Err)
		}
		return *r, nil
	case <-ctx.Done():
		mc.mu.Lock()
		delete(mc.pending, id)
		mc.mu.Unlock()
		return zero, fmt.Errorf("ssh-monitor: op %q: %w", f.Op, ctx.Err())
	case <-mc.done:
		mc.mu.Lock()
		delete(mc.pending, id)
		mc.mu.Unlock()
		return zero, errors.New("ssh-monitor: RPC channel closed")
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
	_, err := mc.call(ctx, rpcPingReq(0))
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
	r, err := mc.call(ctx, f, fds...)
	if err != nil {
		return 0, err
	}
	return r.Pid, nil
}

// Signal asks the monitor to signal a child process group.
func (mc *monitorClient) Signal(ctx context.Context, pid int, sig string) error {
	_, err := mc.call(ctx, rpcSignalReq(0, pid, sig))
	return err
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
