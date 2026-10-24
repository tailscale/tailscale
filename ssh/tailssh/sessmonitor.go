// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build (linux && !android) || (darwin && !ios) || freebsd || openbsd

// Session processes are launched by the connection's privileged monitor.
// tailscaled keeps the parent I/O descriptors and passes the child's stdio
// and optional environment pipe via SCM_RIGHTS.

package tailssh

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"time"
)

// hangupEscalation is the delay between SIGHUP and SIGKILL on session teardown.
const hangupEscalation = 5 * time.Second

func newMonExitStatus() *monExitStatus {
	return &monExitStatus{done: make(chan struct{})}
}

func (s *monExitStatus) complete(code int) {
	s.code = code
	close(s.done)
}

// launchViaMonitor passes cmd and the child's descriptors to the monitor.
// After dispatch, cancellation does not abandon the exec reply: a successful
// launch always registers the child so run can terminate it and wait for exit.
func (ss *sshSession) launchViaMonitor(cmd *exec.Cmd, envFile *os.File, stdio []*os.File, ctty bool) error {
	if len(stdio) != 3 {
		return fmt.Errorf("internal error: monitor exec needs 3 stdio fds, got %d", len(stdio))
	}
	if err := ss.ctx.Err(); err != nil {
		return err
	}
	mc, err := ss.conn.fwdMonitor()
	if err != nil {
		return err
	}
	child, err := mc.ExecIncubator(ss.ctx, cmd.Args, cmd.Env, cmd.Dir, ctty, envFile, stdio...)
	if err != nil {
		return fmt.Errorf("exec on session monitor: %w", err)
	}
	exit := newMonExitStatus()
	ss.conn.fwd.exits.registerSessionExit(child, exit)
	ss.monChild = child
	ss.monExit = exit
	ss.monDead = mc.Gone()
	return nil
}

// waitMonitorProcess returns the child's exit code, or an error if its monitor
// dies without reporting an exit. ok is false for directly launched sessions.
func (ss *sshSession) waitMonitorProcess() (code int, ok bool, err error) {
	if ss.monExit == nil {
		return 0, false, nil
	}
	select {
	case <-ss.monExit.done:
		return ss.monExit.code, true, nil
	case <-ss.monDead:
		// The read loop delivers notifications before closing monDead.
		// Recheck here because both cases may have become ready together.
		select {
		case <-ss.monExit.done:
			return ss.monExit.code, true, nil
		default:
			return 1, true, errors.New("session monitor exited before the session process")
		}
	}
}

// hangupMonitorProcess sends SIGHUP, then SIGKILL after hangupEscalation if the
// child has not exited. It returns false for directly launched sessions.
func (ss *sshSession) hangupMonitorProcess() bool {
	if ss.monChild.PID == 0 {
		return false
	}
	mc := ss.conn.fwdMonitorIfAny()
	if mc == nil {
		// Monitor teardown owns cleanup. Its reaped PIDs may already have
		// been reused, so tailscaled must not signal them directly.
		return true
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := mc.Signal(ctx, ss.monChild, "SIGHUP"); err != nil {
		ss.logf("ssh: SIGHUP session process group: %v", err)
	}
	time.AfterFunc(hangupEscalation, func() { ss.escalateMonitorProcess(mc) })
	return true
}

func (ss *sshSession) escalateMonitorProcess(mc *monitorClient) {
	select {
	case <-ss.monExit.done:
		return
	default:
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := mc.Signal(ctx, ss.monChild, "SIGKILL"); err != nil {
		ss.vlogf("ssh: SIGKILL session process group: %v", err)
	}
}
