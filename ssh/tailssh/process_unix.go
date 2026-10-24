// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build (linux && !android) || (darwin && !ios) || freebsd || openbsd || plan9

package tailssh

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"syscall"

	gliderssh "github.com/tailscale/gliderssh"
)

// monitorProcess identifies one exec child. ID is the exec request ID, which
// distinguishes successive children even when the operating system reuses a PID.
type monitorProcess struct {
	PID int
	ID  int64
}

// monExitStatus publishes an exit code to any number of waiters. The registry
// completes it once; code may be read only after done is closed.
type monExitStatus struct {
	done chan struct{}
	code int
}

// osSessionState holds the platform-specific state of an [sshSession]'s
// process. It is embedded in [sshSession] and initialized by launchProcess.
//
// cmd describes the invocation on both paths. monChild identifies a monitor
// child; cmd.Process identifies a directly launched child.
type osSessionState struct {
	// cmd is the session's incubator or shell process on the direct path.
	// It is set but never started on the monitor path.
	cmd *exec.Cmd

	monChild monitorProcess // zero on the direct path
	// monExit publishes the exit status, or 128+signal for a signaled death.
	monExit *monExitStatus
	// monDead is closed when the monitor's RPC channel is gone, so
	// waiting sessions fail instead of blocking.
	monDead <-chan struct{}
}

// forwardedEnvChildFD is the fd the incubator child reads the forwarded environment from, sent via
// --env-fd. It must match the payload file's index in launchProcess's ExtraFiles (fd = 3 + index).
const forwardedEnvChildFD = 3

// forwardedEnvFile returns the read end of a pipe holding the JSON-encoded forwarded pairs.
// The read end is passed to the incubator child via exec.Cmd.ExtraFiles to communicate
// secrets and config; the payload only ever exists in memory, never on any filesystem. A
// goroutine writes the payload and closes the write end. Caller must close the read end
// after the child starts.
func forwardedEnvFile(forwardedEnv []string) (*os.File, error) {
	if len(forwardedEnv) == 0 {
		return nil, errors.New("no forwarded environment")
	}
	b, err := json.Marshal(forwardedEnv)
	if err != nil {
		return nil, fmt.Errorf("marshaling forwarded environment: %w", err)
	}
	r, w, err := os.Pipe()
	if err != nil {
		return nil, fmt.Errorf("creating forwarded environment pipe: %w", err)
	}
	go func() {
		defer w.Close()
		// A short read fails the session child-side
		_, _ = w.Write(b)
	}()
	return r, nil
}

// canSwitchToLocalUser reports whether this process can run a session as lu.
// A non-root tailscaled can only run sessions as itself.
func canSwitchToLocalUser(lu *userMeta) error {
	if euid := os.Geteuid(); euid != 0 && runtime.GOOS != "plan9" {
		if lu.Uid != fmt.Sprint(euid) {
			return fmt.Errorf("can't switch to user %q from process euid %v", lu.Username, euid)
		}
	}
	return nil
}

// waitProcess waits for the session's process to exit and returns its exit
// code. A non-nil error means the exit code could not be determined.
func (ss *sshSession) waitProcess() (exitCode int, err error) {
	// Monitor path: the child's exit arrives as the monitor's async
	// exit notification, with the code documented on monExit.
	if code, ok, merr := ss.waitMonitorProcess(); ok {
		return code, merr
	}
	err = ss.cmd.Wait()
	if err == nil {
		return 0, nil
	}
	if ee, ok := errors.AsType[*exec.ExitError](err); ok {
		return ee.ProcessState.ExitCode(), nil
	}
	return 1, err
}

// hangupProcess asks the session's process to terminate because the
// session is over. On the monitor path this is hangupMonitorProcess.
// On the direct path it is a single SIGHUP to the child pid.
func (ss *sshSession) hangupProcess() {
	if ss.hangupMonitorProcess() {
		return
	}
	// SIGHUP = POSIX terminal-disconnect semantics; OpenSSH gets it
	// implicitly via PTY-master close (session.c:2246), we send it
	// explicitly because non-PTY sessions use pipes.
	ss.cmd.Process.Signal(syscall.SIGHUP)
}

// systemHostKeyFile returns the path of the system's OpenSSH host key of the
// given type ("rsa", "ecdsa", "ed25519") for tailssh to reuse, or "" to
// generate its own key instead. Only root can read the system keys.
func systemHostKeyFile(typ string) string {
	if os.Geteuid() != 0 {
		return ""
	}
	return "/etc/ssh/ssh_host_" + typ + "_key"
}

// handleSSHAgentForwarding starts a Unix socket listener and in the background
// forwards agent connections between the listener and the gliderssh.Session.
// On success, it assigns ss.agentListener.
//
// The listener and its containing directory are created by a user-cred
// child through conn.fwdListenAgent. See the docs there for the modes.
func (ss *sshSession) handleSSHAgentForwarding(s gliderssh.Session, lu *userMeta) error {
	if !gliderssh.AgentRequested(ss) || !ss.conn.finalAction.AllowAgentForwarding {
		return nil
	}
	// The latched AllowAgentForwarding bit may be stale. See recheckPolicy.
	if !ss.conn.recheckPolicy() {
		return nil
	}
	if sshDisableForwarding() {
		// TODO(bradfitz): or do we want to return an error here instead so the user
		// gets an error if they ran with ssh -A? But for now we just silently
		// don't work, like the condition above.
		return nil
	}
	ss.logf("ssh: agent forwarding requested")
	ln, socket, err := ss.conn.fwdListenAgent(s.Context(), lu)
	if err != nil {
		return err
	}
	// The listener's own address is the kernel's bound path; socket is
	// the path the child reported and the monitor validated. They must
	// agree: the cleanup removes the directory of the validated path, so
	// a child whose report and actual bind disagree is refused.
	if got := ln.Addr().String(); got != socket {
		ln.Close()
		return fmt.Errorf("agent forwarding socket path %q does not match the listener's bound path %q", socket, got)
	}
	ss.agentListener = ln
	go gliderssh.ForwardAgentConnections(ln, s)
	return nil
}

// closeAgentForwarding closes the agent forwarding listener and removes the
// temporary directory that holds its socket, so neither outlives the
// session. The removal rules are platform-specific: on the monitor
// platforms the directory was created by a user-cred child while the
// removal runs with the daemon's credentials; see
// removeAgentForwardingDir in fwdmonitor.go and fwdplan9.go.
func (ss *sshSession) closeAgentForwarding() {
	ln := ss.agentListener
	if ln == nil {
		return
	}
	ss.agentListener = nil
	dir := filepath.Dir(ln.Addr().String())
	ln.Close()
	removeAgentForwardingDir(dir, ss.conn.localUser, ss.logf)
}
