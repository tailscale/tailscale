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
	"strconv"
	"syscall"

	gliderssh "github.com/tailscale/gliderssh"
)

// osSessionState holds the platform-specific state of an [sshSession]'s
// process. It is embedded in [sshSession] and initialized by launchProcess.
type osSessionState struct {
	cmd *exec.Cmd // the session's incubator or shell process
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
	err = ss.cmd.Wait()
	if err == nil {
		return 0, nil
	}
	if ee, ok := errors.AsType[*exec.ExitError](err); ok {
		return ee.ProcessState.ExitCode(), nil
	}
	return 1, err
}

// hangupProcess asks the session's process to terminate because the session
// is over.
func (ss *sshSession) hangupProcess() {
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
func (ss *sshSession) handleSSHAgentForwarding(s gliderssh.Session, lu *userMeta) error {
	if !gliderssh.AgentRequested(ss) || !ss.conn.finalAction.AllowAgentForwarding {
		return nil
	}
	if sshDisableForwarding() {
		// TODO(bradfitz): or do we want to return an error here instead so the user
		// gets an error if they ran with ssh -A? But for now we just silently
		// don't work, like the condition above.
		return nil
	}
	ss.logf("ssh: agent forwarding requested")
	ln, err := gliderssh.NewAgentListener()
	if err != nil {
		return err
	}
	defer func() {
		if err != nil && ln != nil {
			ln.Close()
		}
	}()

	// 31 bits so that the values fit an int on every platform.
	uid, err := strconv.ParseUint(lu.Uid, 10, 31)
	if err != nil {
		return err
	}
	gid, err := strconv.ParseUint(lu.Gid, 10, 31)
	if err != nil {
		return err
	}
	socket := ln.Addr().String()
	dir := filepath.Dir(socket)
	// Make sure the socket is accessible only by the user.
	if err := os.Chmod(socket, 0600); err != nil {
		return err
	}
	if err := os.Chown(socket, int(uid), int(gid)); err != nil {
		return err
	}
	// Make sure the dir is also accessible.
	if err := os.Chmod(dir, 0755); err != nil {
		return err
	}

	go gliderssh.ForwardAgentConnections(ln, s)
	ss.agentListener = ln
	return nil
}
