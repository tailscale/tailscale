// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// This file contains the Windows-specific parts of the Tailscale SSH server:
// how a session's process is created as the target user, how it gets a
// pseudoconsole, and how it is waited for and terminated.
//
// There is no incubator child process on Windows. When tailscaled runs as
// LocalSystem (the normal case, as the Tailscale service), it logs the target
// user on with an S4U (service-for-user) logon, which needs no password,
// loads their profile, and creates the session process directly with that
// user's token. Pseudoconsoles can only be created for the current user, so
// for PTY sessions the s4u package first starts a small relay process
// ("tailscaled be-child s4u") as the user, and that relay creates the
// pseudoconsole and the shell.
//
// When tailscaled is not LocalSystem (a plain tailscaled.exe in a terminal),
// it can only run sessions as the user it is already running as.

package tailssh

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"strings"

	gliderssh "github.com/tailscale/gliderssh"
	"golang.org/x/sys/windows"
	"tailscale.com/cmd/tailscaled/childproc"
	"tailscale.com/tailcfg/nodecap"
	"tailscale.com/util/winutil"
	"tailscale.com/util/winutil/s4u"
)

// s4uSourceName identifies Tailscale SSH as the source of the logon sessions
// it creates (the TOKEN_SOURCE of the tokens). It is limited to 8 ASCII bytes.
const s4uSourceName = "tsssh"

// registerIncubator registers the child process handlers. It is called from
// [Register], which is called from the init of tailscale.com/feature/ssh.
//
// The s4u package registers its own "s4u" pseudoconsole relay handler.
func registerIncubator() {
	childproc.Add("sftp", beSFTP)
}

// osSessionState holds the Windows-specific state of an [sshSession]'s process.
type osSessionState struct {
	proc *s4u.Process
}

// canSwitchToLocalUser reports whether this process can run a session as lu.
// LocalSystem can log any local user on; anything else can only run sessions
// as itself.
func canSwitchToLocalUser(lu *userMeta) error {
	if winutil.IsCurrentProcessLocalSystem() {
		return nil
	}
	cu, err := user.Current()
	if err != nil {
		return fmt.Errorf("can't determine the current user: %w", err)
	}
	if !strings.EqualFold(cu.Uid, lu.Uid) {
		return fmt.Errorf("can't switch to user %q: tailscaled is running as %q rather than as LocalSystem", lu.Username, cu.Username)
	}
	return nil
}

// launchProcess starts the session's process: the user's shell, running
// the requested command if any, or the in-process SFTP server for SFTP
// sessions. It sets ss.proc, ss.wrStdin, ss.rdStdout, and ss.rdStderr.
func (ss *sshSession) launchProcess() error {
	lu := ss.conn.localUser
	ci := ss.conn.info

	var cli winutil.CommandLineInfo
	switch ss.Subsystem() {
	case "sftp":
		if ss.conn.srv.tailscaledPath == "" {
			// SFTP relies on the embedded Go-based SFTP server in tailscaled,
			// so without tailscaled, we can't serve SFTP.
			return errors.New("no tailscaled found on path, can't serve SFTP")
		}
		cli.ExePath = ss.conn.srv.tailscaledPath
		cli.SetArgs([]string{"be-child", "sftp"})
	case "":
		shell := lu.LoginShell()
		cli.ExePath = shell
		cli.SetArgs(windowsShellArgs(shell, ss.RawCommand()))
	default:
		panic(fmt.Sprintf("unexpected subsystem: %v", ss.Subsystem()))
	}

	// The session process gets the user's own environment (from their
	// token, or ours when running as the current user) plus these.
	env := map[string]string{
		"SSH_CLIENT":     fmt.Sprintf("%s %d %d", ci.src.Addr(), ci.src.Port(), ci.dst.Port()),
		"SSH_CONNECTION": fmt.Sprintf("%s %d %s %d", ci.src.Addr(), ci.src.Port(), ci.dst.Addr(), ci.dst.Port()),
	}
	addEnv := func(kv string) {
		if k, v, ok := strings.Cut(kv, "="); ok {
			env[k] = v
		}
	}
	for _, kv := range ss.Environ() {
		if acceptEnvPair(kv) {
			addEnv(kv)
		}
	}
	if nm := ss.conn.srv.lb.NetMapNoPeers(); nm.HasCap(nodecap.SSHEnvironmentVariables) {
		accepted, err := filterEnv(ss.conn.acceptEnv, ss.Environ())
		if err != nil {
			return err
		}
		for _, kv := range accepted {
			addEnv(kv)
		}
	}

	ptyReq, winCh, isPty := ss.Pty()
	if isPty {
		if sshDisablePTY() {
			ss.logf("pty support disabled by envknob")
			return errors.New("pty support disabled by envknob")
		}
		if ptyReq.Term != "" {
			env["TERM"] = ptyReq.Term
		}
	}

	// As LocalSystem, log the user on. The session's Close is deferred
	// here, but the logon session and profile stay loaded until the
	// process is released; see s4u.Session.Close.
	var sess *s4u.Session
	if winutil.IsCurrentProcessLocalSystem() {
		var err error
		sess, err = s4u.Login(ss.logf, s4uSourceName, &lu.User, s4u.CapCreateProcess)
		if err != nil {
			return fmt.Errorf("logging on as %q: %w", lu.Username, err)
		}
		defer sess.Close()
	}

	var proc *s4u.Process
	var err error
	if isPty {
		size := ptySize(ptyReq.Window)
		ss.logf("starting pty command: %v %v", cli.ExePath, cli.Args)
		if sess != nil {
			proc, err = sess.StartProcessWithPTY(cli, env, size)
		} else {
			proc, err = s4u.StartCurrentUserProcessWithPTY(ss.logf, cli, env, size)
		}
	} else {
		ss.logf("starting non-pty command: %v %v", cli.ExePath, cli.Args)
		if sess != nil {
			proc, err = sess.StartProcessWithPipes(cli, env)
		} else {
			proc, err = s4u.StartCurrentUserProcessWithPipes(ss.logf, cli, env)
		}
	}
	if err != nil {
		return err
	}

	ss.proc = proc
	ss.wrStdin = proc.Stdin()
	ss.rdStdout = proc.Stdout()
	ss.rdStderr = proc.Stderr() // nil for pty sessions
	// The pipes are owned by run's copier goroutines, which drain them to
	// EOF after the process exits. Release just frees the process and its
	// logon session.
	ss.childPipes = []io.Closer{closerFunc(proc.Release)}

	if isPty {
		ss.ptyReq = &ptyReq
		if resize := proc.PTYResizer(); resize != nil {
			go func() {
				for win := range winCh {
					if err := resize(ptySize(win)); err != nil {
						ss.vlogf("pty resize: %v", err)
					}
				}
			}()
		}
	}
	return nil
}

// ptySize converts an SSH window size to pseudoconsole coordinates. Clients
// without a real terminal can send zero dimensions, which the pseudoconsole
// API rejects, so those fall back to 80x24.
func ptySize(w gliderssh.Window) windows.Coord {
	c := windows.Coord{X: int16(w.Width), Y: int16(w.Height)}
	if w.Width <= 0 || w.Width > 1<<15-1 {
		c.X = 80
	}
	if w.Height <= 0 || w.Height > 1<<15-1 {
		c.Y = 24
	}
	return c
}

// acceptEnvPair reports whether the environment variable key=value pair
// should be accepted from the client. It uses the same default as OpenSSH
// AcceptEnv.
func acceptEnvPair(kv string) bool {
	k, _, ok := strings.Cut(kv, "=")
	if !ok || isDangerousEnvVar(k) || forbiddenEnvKey(k) {
		return false
	}
	return k == "TERM" || k == "LANG" || strings.HasPrefix(k, "LC_")
}

// closerFunc adapts a func to io.Closer.
type closerFunc func() error

func (f closerFunc) Close() error { return f() }

// waitProcess waits for the session's process to exit and returns its exit
// code. A non-nil error means the exit code could not be determined.
func (ss *sshSession) waitProcess() (exitCode int, err error) {
	code, err := ss.proc.Wait()
	if err != nil {
		return 1, err
	}
	return int(code), nil
}

// hangupProcess terminates the session's process because the session is
// over. Windows has no SIGHUP; the process, and through its job object any
// descendants it left in the job, are killed.
func (ss *sshSession) hangupProcess() {
	ss.proc.Terminate()
}

// systemHostKeyFile returns the path of the OpenSSH for Windows host key of
// the given type ("rsa", "ecdsa", "ed25519") for tailssh to reuse if it is
// present and readable, so that the node presents the same host key over
// Tailscale SSH as over sshd. Only LocalSystem and administrators can read
// those keys; other callers get "" and generate their own.
func systemHostKeyFile(typ string) string {
	if !winutil.IsCurrentProcessElevated() {
		return ""
	}
	programData := os.Getenv("ProgramData")
	if programData == "" {
		return ""
	}
	return filepath.Join(programData, "ssh", "ssh_host_"+typ+"_key")
}

// handleSSHAgentForwarding is a no-op on Windows: OpenSSH for Windows's
// ssh-agent listens on a named pipe rather than an SSH_AUTH_SOCK Unix
// socket, so there is nothing a forwarded socket could plug into.
func (ss *sshSession) handleSSHAgentForwarding(s gliderssh.Session, lu *userMeta) error {
	if gliderssh.AgentRequested(ss) && ss.conn.finalAction.AllowAgentForwarding {
		ss.logf("ssh: agent forwarding requested, but it is not supported on Windows")
	}
	return nil
}
