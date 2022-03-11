// Copyright (c) 2022 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// This file contains the code for the incubator process.
// Taiscaled launches the incubator as the same user as it was launched as.
// The incbuator then registers a new session with the OS, sets its own UID to
// the specified `--uid`` and then lauches the requested `--cmd`.

//go:build linux || (darwin && !ios)
// +build linux darwin,!ios

package tailssh

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"log/syslog"
	"os"
	"os/exec"
	"os/user"
	"runtime"
	"strings"
	"syscall"

	"github.com/creack/pty"
	"github.com/gliderlabs/ssh"
	"github.com/u-root/u-root/pkg/termios"
	"golang.org/x/sys/unix"
	"tailscale.com/cmd/tailscaled/childproc"
	"tailscale.com/types/logger"
)

func init() {
	childproc.Add("ssh", beIncubator)
}

var ptyName = func(f *os.File) (string, error) {
	return "", fmt.Errorf("unimplemented")
}

// maybeStartLoginSession starts a new login session for the specified UID.
// On success, it may return a non-nil close func which must be closed to
// release the session.
// See maybeStartLoginSessionLinux.
var maybeStartLoginSession = func(logf logger.Logf, uid uint32, localUser, remoteUser, remoteHost, tty string) (close func() error, err error) {
	return nil, nil
}

// newIncubatorCommand returns a new exec.Cmd configured with
// `tailscaled be-child ssh` as the entrypoint.
// If tailscaled is empty, the desired cmd is executed directly.
func newIncubatorCommand(ctx context.Context, ci *sshConnInfo, lu *user.User, tailscaled, name string, args []string) *exec.Cmd {
	if tailscaled == "" {
		return exec.CommandContext(ctx, name, args...)
	}
	remoteUser := ci.uprof.LoginName
	if len(ci.node.Tags) > 0 {
		remoteUser = strings.Join(ci.node.Tags, ",")
	}

	incubatorArgs := []string{
		"be-child",
		"ssh",
		"--uid=" + lu.Uid,
		"--local-user=" + lu.Username,
		"--remote-user=" + remoteUser,
		"--remote-ip=" + ci.src.IP().String(),
		"--cmd=" + name,
		"--has-tty=false", // updated in-place by startWithPTY
		"--tty-name=",     // updated in-place by startWithPTY
	}
	if len(args) > 0 {
		incubatorArgs = append(incubatorArgs, "--")
		incubatorArgs = append(incubatorArgs, args...)
	}

	return exec.CommandContext(ctx, tailscaled, incubatorArgs...)
}

const debugIncubator = false

// beIncubator is the entrypoint to the `tailscaled be-child ssh` subcommand.
// It is responsible for informing the system of a new login session for the user.
// This is sometimes necessary for mounting home directories and decrypting file
// systems.
//
// Taiscaled launches the incubator as the same user as it was launched as.
// The incbuator then registers a new session with the OS, sets its own UID to
// the specified `--uid`` and then lauches the requested `--cmd`.
func beIncubator(args []string) error {
	var (
		flags      = flag.NewFlagSet("", flag.ExitOnError)
		uid        = flags.Uint64("uid", 0, "the uid of local-user")
		localUser  = flags.String("local-user", "", "the user to run as")
		remoteUser = flags.String("remote-user", "", "the remote user/tags")
		remoteIP   = flags.String("remote-ip", "", "the remote Tailscale IP")
		ttyName    = flags.String("tty-name", "", "the tty name (pts/3)")
		hasTTY     = flags.Bool("has-tty", false, "is the output attached to a tty")
		cmdName    = flags.String("cmd", "", "the cmd to launch")
	)
	if err := flags.Parse(args); err != nil {
		return err
	}
	cmdArgs := flags.Args()

	logf := logger.Discard
	if debugIncubator {
		// We don't own stdout or stderr, so the only place we can log is syslog.
		if sl, err := syslog.New(syslog.LOG_INFO|syslog.LOG_DAEMON, "tailscaled-ssh"); err == nil {
			logf = log.New(sl, "", 0).Printf
		}
	}

	euid := uint64(os.Geteuid())
	// Inform the system that we are about to log someone in.
	// We can only do this if we are running as root.
	sessionCloser, err := maybeStartLoginSession(logf, uint32(*uid), *localUser, *remoteUser, *remoteIP, *ttyName)
	if err == nil && sessionCloser != nil {
		defer sessionCloser()
	}
	if euid != *uid {
		// Switch users if required before starting the desired process.
		if err := syscall.Setuid(int(*uid)); err != nil {
			logf(err.Error())
			os.Exit(1)
		}
	}

	cmd := exec.Command(*cmdName, cmdArgs...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = os.Environ()

	if *hasTTY {
		// If we were launched with a tty then we should
		// mark that as the ctty of the child. However,
		// as the ctty is being passed from the parent
		// we set the child to foreground instead which
		// also passes the ctty.
		// However, we can not do this if never had a tty to
		// begin with.
		cmd.SysProcAttr = &syscall.SysProcAttr{
			Foreground: true,
		}
	}
	return cmd.Run()
}

// launchProcess launches an incubator process for the provided session.
// It is responsible for configuring the process execution environment.
// The caller can wait for the process to exit by calling cmd.Wait().
func (srv *server) launchProcess(ctx context.Context, s ssh.Session, ci *sshConnInfo, lu *user.User) (cmd *exec.Cmd, stdin io.WriteCloser, stdout, stderr io.Reader, err error) {
	shell := loginShell(lu.Uid)
	var args []string
	if rawCmd := s.RawCommand(); rawCmd != "" {
		args = append(args, "-c", rawCmd)
	} else {
		args = append(args, "-l") // login shell
	}
	ptyReq, winCh, isPty := s.Pty()

	cmd = newIncubatorCommand(ctx, ci, lu, srv.tailscaledPath, shell, args)
	cmd.Dir = lu.HomeDir
	cmd.Env = append(cmd.Env, envForUser(lu)...)
	cmd.Env = append(cmd.Env, s.Environ()...)
	cmd.Env = append(cmd.Env,
		fmt.Sprintf("SSH_CLIENT=%s %d %d", ci.src.IP(), ci.src.Port(), ci.dst.Port()),
		fmt.Sprintf("SSH_CONNECTION=%s %d %s %d", ci.src.IP(), ci.src.Port(), ci.dst.IP(), ci.dst.Port()),
	)
	srv.logf("ssh: starting: %+v", cmd.Args)

	if !isPty {
		stdin, stdout, stderr, err = startWithStdPipes(cmd)
		return
	}
	pty, err := startWithPTY(cmd, ptyReq)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	go resizeWindow(pty, winCh)
	// When using a pty we don't get a separate reader for stderr.
	return cmd, pty, pty, nil, nil
}

func resizeWindow(f *os.File, winCh <-chan ssh.Window) {
	for win := range winCh {
		unix.IoctlSetWinsize(int(f.Fd()), syscall.TIOCSWINSZ, &unix.Winsize{
			Row: uint16(win.Height),
			Col: uint16(win.Width),
		})
	}
}

// startWithPTY starts cmd with a psuedo-terminal attached to Stdin, Stdout and Stderr.
func startWithPTY(cmd *exec.Cmd, ptyReq ssh.Pty) (ptyFile *os.File, err error) {
	var tty *os.File
	ptyFile, tty, err = pty.Open()
	if err != nil {
		err = fmt.Errorf("pty.Open: %w", err)
		return
	}
	defer func() {
		if err != nil {
			ptyFile.Close()
			tty.Close()
		}
	}()
	ptyRawConn, err := ptyFile.SyscallConn()
	if err != nil {
		return nil, fmt.Errorf("SyscallConn: %w", err)
	}
	var ctlErr error
	if err := ptyRawConn.Control(func(fd uintptr) {
		// Load existing PTY settings to modify them & save them back.
		tios, err := termios.GTTY(int(fd))
		if err != nil {
			ctlErr = fmt.Errorf("GTTY: %w", err)
			return
		}

		// Set the rows & cols to those advertised from the ptyReq frame
		// received over SSH.
		tios.Row = int(ptyReq.Window.Height)
		tios.Col = int(ptyReq.Window.Width)

		// And these are just stumbling around in the dark temporarily
		// while we try to match OpenSSH settings. Empirically this makes
		// stty -a output be the same, but we're still having problems:
		// https://github.com/tailscale/tailscale/issues/4146
		// TODO(bradfitz): figure all this out and do something more principled
		// and confident and documented, once we have a clue.
		tios.Ispeed = 9600
		tios.Ospeed = 9600
		tios.CC["eol"] = 255
		tios.CC["eol2"] = 255
		tios.Opts["echok"] = false
		tios.Opts["imaxbel"] = true
		tios.Opts["iutf8"] = true
		tios.Opts["ixany"] = true
		tios.Opts["pendin"] = true

		// Save PTY settings.
		if _, err := tios.STTY(int(fd)); err != nil {
			ctlErr = fmt.Errorf("STTY: %w", err)
			return
		}
	}); err != nil {
		return nil, fmt.Errorf("ptyRawConn.Control: %w", err)
	}
	if ctlErr != nil {
		return nil, fmt.Errorf("ptyRawConn.Control func: %w", ctlErr)
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setctty: true,
		Setsid:  true,
	}
	updateStringInSlice(cmd.Args, "--has-tty=false", "--has-tty=true")
	if ptyName, err := ptyName(ptyFile); err == nil {
		updateStringInSlice(cmd.Args, "--tty-name=", "--tty-name="+ptyName)
	}

	if ptyReq.Term != "" {
		cmd.Env = append(cmd.Env, fmt.Sprintf("TERM=%s", ptyReq.Term))
	}
	cmd.Stdin = tty
	cmd.Stdout = tty
	cmd.Stderr = tty

	if err = cmd.Start(); err != nil {
		return
	}
	return ptyFile, nil
}

// startWithStdPipes starts cmd with os.Pipe for Stdin, Stdout and Stderr.
func startWithStdPipes(cmd *exec.Cmd) (stdin io.WriteCloser, stdout, stderr io.ReadCloser, err error) {
	defer func() {
		if err != nil {
			for _, c := range []io.Closer{stdin, stdout, stderr} {
				if c != nil {
					c.Close()
				}
			}
		}
	}()
	stdin, err = cmd.StdinPipe()
	if err != nil {
		return
	}
	stdout, err = cmd.StdoutPipe()
	if err != nil {
		return
	}
	stderr, err = cmd.StderrPipe()
	if err != nil {
		return
	}
	err = cmd.Start()
	return
}

func loginShell(uid string) string {
	switch runtime.GOOS {
	case "linux":
		out, _ := exec.Command("getent", "passwd", uid).Output()
		// out is "root:x:0:0:root:/root:/bin/bash"
		f := strings.SplitN(string(out), ":", 10)
		if len(f) > 6 {
			return strings.TrimSpace(f[6]) // shell
		}
	}
	if e := os.Getenv("SHELL"); e != "" {
		return e
	}
	return "/bin/bash"
}

func envForUser(u *user.User) []string {
	return []string{
		fmt.Sprintf("SHELL=" + loginShell(u.Uid)),
		fmt.Sprintf("USER=" + u.Username),
		fmt.Sprintf("HOME=" + u.HomeDir),
	}
}

// updateStringInSlice mutates ss to change the first occurrence of a
// to b.
func updateStringInSlice(ss []string, a, b string) {
	for i, s := range ss {
		if s == a {
			ss[i] = b
			return
		}
	}
}
