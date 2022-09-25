// Copyright (c) 2022 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// This file contains the code for the incubator process.  Tailscaled
// launches the incubator as the same user as it was launched as.  The
// incubator then registers a new session with the OS, sets its UID
// and groups to the specified `--uid`, `--gid` and `--groups`, and
// then launches the requested `--cmd`.

//go:build linux || (darwin && !ios)
// +build linux darwin,!ios

package tailssh

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"log/syslog"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"

	"github.com/creack/pty"
	"github.com/pkg/sftp"
	"github.com/u-root/u-root/pkg/termios"
	gossh "golang.org/x/crypto/ssh"
	"golang.org/x/sys/unix"
	"tailscale.com/cmd/tailscaled/childproc"
	"tailscale.com/tempfork/gliderlabs/ssh"
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
var maybeStartLoginSession = func(logf logger.Logf, ia incubatorArgs) (close func() error, err error) {
	return nil, nil
}

// newIncubatorCommand returns a new exec.Cmd configured with
// `tailscaled be-child ssh` as the entrypoint.
//
// If ss.srv.tailscaledPath is empty, this method is equivalent to
// exec.CommandContext.
func (ss *sshSession) newIncubatorCommand() *exec.Cmd {
	var (
		name    string
		args    []string
		isSFTP  bool
		isShell bool
	)
	switch ss.Subsystem() {
	case "sftp":
		isSFTP = true
	case "":
		name = loginShell(ss.conn.localUser.Uid)
		if rawCmd := ss.RawCommand(); rawCmd != "" {
			args = append(args, "-c", rawCmd)
		} else {
			isShell = true
			args = append(args, "-l") // login shell
		}
	default:
		panic(fmt.Sprintf("unexpected subsystem: %v", ss.Subsystem()))
	}

	if ss.conn.srv.tailscaledPath == "" {
		// TODO(maisem): this doesn't work with sftp
		return exec.CommandContext(ss.ctx, name, args...)
	}
	ss.conn.mu.Lock()
	lu := ss.conn.localUser
	ci := ss.conn.info
	gids := strings.Join(ss.conn.userGroupIDs, ",")
	ss.conn.mu.Unlock()
	remoteUser := ci.uprof.LoginName
	if len(ci.node.Tags) > 0 {
		remoteUser = strings.Join(ci.node.Tags, ",")
	}

	incubatorArgs := []string{
		"be-child",
		"ssh",
		"--uid=" + lu.Uid,
		"--gid=" + lu.Gid,
		"--groups=" + gids,
		"--local-user=" + lu.Username,
		"--remote-user=" + remoteUser,
		"--remote-ip=" + ci.src.Addr().String(),
		"--has-tty=false", // updated in-place by startWithPTY
		"--tty-name=",     // updated in-place by startWithPTY
	}

	if isSFTP {
		incubatorArgs = append(incubatorArgs, "--sftp")
	} else {
		if isShell {
			incubatorArgs = append(incubatorArgs, "--shell")
			// Currently (2022-05-09) `login` is only used for shells
			if lp, err := exec.LookPath("login"); err == nil {
				incubatorArgs = append(incubatorArgs, "--login-cmd="+lp)
			}
		}
		incubatorArgs = append(incubatorArgs, "--cmd="+name)
		if len(args) > 0 {
			incubatorArgs = append(incubatorArgs, "--")
			incubatorArgs = append(incubatorArgs, args...)
		}
	}
	return exec.CommandContext(ss.ctx, ss.conn.srv.tailscaledPath, incubatorArgs...)
}

const debugIncubator = false

type stdRWC struct{}

func (stdRWC) Read(p []byte) (n int, err error) {
	return os.Stdin.Read(p)
}

func (stdRWC) Write(b []byte) (n int, err error) {
	return os.Stdout.Write(b)
}

func (stdRWC) Close() error {
	os.Exit(0)
	return nil
}

type incubatorArgs struct {
	uid          uint64
	gid          int
	groups       string
	localUser    string
	remoteUser   string
	remoteIP     string
	ttyName      string
	hasTTY       bool
	cmdName      string
	isSFTP       bool
	isShell      bool
	loginCmdPath string
	cmdArgs      []string
}

func parseIncubatorArgs(args []string) (a incubatorArgs) {
	flags := flag.NewFlagSet("", flag.ExitOnError)
	flags.Uint64Var(&a.uid, "uid", 0, "the uid of local-user")
	flags.IntVar(&a.gid, "gid", 0, "the gid of local-user")
	flags.StringVar(&a.groups, "groups", "", "comma-separated list of gids of local-user")
	flags.StringVar(&a.localUser, "local-user", "", "the user to run as")
	flags.StringVar(&a.remoteUser, "remote-user", "", "the remote user/tags")
	flags.StringVar(&a.remoteIP, "remote-ip", "", "the remote Tailscale IP")
	flags.StringVar(&a.ttyName, "tty-name", "", "the tty name (pts/3)")
	flags.BoolVar(&a.hasTTY, "has-tty", false, "is the output attached to a tty")
	flags.StringVar(&a.cmdName, "cmd", "", "the cmd to launch (ignored in sftp mode)")
	flags.BoolVar(&a.isShell, "shell", false, "is launching a shell (with no cmds)")
	flags.BoolVar(&a.isSFTP, "sftp", false, "run sftp server (cmd is ignored)")
	flags.StringVar(&a.loginCmdPath, "login-cmd", "", "the path to `login` cmd")
	flags.Parse(args)
	a.cmdArgs = flags.Args()
	return a
}

// beIncubator is the entrypoint to the `tailscaled be-child ssh` subcommand.
// It is responsible for informing the system of a new login session for the user.
// This is sometimes necessary for mounting home directories and decrypting file
// systems.
//
// Tailscaled launches the incubator as the same user as it was
// launched as.  The incubator then registers a new session with the
// OS, sets its UID and groups to the specified `--uid`, `--gid` and
// `--groups` and then launches the requested `--cmd`.
func beIncubator(args []string) error {
	ia := parseIncubatorArgs(args)
	if ia.isSFTP && ia.isShell {
		return fmt.Errorf("--sftp and --shell are mutually exclusive")
	}

	logf := logger.Discard
	if debugIncubator {
		// We don't own stdout or stderr, so the only place we can log is syslog.
		if sl, err := syslog.New(syslog.LOG_INFO|syslog.LOG_DAEMON, "tailscaled-ssh"); err == nil {
			logf = log.New(sl, "", 0).Printf
		}
	}

	euid := uint64(os.Geteuid())
	runningAsRoot := euid == 0
	if runningAsRoot && ia.isShell && ia.loginCmdPath != "" && ia.hasTTY {
		// If we are trying to launch a login shell, just exec into login
		// instead. We can only do this if a TTY was requested, otherwise login
		// exits immediately, which breaks things likes mosh and VSCode.
		return unix.Exec(ia.loginCmdPath, ia.loginArgs(), os.Environ())
	}

	// Inform the system that we are about to log someone in.
	// We can only do this if we are running as root.
	// This is best effort to still allow running on machines where
	// we don't support starting sessions, e.g. darwin.
	sessionCloser, err := maybeStartLoginSession(logf, ia)
	if err == nil && sessionCloser != nil {
		defer sessionCloser()
	}
	var groupIDs []int
	for _, g := range strings.Split(ia.groups, ",") {
		gid, err := strconv.ParseInt(g, 10, 32)
		if err != nil {
			return err
		}
		groupIDs = append(groupIDs, int(gid))
	}

	if err := setGroups(groupIDs); err != nil {
		return err
	}
	if egid := os.Getegid(); egid != ia.gid {
		if err := syscall.Setgid(int(ia.gid)); err != nil {
			logf(err.Error())
			os.Exit(1)
		}
	}
	if euid != ia.uid {
		// Switch users if required before starting the desired process.
		if err := syscall.Setuid(int(ia.uid)); err != nil {
			logf(err.Error())
			os.Exit(1)
		}
	}
	if ia.isSFTP {
		logf("handling sftp")

		server, err := sftp.NewServer(stdRWC{})
		if err != nil {
			return err
		}
		return server.Serve()
	}

	cmd := exec.Command(ia.cmdName, ia.cmdArgs...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = os.Environ()

	if ia.hasTTY {
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
//
// It sets ss.cmd, stdin, stdout, and stderr.
func (ss *sshSession) launchProcess() error {
	ss.cmd = ss.newIncubatorCommand()

	cmd := ss.cmd
	cmd.Dir = ss.conn.localUser.HomeDir
	cmd.Env = append(cmd.Env, envForUser(ss.conn.localUser)...)
	for _, kv := range ss.Environ() {
		if acceptEnvPair(kv) {
			cmd.Env = append(cmd.Env, kv)
		}
	}

	ci := ss.conn.info
	cmd.Env = append(cmd.Env,
		fmt.Sprintf("SSH_CLIENT=%s %d %d", ci.src.Addr(), ci.src.Port(), ci.dst.Port()),
		fmt.Sprintf("SSH_CONNECTION=%s %d %s %d", ci.src.Addr(), ci.src.Port(), ci.dst.Addr(), ci.dst.Port()),
	)

	if ss.agentListener != nil {
		cmd.Env = append(cmd.Env, fmt.Sprintf("SSH_AUTH_SOCK=%s", ss.agentListener.Addr()))
	}

	ptyReq, winCh, isPty := ss.Pty()
	if !isPty {
		ss.logf("starting non-pty command: %+v", cmd.Args)
		return ss.startWithStdPipes()
	}
	ss.ptyReq = &ptyReq
	pty, err := ss.startWithPTY()
	if err != nil {
		return err
	}

	// We need to be able to close stdin and stdout separately later so make a
	// dup.
	ptyDup, err := syscall.Dup(int(pty.Fd()))
	if err != nil {
		return err
	}
	go resizeWindow(ptyDup /* arbitrary fd */, winCh)

	ss.stdin = pty
	ss.stdout = os.NewFile(uintptr(ptyDup), pty.Name())
	ss.stderr = nil // not available for pty

	return nil
}

func resizeWindow(fd int, winCh <-chan ssh.Window) {
	for win := range winCh {
		unix.IoctlSetWinsize(fd, syscall.TIOCSWINSZ, &unix.Winsize{
			Row: uint16(win.Height),
			Col: uint16(win.Width),
		})
	}
}

// opcodeShortName is a mapping of SSH opcode
// to mnemonic names expected by the termios package.
// These are meant to be platform independent.
var opcodeShortName = map[uint8]string{
	gossh.VINTR:         "intr",
	gossh.VQUIT:         "quit",
	gossh.VERASE:        "erase",
	gossh.VKILL:         "kill",
	gossh.VEOF:          "eof",
	gossh.VEOL:          "eol",
	gossh.VEOL2:         "eol2",
	gossh.VSTART:        "start",
	gossh.VSTOP:         "stop",
	gossh.VSUSP:         "susp",
	gossh.VDSUSP:        "dsusp",
	gossh.VREPRINT:      "rprnt",
	gossh.VWERASE:       "werase",
	gossh.VLNEXT:        "lnext",
	gossh.VFLUSH:        "flush",
	gossh.VSWTCH:        "swtch",
	gossh.VSTATUS:       "status",
	gossh.VDISCARD:      "discard",
	gossh.IGNPAR:        "ignpar",
	gossh.PARMRK:        "parmrk",
	gossh.INPCK:         "inpck",
	gossh.ISTRIP:        "istrip",
	gossh.INLCR:         "inlcr",
	gossh.IGNCR:         "igncr",
	gossh.ICRNL:         "icrnl",
	gossh.IUCLC:         "iuclc",
	gossh.IXON:          "ixon",
	gossh.IXANY:         "ixany",
	gossh.IXOFF:         "ixoff",
	gossh.IMAXBEL:       "imaxbel",
	gossh.IUTF8:         "iutf8",
	gossh.ISIG:          "isig",
	gossh.ICANON:        "icanon",
	gossh.XCASE:         "xcase",
	gossh.ECHO:          "echo",
	gossh.ECHOE:         "echoe",
	gossh.ECHOK:         "echok",
	gossh.ECHONL:        "echonl",
	gossh.NOFLSH:        "noflsh",
	gossh.TOSTOP:        "tostop",
	gossh.IEXTEN:        "iexten",
	gossh.ECHOCTL:       "echoctl",
	gossh.ECHOKE:        "echoke",
	gossh.PENDIN:        "pendin",
	gossh.OPOST:         "opost",
	gossh.OLCUC:         "olcuc",
	gossh.ONLCR:         "onlcr",
	gossh.OCRNL:         "ocrnl",
	gossh.ONOCR:         "onocr",
	gossh.ONLRET:        "onlret",
	gossh.CS7:           "cs7",
	gossh.CS8:           "cs8",
	gossh.PARENB:        "parenb",
	gossh.PARODD:        "parodd",
	gossh.TTY_OP_ISPEED: "tty_op_ispeed",
	gossh.TTY_OP_OSPEED: "tty_op_ospeed",
}

// startWithPTY starts cmd with a psuedo-terminal attached to Stdin, Stdout and Stderr.
func (ss *sshSession) startWithPTY() (ptyFile *os.File, err error) {
	ptyReq := ss.ptyReq
	cmd := ss.cmd
	if cmd == nil {
		return nil, errors.New("nil ss.cmd")
	}
	if ptyReq == nil {
		return nil, errors.New("nil ss.ptyReq")
	}

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
	ptyRawConn, err := tty.SyscallConn()
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

		for c, v := range ptyReq.Modes {
			if c == gossh.TTY_OP_ISPEED {
				tios.Ispeed = int(v)
				continue
			}
			if c == gossh.TTY_OP_OSPEED {
				tios.Ospeed = int(v)
				continue
			}
			k, ok := opcodeShortName[c]
			if !ok {
				ss.vlogf("unknown opcode: %d", c)
				continue
			}
			if _, ok := tios.CC[k]; ok {
				tios.CC[k] = uint8(v)
				continue
			}
			if _, ok := tios.Opts[k]; ok {
				tios.Opts[k] = v > 0
				continue
			}
			ss.vlogf("unsupported opcode: %v(%d)=%v", k, c, v)
		}

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
		fullPath := filepath.Join("/dev", ptyName)
		cmd.Env = append(cmd.Env, fmt.Sprintf("SSH_TTY=%s", fullPath))
	}

	if ptyReq.Term != "" {
		cmd.Env = append(cmd.Env, fmt.Sprintf("TERM=%s", ptyReq.Term))
	}
	cmd.Stdin = tty
	cmd.Stdout = tty
	cmd.Stderr = tty

	ss.logf("starting pty command: %+v", cmd.Args)
	if err = cmd.Start(); err != nil {
		return
	}
	return ptyFile, nil
}

// startWithStdPipes starts cmd with os.Pipe for Stdin, Stdout and Stderr.
func (ss *sshSession) startWithStdPipes() (err error) {
	var stdin io.WriteCloser
	var stdout, stderr io.ReadCloser
	defer func() {
		if err != nil {
			for _, c := range []io.Closer{stdin, stdout, stderr} {
				if c != nil {
					c.Close()
				}
			}
		}
	}()
	cmd := ss.cmd
	if cmd == nil {
		return errors.New("nil cmd")
	}
	stdin, err = cmd.StdinPipe()
	if err != nil {
		return err
	}
	stdout, err = cmd.StdoutPipe()
	if err != nil {
		return err
	}
	stderr, err = cmd.StderrPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	ss.stdin = stdin
	ss.stdout = stdout
	ss.stderr = stderr
	return nil
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
	return "/bin/sh"
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

// acceptEnvPair reports whether the environment variable key=value pair
// should be accepted from the client. It uses the same default as OpenSSH
// AcceptEnv.
func acceptEnvPair(kv string) bool {
	k, _, ok := strings.Cut(kv, "=")
	if !ok {
		return false
	}
	return k == "TERM" || k == "LANG" || strings.HasPrefix(k, "LC_")
}
