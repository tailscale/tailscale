// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// This file contains the code for the incubator process.  Tailscaled
// launches the incubator as the same user as it was launched as.  The
// incubator then registers a new session with the OS, sets its UID
// and groups to the specified `--uid`, `--gid` and `--groups`, and
// then launches the requested `--cmd`.

//go:build linux || (darwin && !ios) || freebsd || openbsd

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
	"sort"
	"strconv"
	"strings"
	"syscall"

	"github.com/creack/pty"
	"github.com/pkg/sftp"
	"github.com/u-root/u-root/pkg/termios"
	"go4.org/mem"
	gossh "golang.org/x/crypto/ssh"
	"golang.org/x/exp/slices"
	"golang.org/x/sys/unix"
	"tailscale.com/cmd/tailscaled/childproc"
	"tailscale.com/envknob"
	"tailscale.com/hostinfo"
	"tailscale.com/tempfork/gliderlabs/ssh"
	"tailscale.com/types/logger"
	"tailscale.com/util/lineread"
	"tailscale.com/version/distro"
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
//
// The returned Cmd.Env is guaranteed to be nil; the caller populates it.
func (ss *sshSession) newIncubatorCommand() (cmd *exec.Cmd) {
	defer func() {
		if cmd.Env != nil {
			panic("internal error")
		}
	}()
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
		name = loginShell(ss.conn.localUser)
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
	lu := ss.conn.localUser
	ci := ss.conn.info
	gids := strings.Join(ss.conn.userGroupIDs, ",")
	remoteUser := ci.uprof.LoginName
	if ci.node.IsTagged() {
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
		}
		if isShell || runtime.GOOS == "darwin" {
			// Only the macOS version of the login command supports executing a
			// command, all other versions only support launching a shell
			// without taking any arguments.
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
	if runningAsRoot && ia.loginCmdPath != "" {
		// Check if we can exec into the login command instead of trying to
		// incubate ourselves.
		if la := ia.loginArgs(); la != nil {
			return unix.Exec(ia.loginCmdPath, la, os.Environ())
		}
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

	if err := dropPrivileges(logf, int(ia.uid), ia.gid, groupIDs); err != nil {
		return err
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
	err = cmd.Run()
	if ee, ok := err.(*exec.ExitError); ok {
		ps := ee.ProcessState
		code := ps.ExitCode()
		if code < 0 {
			// TODO(bradfitz): do we need to also check the syscall.WaitStatus
			// and make our process look like it also died by signal/same signal
			// as our child process? For now we just do the exit code.
			fmt.Fprintf(os.Stderr, "[tailscale-ssh: process died: %v]\n", ps.String())
			code = 1 // for now. so we don't exit with negative
		}
		os.Exit(code)
	}
	return err
}

// TODO(andrew-d): verify that this works in more configurations before
// enabling by default.
const assertDropPrivileges = false

// dropPrivileges contains all the logic for dropping privileges to a different
// UID, GID, and set of supplementary groups. This function is
// security-sensitive and ordering-dependent; please be very cautious if/when
// refactoring.
//
// WARNING: if you change this function, you *MUST* run the TestDropPrivileges
// test in this package as root on at least Linux, FreeBSD and Darwin. This can
// be done by running:
//
//	go test -c ./ssh/tailssh/ && sudo ./tailssh.test -test.v -test.run TestDropPrivileges
func dropPrivileges(logf logger.Logf, wantUid, wantGid int, supplementaryGroups []int) error {
	fatalf := func(format string, args ...any) {
		logf(format, args...)
		os.Exit(1)
	}

	euid := os.Geteuid()
	egid := os.Getegid()

	if runtime.GOOS == "darwin" || runtime.GOOS == "freebsd" {
		// On FreeBSD and Darwin, the first entry returned from the
		// getgroups(2) syscall is the egid, and changing it with
		// setgroups(2) changes the egid of the process. This is
		// technically a violation of the POSIX standard; see the
		// following article for more detail:
		//    https://www.usenix.org/system/files/login/articles/325-tsafrir.pdf
		//
		// In this case, we add an entry at the beginning of the
		// groupIDs list containing the expected gid if it's not
		// already there, which modifies the egid and additional groups
		// as one unit.
		if len(supplementaryGroups) == 0 || supplementaryGroups[0] != wantGid {
			supplementaryGroups = append([]int{wantGid}, supplementaryGroups...)
		}
	}

	if err := setGroups(supplementaryGroups); err != nil {
		return err
	}
	if egid != wantGid {
		// On FreeBSD and Darwin, we may have already called the
		// equivalent of setegid(wantGid) via the call to setGroups,
		// above. However, per the manpage, setgid(getegid()) is an
		// allowed operation regardless of privilege level.
		//
		// FreeBSD:
		//	The setgid() system call is permitted if the specified ID
		//	is equal to the real group ID or the effective group ID
		//	of the process, or if the effective user ID is that of
		//	the super user.
		//
		// Darwin:
		//	The setgid() function is permitted if the effective
		//	user ID is that of the super user, or if the specified
		//	group ID is the same as the effective group ID.  If
		//	not, but the specified group ID is the same as the real
		//	group ID, setgid() will set the effective group ID to
		//	the real group ID.
		if err := syscall.Setgid(wantGid); err != nil {
			fatalf("Setgid(%d): %v", wantGid, err)
		}
	}
	if euid != wantUid {
		// Switch users if required before starting the desired process.
		if err := syscall.Setuid(wantUid); err != nil {
			fatalf("Setuid(%d): %v", wantUid, err)
		}
	}

	// If we changed either the UID or GID, defensively assert that we
	// cannot reset the it back to our original values, and that the
	// current egid/euid are the expected values after we change
	// everything; if not, we exit the process.
	if assertDropPrivileges {
		if egid != wantGid {
			if err := syscall.Setegid(egid); err == nil {
				fatalf("unexpectedly able to set egid back to %d", egid)
			}
		}
		if euid != wantUid {
			if err := syscall.Seteuid(euid); err == nil {
				fatalf("unexpectedly able to set euid back to %d", euid)
			}
		}

		if got := os.Getegid(); got != wantGid {
			fatalf("got egid=%d, want %d", got, wantGid)
		}
		if got := os.Geteuid(); got != wantUid {
			fatalf("got euid=%d, want %d", got, wantUid)
		}

		// TODO(andrew-d): assert that our supplementary groups are correct
	}

	return nil
}

// launchProcess launches an incubator process for the provided session.
// It is responsible for configuring the process execution environment.
// The caller can wait for the process to exit by calling cmd.Wait().
//
// It sets ss.cmd, stdin, stdout, and stderr.
func (ss *sshSession) launchProcess() error {
	ss.cmd = ss.newIncubatorCommand()

	cmd := ss.cmd
	homeDir := ss.conn.localUser.HomeDir
	if _, err := os.Stat(homeDir); err == nil {
		cmd.Dir = homeDir
	} else if os.IsNotExist(err) {
		// If the home directory doesn't exist, we can't chdir to it.
		// Instead, we'll chdir to the root directory.
		cmd.Dir = "/"
	} else {
		return err
	}
	cmd.Env = envForUser(ss.conn.localUser)
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

func loginShell(u *user.User) string {
	switch runtime.GOOS {
	case "linux":
		out, _ := exec.Command("getent", "passwd", u.Uid).Output()
		// out is "root:x:0:0:root:/root:/bin/bash"
		f := strings.SplitN(string(out), ":", 10)
		if len(f) > 6 {
			return strings.TrimSpace(f[6]) // shell
		}
	case "darwin":
		// Note: /Users/username is key, and not the same as u.HomeDir.
		out, _ := exec.Command("dscl", ".", "-read", filepath.Join("/Users", u.Username), "UserShell").Output()
		// out is "UserShell: /bin/bash"
		s, ok := strings.CutPrefix(string(out), "UserShell: ")
		if ok {
			return strings.TrimSpace(s)
		}
	}
	if e := os.Getenv("SHELL"); e != "" {
		return e
	}
	return "/bin/sh"
}

func envForUser(u *user.User) []string {
	return []string{
		fmt.Sprintf("SHELL=" + loginShell(u)),
		fmt.Sprintf("USER=" + u.Username),
		fmt.Sprintf("HOME=" + u.HomeDir),
		fmt.Sprintf("PATH=" + defaultPathForUser(u)),
	}
}

// defaultPathTmpl specifies the default PATH template to use for new sessions.
//
// If empty, a default value is used based on the OS & distro to match OpenSSH's
// usually-hardcoded behavior. (see
// https://github.com/tailscale/tailscale/issues/5285 for background).
//
// The template may contain @{HOME} or @{PAM_USER} which expand to the user's
// home directory and username, respectively. (PAM is not used, despite the
// name)
var defaultPathTmpl = envknob.RegisterString("TAILSCALE_SSH_DEFAULT_PATH")

func defaultPathForUser(u *user.User) string {
	if s := defaultPathTmpl(); s != "" {
		return expandDefaultPathTmpl(s, u)
	}
	isRoot := u.Uid == "0"
	switch distro.Get() {
	case distro.Debian:
		hi := hostinfo.New()
		if hi.Distro == "ubuntu" {
			// distro.Get's Debian includes Ubuntu. But see if it's actually Ubuntu.
			// Ubuntu doesn't empirically seem to distinguish between root and non-root for the default.
			// And it includes /snap/bin.
			return "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin"
		}
		if isRoot {
			return "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
		}
		return "/usr/local/bin:/usr/bin:/bin:/usr/bn/games"
	case distro.NixOS:
		return defaultPathForUserOnNixOS(u)
	}
	if isRoot {
		return "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
	}
	return "/usr/local/bin:/usr/bin:/bin"
}

func defaultPathForUserOnNixOS(u *user.User) string {
	var path string
	lineread.File("/etc/pam/environment", func(lineb []byte) error {
		if v := pathFromPAMEnvLine(lineb, u); v != "" {
			path = v
			return io.EOF // stop iteration
		}
		return nil
	})
	return path
}

func pathFromPAMEnvLine(line []byte, u *user.User) (path string) {
	if !mem.HasPrefix(mem.B(line), mem.S("PATH")) {
		return ""
	}
	rest := strings.TrimSpace(strings.TrimPrefix(string(line), "PATH"))
	if quoted, ok := strings.CutPrefix(rest, "DEFAULT="); ok {
		if path, err := strconv.Unquote(quoted); err == nil {
			return expandDefaultPathTmpl(path, u)
		}
	}
	return ""
}

func expandDefaultPathTmpl(t string, u *user.User) string {
	p := strings.NewReplacer(
		"@{HOME}", u.HomeDir,
		"@{PAM_USER}", u.Username,
	).Replace(t)
	if strings.Contains(p, "@{") {
		// If there are unknown expansions, conservatively fail closed.
		return ""
	}
	return p
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

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// loginArgs returns the arguments to use to exec the login binary.
// It returns nil if the login binary should not be used.
// The login binary is only used:
//   - on darwin, if the client is requesting a shell or a command.
//   - on linux and BSD, if the client is requesting a shell with a TTY.
func (ia *incubatorArgs) loginArgs() []string {
	if ia.isSFTP {
		return nil
	}
	switch runtime.GOOS {
	case "darwin":
		args := []string{
			ia.loginCmdPath,
			"-f", // already authenticated

			// login typically discards the previous environment, but we want to
			// preserve any environment variables that we currently have.
			"-p",

			"-h", ia.remoteIP, // -h is "remote host"
			ia.localUser,
		}
		if !ia.hasTTY {
			args[2] = "-pq" // -q is "quiet" which suppresses the login banner
		}
		if ia.cmdName != "" {
			args = append(args, ia.cmdName)
			args = append(args, ia.cmdArgs...)
		}
		return args
	case "linux":
		if !ia.isShell || !ia.hasTTY {
			// We can only use login command if a shell was requested with a TTY. If
			// there is no TTY, login exits immediately, which breaks things likes
			// mosh and VSCode.
			return nil
		}
		if distro.Get() == distro.Arch && !fileExists("/etc/pam.d/remote") {
			// See https://github.com/tailscale/tailscale/issues/4924
			//
			// Arch uses a different login binary that makes the -h flag set the PAM
			// service to "remote". So if they don't have that configured, don't
			// pass -h.
			return []string{ia.loginCmdPath, "-f", ia.localUser, "-p"}
		}
		return []string{ia.loginCmdPath, "-f", ia.localUser, "-h", ia.remoteIP, "-p"}
	case "freebsd", "openbsd":
		if !ia.isShell || !ia.hasTTY {
			// We can only use login command if a shell was requested with a TTY. If
			// there is no TTY, login exits immediately, which breaks things likes
			// mosh and VSCode.
			return nil
		}
		return []string{ia.loginCmdPath, "-fp", "-h", ia.remoteIP, ia.localUser}
	}
	panic("unimplemented")
}

func setGroups(groupIDs []int) error {
	if runtime.GOOS == "darwin" && len(groupIDs) > 16 {
		// darwin returns "invalid argument" if more than 16 groups are passed to syscall.Setgroups
		// some info can be found here:
		// https://opensource.apple.com/source/samba/samba-187.8/patches/support-darwin-initgroups-syscall.auto.html
		// this fix isn't great, as anyone reading this has probably just wasted hours figuring out why
		// some permissions thing isn't working, due to some arbitrary group ordering, but it at least allows
		// this to work for more things than it previously did.
		groupIDs = groupIDs[:16]
	}

	err := syscall.Setgroups(groupIDs)
	if err != nil && os.Geteuid() != 0 && groupsMatchCurrent(groupIDs) {
		// If we're not root, ignore a Setgroups failure if all groups are the same.
		return nil
	}
	return err
}

func groupsMatchCurrent(groupIDs []int) bool {
	existing, err := syscall.Getgroups()
	if err != nil {
		return false
	}
	if len(existing) != len(groupIDs) {
		return false
	}
	groupIDs = slices.Clone(groupIDs)
	sort.Ints(groupIDs)
	sort.Ints(existing)
	return slices.Equal(groupIDs, existing)
}
