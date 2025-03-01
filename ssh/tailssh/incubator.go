// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// This file contains the code for the incubator process.  Tailscaled
// launches the incubator as the same user as it was launched as.  The
// incubator then registers a new session with the OS, sets its UID
// and groups to the specified `--uid`, `--gid` and `--groups`, and
// then launches the requested `--cmd`.

//go:build linux || (darwin && !ios) || freebsd || openbsd || plan9

package tailssh

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"

	"github.com/pkg/sftp"
	gossh "golang.org/x/crypto/ssh"
	"tailscale.com/cmd/tailscaled/childproc"
	"tailscale.com/hostinfo"
	"tailscale.com/tailcfg"
	"tailscale.com/types/logger"
	"tailscale.com/version/distro"
)

const (
	linux   = "linux"
	darwin  = "darwin"
	freebsd = "freebsd"
	openbsd = "openbsd"
)

func init() {
	childproc.Add("sftp", beSFTP)
}

var ptyName = func(f *os.File) (string, error) {
	return "", fmt.Errorf("unimplemented")
}

// maybeStartLoginSession informs the system that we are about to log someone
// in. On success, it may return a non-nil close func which must be closed to
// release the session.
// We can only do this if we are running as root.
// This is best effort to still allow running on machines where
// we don't support starting sessions, e.g. darwin.
// See maybeStartLoginSessionLinux.
var maybeStartLoginSession = func(dlogf logger.Logf, ia incubatorArgs) (close func() error) {
	return nil
}

// newIncubatorCommand returns a new exec.Cmd configured with
// `tailscaled be-child ssh` as the entrypoint.
//
// If ss.srv.tailscaledPath is empty, this method is equivalent to
// exec.CommandContext.
//
// The returned Cmd.Env is guaranteed to be nil; the caller populates it.
func (ss *sshSession) newIncubatorCommand(logf logger.Logf) (cmd *exec.Cmd, err error) {
	defer func() {
		if cmd.Env != nil {
			panic("internal error")
		}
	}()

	var isSFTP, isShell bool
	switch ss.Subsystem() {
	case "sftp":
		isSFTP = true
	case "":
		isShell = ss.RawCommand() == ""
	default:
		panic(fmt.Sprintf("unexpected subsystem: %v", ss.Subsystem()))
	}

	if ss.conn.srv.tailscaledPath == "" || runtime.GOOS == "plan9" {
		if isSFTP {
			// SFTP relies on the embedded Go-based SFTP server in tailscaled,
			// so without tailscaled, we can't serve SFTP.
			return nil, errors.New("no tailscaled found on path, can't serve SFTP")
		}

		loginShell := ss.conn.localUser.LoginShell()
		args := shellArgs(isShell, ss.RawCommand())
		logf("directly running %s %q", loginShell, args)
		return exec.CommandContext(ss.ctx, loginShell, args...), nil
	}

	lu := ss.conn.localUser
	ci := ss.conn.info
	groups := strings.Join(ss.conn.userGroupIDs, ",")
	remoteUser := ci.uprof.LoginName
	if ci.node.IsTagged() {
		remoteUser = strings.Join(ci.node.Tags().AsSlice(), ",")
	}

	incubatorArgs := []string{
		"be-child",
		"ssh",
		"--login-shell=" + lu.LoginShell(),
		"--uid=" + lu.Uid,
		"--gid=" + lu.Gid,
		"--groups=" + groups,
		"--local-user=" + lu.Username,
		"--home-dir=" + lu.HomeDir,
		"--remote-user=" + remoteUser,
		"--remote-ip=" + ci.src.Addr().String(),
		"--has-tty=false", // updated in-place by startWithPTY
		"--tty-name=",     // updated in-place by startWithPTY
	}

	// We have to check the below outside of the incubator process, because it
	// relies on the "getenforce" command being on the PATH, which it is not
	// when in the incubator.
	if runtime.GOOS == linux && hostinfo.IsSELinuxEnforcing() {
		incubatorArgs = append(incubatorArgs, "--is-selinux-enforcing")
	}

	nm := ss.conn.srv.lb.NetMap()
	forceV1Behavior := nm.HasCap(tailcfg.NodeAttrSSHBehaviorV1) && !nm.HasCap(tailcfg.NodeAttrSSHBehaviorV2)
	if forceV1Behavior {
		incubatorArgs = append(incubatorArgs, "--force-v1-behavior")
	}

	if debugTest.Load() {
		incubatorArgs = append(incubatorArgs, "--debug-test")
	}

	switch {
	case isSFTP:
		// Note that we include both the `--sftp` flag and a command to launch
		// tailscaled as `be-child sftp`. If login or su is available, and
		// we're not running with tailcfg.NodeAttrSSHBehaviorV1, this will
		// result in serving SFTP within a login shell, with full PAM
		// integration. Otherwise, we'll serve SFTP in the incubator process
		// with no PAM integration.
		incubatorArgs = append(incubatorArgs, "--sftp", fmt.Sprintf("--cmd=%s be-child sftp", ss.conn.srv.tailscaledPath))
	case isShell:
		incubatorArgs = append(incubatorArgs, "--shell")
	default:
		incubatorArgs = append(incubatorArgs, "--cmd="+ss.RawCommand())
	}

	allowSendEnv := nm.HasCap(tailcfg.NodeAttrSSHEnvironmentVariables)
	if allowSendEnv {
		env, err := filterEnv(ss.conn.acceptEnv, ss.Session.Environ())
		if err != nil {
			return nil, err
		}

		if len(env) > 0 {
			encoded, err := json.Marshal(env)
			if err != nil {
				return nil, fmt.Errorf("failed to encode environment: %w", err)
			}
			incubatorArgs = append(incubatorArgs, fmt.Sprintf("--encoded-env=%q", encoded))
		}
	}

	return exec.CommandContext(ss.ctx, ss.conn.srv.tailscaledPath, incubatorArgs...), nil
}

var debugIncubator bool
var debugTest atomic.Bool

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
	loginShell         string
	uid                int
	gid                int
	gids               []int
	localUser          string
	homeDir            string
	remoteUser         string
	remoteIP           string
	ttyName            string
	hasTTY             bool
	cmd                string
	isSFTP             bool
	isShell            bool
	forceV1Behavior    bool
	debugTest          bool
	isSELinuxEnforcing bool
	encodedEnv         string
}

func parseIncubatorArgs(args []string) (incubatorArgs, error) {
	var ia incubatorArgs
	var groups string

	flags := flag.NewFlagSet("", flag.ExitOnError)
	flags.StringVar(&ia.loginShell, "login-shell", "", "path to the user's preferred login shell")
	flags.IntVar(&ia.uid, "uid", 0, "the uid of local-user")
	flags.IntVar(&ia.gid, "gid", 0, "the gid of local-user")
	flags.StringVar(&groups, "groups", "", "comma-separated list of gids of local-user")
	flags.StringVar(&ia.localUser, "local-user", "", "the user to run as")
	flags.StringVar(&ia.homeDir, "home-dir", "/", "the user's home directory")
	flags.StringVar(&ia.remoteUser, "remote-user", "", "the remote user/tags")
	flags.StringVar(&ia.remoteIP, "remote-ip", "", "the remote Tailscale IP")
	flags.StringVar(&ia.ttyName, "tty-name", "", "the tty name (pts/3)")
	flags.BoolVar(&ia.hasTTY, "has-tty", false, "is the output attached to a tty")
	flags.StringVar(&ia.cmd, "cmd", "", "the cmd to launch, including all arguments (ignored in sftp mode)")
	flags.BoolVar(&ia.isShell, "shell", false, "is launching a shell (with no cmds)")
	flags.BoolVar(&ia.isSFTP, "sftp", false, "run sftp server (cmd is ignored)")
	flags.BoolVar(&ia.forceV1Behavior, "force-v1-behavior", false, "allow falling back to the su command if login is unavailable")
	flags.BoolVar(&ia.debugTest, "debug-test", false, "should debug in test mode")
	flags.BoolVar(&ia.isSELinuxEnforcing, "is-selinux-enforcing", false, "whether SELinux is in enforcing mode")
	flags.StringVar(&ia.encodedEnv, "encoded-env", "", "JSON encoded array of environment variables in '['key=value']' format")
	flags.Parse(args)

	for _, g := range strings.Split(groups, ",") {
		gid, err := strconv.Atoi(g)
		if err != nil {
			return ia, fmt.Errorf("unable to parse group id %q: %w", g, err)
		}
		ia.gids = append(ia.gids, gid)
	}

	return ia, nil
}

func (ia incubatorArgs) forwadedEnviron() ([]string, string, error) {
	environ := os.Environ()
	// pass through SSH_AUTH_SOCK environment variable to support ssh agent forwarding
	allowListKeys := "SSH_AUTH_SOCK"

	if ia.encodedEnv != "" {
		unquoted, err := strconv.Unquote(ia.encodedEnv)
		if err != nil {
			return nil, "", fmt.Errorf("unable to parse encodedEnv %q: %w", ia.encodedEnv, err)
		}

		var extraEnviron []string

		err = json.Unmarshal([]byte(unquoted), &extraEnviron)
		if err != nil {
			return nil, "", fmt.Errorf("unable to parse encodedEnv %q: %w", ia.encodedEnv, err)
		}

		environ = append(environ, extraEnviron...)

		for _, v := range extraEnviron {
			allowListKeys = fmt.Sprintf("%s,%s", allowListKeys, strings.Split(v, "=")[0])
		}
	}

	return environ, allowListKeys, nil
}

func handleInProcess(dlogf logger.Logf, ia incubatorArgs) error {
	if ia.isSFTP {
		return handleSFTPInProcess(dlogf, ia)
	}
	return handleSSHInProcess(dlogf, ia)
}

func handleSFTPInProcess(dlogf logger.Logf, ia incubatorArgs) error {
	dlogf("handling sftp")

	sessionCloser := maybeStartLoginSession(dlogf, ia)
	if sessionCloser != nil {
		defer sessionCloser()
	}
	return serveSFTP()
}

// beSFTP serves SFTP in-process.
func beSFTP(args []string) error {
	return serveSFTP()
}

func serveSFTP() error {
	server, err := sftp.NewServer(stdRWC{})
	if err != nil {
		return err
	}
	// TODO(https://github.com/pkg/sftp/pull/554): Revert the check for io.EOF,
	// when sftp is patched to report clean termination.
	if err := server.Serve(); err != nil && err != io.EOF {
		return err
	}
	return nil
}

// shouldAttemptLoginShell decides whether we should attempt to get a full
// login shell with the login or su commands. We will attempt a login shell
// if all of the following conditions are met.
//
// - We are running as root
// - This is not an SELinuxEnforcing host
//
// The last condition exists because if we're running on a SELinux-enabled
// system, neiher login nor su will be able to set the correct context for the
// shell. So, we don't bother trying to run them and instead fall back to using
// the incubator to launch the shell.
// See http://github.com/tailscale/tailscale/issues/4908.
func shouldAttemptLoginShell(dlogf logger.Logf, ia incubatorArgs) bool {
	if ia.forceV1Behavior && ia.isSFTP {
		// v1 behavior did not run SFTP within a login shell.
		dlogf("Forcing v1 behavior, won't use login shell for SFTP")
		return false
	}

	return runningAsRoot() && !ia.isSELinuxEnforcing
}

func runningAsRoot() bool {
	euid := os.Geteuid()
	return euid == 0
}

// handleSSHInProcess is a last resort if we couldn't use login or su. It
// registers a new session with the OS, sets its UID, GID and groups to the
// specified values, and then launches the requested `--cmd` in the user's
// login shell.
func handleSSHInProcess(dlogf logger.Logf, ia incubatorArgs) error {
	sessionCloser := maybeStartLoginSession(dlogf, ia)
	if sessionCloser != nil {
		defer sessionCloser()
	}

	environ, _, err := ia.forwadedEnviron()
	if err != nil {
		return err
	}

	args := shellArgs(ia.isShell, ia.cmd)
	dlogf("running %s %q", ia.loginShell, args)
	cmd := newCommand(ia.hasTTY, ia.loginShell, environ, args)
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

func newCommand(hasTTY bool, cmdPath string, cmdEnviron []string, cmdArgs []string) *exec.Cmd {
	cmd := exec.Command(cmdPath, cmdArgs...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = cmdEnviron

	if hasTTY {
		// If we were launched with a tty then we should mark that as the ctty
		// of the child. However, as the ctty is being passed from the parent
		// we set the child to foreground instead which also passes the ctty.
		// However, we can not do this if never had a tty to begin with.
		cmd.SysProcAttr = &syscall.SysProcAttr{
			//Foreground: true,
		}
	}

	return cmd
}

const (
	// This controls whether we assert that our privileges were dropped
	// using geteuid/getegid; it's a const and not an envknob because the
	// incubator doesn't see the parent's environment.
	//
	// TODO(andrew): remove this const and always do this after sufficient
	// testing, e.g. the 1.40 release
	assertPrivilegesWereDropped = true

	// TODO(andrew-d): verify that this works in more configurations before
	// enabling by default.
	assertPrivilegesWereDroppedByAttemptingToUnDrop = false
)

// launchProcess launches an incubator process for the provided session.
// It is responsible for configuring the process execution environment.
// The caller can wait for the process to exit by calling cmd.Wait().
//
// It sets ss.cmd, stdin, stdout, and stderr.
func (ss *sshSession) launchProcess() error {
	var err error
	ss.cmd, err = ss.newIncubatorCommand(ss.logf)
	if err != nil {
		return err
	}

	cmd := ss.cmd
	cmd.Dir = "/"
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

	return ss.startWithStdPipes()

	return nil
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

// startWithStdPipes starts cmd with os.Pipe for Stdin, Stdout and Stderr.
func (ss *sshSession) startWithStdPipes() (err error) {
	var rdStdin, wrStdout, wrStderr io.ReadWriteCloser
	defer func() {
		if err != nil {
			closeAll(rdStdin, ss.wrStdin, ss.rdStdout, wrStdout, ss.rdStderr, wrStderr)
		}
	}()
	if ss.cmd == nil {
		return errors.New("nil cmd")
	}
	if rdStdin, ss.wrStdin, err = os.Pipe(); err != nil {
		return err
	}
	if ss.rdStdout, wrStdout, err = os.Pipe(); err != nil {
		return err
	}
	if ss.rdStderr, wrStderr, err = os.Pipe(); err != nil {
		return err
	}
	ss.cmd.Stdin = rdStdin
	ss.cmd.Stdout = wrStdout
	ss.cmd.Stderr = wrStderr
	ss.childPipes = []io.Closer{rdStdin, wrStdout, wrStderr}
	return ss.cmd.Start()
}

func envForUser(u *userMeta) []string {
	return []string{
		fmt.Sprintf("SHELL=%s", u.LoginShell()),
		fmt.Sprintf("USER=%s", u.Username),
		fmt.Sprintf("HOME=%s", u.HomeDir),
		fmt.Sprintf("PATH=%s", defaultPathForUser(&u.User)),
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

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// loginArgs returns the arguments to use to exec the login binary.
func (ia *incubatorArgs) loginArgs(loginCmdPath string) []string {
	switch runtime.GOOS {
	case darwin:
		args := []string{
			loginCmdPath,
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
		if ia.cmd != "" {
			args = append(args, ia.loginShell, "-c", ia.cmd)
		}

		return args
	case linux:
		if distro.Get() == distro.Arch && !fileExists("/etc/pam.d/remote") {
			// See https://github.com/tailscale/tailscale/issues/4924
			//
			// Arch uses a different login binary that makes the -h flag set the PAM
			// service to "remote". So if they don't have that configured, don't
			// pass -h.
			return []string{loginCmdPath, "-f", ia.localUser, "-p"}
		}
		return []string{loginCmdPath, "-f", ia.localUser, "-h", ia.remoteIP, "-p"}
	case freebsd, openbsd:
		return []string{loginCmdPath, "-fp", "-h", ia.remoteIP, ia.localUser}
	}
	panic("unimplemented")
}

func shellArgs(isShell bool, cmd string) []string {
	if isShell {
		if runtime.GOOS == freebsd || runtime.GOOS == openbsd {
			// bsd shells don't support the "-l" option, so we can't run as a login shell
			return []string{}
		}
		return []string{"-l"}
	} else {
		return []string{"-c", cmd}
	}
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
