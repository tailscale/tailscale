// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// This file contains the code for the incubator process.  Tailscaled
// launches the incubator as the same user as it was launched as.  The
// incubator then registers a new session with the OS, sets its UID
// and groups to the specified `--uid`, `--gid` and `--groups`, and
// then launches the requested `--cmd`.

//go:build (linux && !android) || (darwin && !ios) || freebsd || openbsd

package tailssh

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"log"
	"log/syslog"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/creack/pty"
	"github.com/pkg/sftp"
	"github.com/u-root/u-root/pkg/termios"
	gossh "golang.org/x/crypto/ssh"
	"golang.org/x/sys/unix"
	"tailscale.com/cmd/tailscaled/childproc"
	"tailscale.com/hostinfo"
	"tailscale.com/tailcfg"
	"tailscale.com/tempfork/gliderlabs/ssh"
	"tailscale.com/types/logger"
	"tailscale.com/version/distro"
)

const (
	linux   = "linux"
	darwin  = "darwin"
	freebsd = "freebsd"
	openbsd = "openbsd"
	windows = "windows"
)

func init() {
	childproc.Add("ssh", beIncubator)
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

// truePaths are the common locations to find the true binary, in likelihood order.
var truePaths = [...]string{"/usr/bin/true", "/bin/true"}

// tryExecInDir tries to run a command in dir and returns nil if it succeeds.
// Otherwise, it returns a filesystem error or a timeout error if the command
// took too long.
func tryExecInDir(ctx context.Context, dir string) error {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	run := func(path string) error {
		cmd := exec.CommandContext(ctx, path)
		cmd.Dir = dir
		return cmd.Run()
	}

	// Assume that the following executables exist, are executable, and
	// immediately return.
	if runtime.GOOS == windows {
		windir := os.Getenv("windir")
		return run(filepath.Join(windir, "system32", "doskey.exe"))
	}
	// Execute the first "true" we find in the list.
	for _, path := range truePaths {
		// Note: LookPath does not consult $PATH when passed multi-label paths.
		if p, err := exec.LookPath(path); err == nil {
			return run(p)
		}
	}
	return exec.ErrNotFound
}

// newIncubatorCommand returns a new exec.Cmd configured with
// `tailscaled be-child ssh` as the entrypoint.
//
// If ss.srv.tailscaledPath is empty, this method is almost equivalent to
// exec.CommandContext. It will refuse to run in SFTP-mode. It will simulate the
// behavior of SSHD when by falling back to the root directory if it cannot run
// a command in the user’s home directory.
//
// The returned Cmd.Env is guaranteed to be nil; the caller populates it.
func (ss *sshSession) newIncubatorCommand(logf logger.Logf) (cmd *exec.Cmd, err error) {
	defer func() {
		if cmd != nil && cmd.Env != nil {
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

	if ss.conn.srv.tailscaledPath == "" {
		if isSFTP {
			// SFTP relies on the embedded Go-based SFTP server in tailscaled,
			// so without tailscaled, we can't serve SFTP.
			return nil, errors.New("no tailscaled found on path, can't serve SFTP")
		}

		loginShell := ss.conn.localUser.LoginShell()
		args := shellArgs(isShell, ss.RawCommand())
		logf("directly running %s %q", loginShell, args)
		cmd = exec.CommandContext(ss.ctx, loginShell, args...)

		// While running directly instead of using `tailscaled be-child`,
		// do what sshd does by running inside the home directory,
		// falling back to the root directory it doesn't have permissions.
		// This can happen if the system has networked home directories,
		// i.e. NFS or SMB, which enable root-squashing by default.
		cmd.Dir = ss.conn.localUser.HomeDir
		err := tryExecInDir(ss.ctx, cmd.Dir)
		switch {
		case errors.Is(err, exec.ErrNotFound):
			// /bin/true might not be installed on a barebones system,
			// so we assume that the home directory does not exist.
			cmd.Dir = "/"
		case errors.Is(err, fs.ErrPermission) || errors.Is(err, fs.ErrNotExist):
			// Ensure that cmd.Dir is the source of the error.
			var pathErr *fs.PathError
			if errors.As(err, &pathErr) && pathErr.Path == cmd.Dir {
				// If we cannot run loginShell in localUser.HomeDir,
				// we will try to run this command in the root directory.
				cmd.Dir = "/"
			} else {
				return nil, err
			}
		case err != nil:
			return nil, err
		}

		return cmd, nil
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

	cmd = exec.CommandContext(ss.ctx, ss.conn.srv.tailscaledPath, incubatorArgs...)
	// The incubator will chdir into the home directory after it drops privileges.
	cmd.Dir = "/"
	return cmd, nil
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

// forwardedEnviron returns the concatenation of the current environment with
// any environment variables specified in ia.encodedEnv.
//
// It also returns allowedExtraKeys, containing the env keys that were passed in
// to ia.encodedEnv.
func (ia incubatorArgs) forwardedEnviron() (env, allowedExtraKeys []string, err error) {
	environ := os.Environ()

	// pass through SSH_AUTH_SOCK environment variable to support ssh agent forwarding
	// TODO(bradfitz,percy): why is this listed specially? If the parent wanted to included
	// it, couldn't it have just passed it to the incubator in encodedEnv?
	// If it didn't, no reason for us to pass it to "su -w ..." if it's not in our env
	// anyway? (Surely we don't want to inherit the tailscaled parent SSH_AUTH_SOCK, if any)
	allowedExtraKeys = []string{"SSH_AUTH_SOCK"}

	if ia.encodedEnv != "" {
		unquoted, err := strconv.Unquote(ia.encodedEnv)
		if err != nil {
			return nil, nil, fmt.Errorf("unable to parse encodedEnv %q: %w", ia.encodedEnv, err)
		}

		var extraEnviron []string

		err = json.Unmarshal([]byte(unquoted), &extraEnviron)
		if err != nil {
			return nil, nil, fmt.Errorf("unable to parse encodedEnv %q: %w", ia.encodedEnv, err)
		}

		environ = append(environ, extraEnviron...)

		for _, kv := range extraEnviron {
			if k, _, ok := strings.Cut(kv, "="); ok {
				allowedExtraKeys = append(allowedExtraKeys, k)
			}
		}
	}

	return environ, allowedExtraKeys, nil
}

// beIncubator is the entrypoint to the `tailscaled be-child ssh` subcommand.
// It is responsible for informing the system of a new login session for the
// user. This is sometimes necessary for mounting home directories and
// decrypting file systems.
//
// Tailscaled launches the incubator as the same user as it was launched as.
func beIncubator(args []string) error {
	// To defend against issues like https://golang.org/issue/1435,
	// defensively lock our current goroutine's thread to the current
	// system thread before we start making any UID/GID/group changes.
	//
	// This shouldn't matter on Linux because syscall.AllThreadsSyscall is
	// used to invoke syscalls on all OS threads, but (as of 2023-03-23)
	// that function is not implemented on all platforms.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	ia, err := parseIncubatorArgs(args)
	if err != nil {
		return err
	}
	if ia.isSFTP && ia.isShell {
		return fmt.Errorf("--sftp and --shell are mutually exclusive")
	}

	dlogf := logger.Discard
	if debugIncubator {
		// We don't own stdout or stderr, so the only place we can log is syslog.
		if sl, err := syslog.New(syslog.LOG_INFO|syslog.LOG_DAEMON, "tailscaled-ssh"); err == nil {
			dlogf = log.New(sl, "", 0).Printf
		}
	} else if ia.debugTest {
		// In testing, we don't always have syslog, so log to a temp file.
		if logFile, err := os.OpenFile("/tmp/tailscalessh.log", os.O_APPEND|os.O_WRONLY, 0666); err == nil {
			lf := log.New(logFile, "", 0)
			dlogf = func(msg string, args ...any) {
				lf.Printf(msg, args...)
				logFile.Sync()
			}
			defer logFile.Close()
		}
	}

	if !shouldAttemptLoginShell(dlogf, ia) {
		dlogf("not attempting login shell")
		return handleInProcess(dlogf, ia)
	}

	// First try the login command
	if err := tryExecLogin(dlogf, ia); err != nil {
		return err
	}

	// If we got here, we weren't able to use login (because tryExecLogin
	// returned without replacing the running process), maybe we can use
	// su.
	if handled, err := trySU(dlogf, ia); handled {
		return err
	} else {
		dlogf("not attempting su")
		return handleInProcess(dlogf, ia)
	}
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

	if err := dropPrivileges(dlogf, ia); err != nil {
		return err
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

// tryExecLogin attempts to handle the ssh session by creating a full login
// shell using the login command. If it never tried, it returns nil. If it
// failed to do so, it returns an error.
//
// Creating a login shell in this way allows us to register the remote IP of
// the login session, trigger PAM authentication, and get the "remote" PAM
// profile.
//
// However, login is subject to some limitations.
//
// 1. login cannot be used to execute commands except on macOS.
// 2. On Linux and BSD, login requires a TTY to keep running.
//
// In these cases, tryExecLogin returns (false, nil) to indicate that processing
// should fall through to other methods, such as using the su command.
//
// Note that this uses unix.Exec to replace the current process, so in cases
// where we actually do run login, no subsequent Go code will execute.
func tryExecLogin(dlogf logger.Logf, ia incubatorArgs) error {
	// Only the macOS version of the login command supports executing a
	// command, all other versions only support launching a shell without
	// taking any arguments.
	if !ia.isShell && runtime.GOOS != darwin {
		dlogf("won't use login because we're not in a shell or on macOS")
		return nil
	}

	switch runtime.GOOS {
	case linux, freebsd, openbsd:
		if !ia.hasTTY {
			dlogf("can't use login because of missing TTY")
			// We can only use the login command if a shell was requested with
			// a TTY. If there is no TTY, login exits immediately, which
			// breaks things like mosh and VSCode.
			return nil
		}
	}

	loginCmdPath, err := exec.LookPath("login")
	if err != nil {
		dlogf("failed to get login args: %s", err)
		return nil
	}
	loginArgs := ia.loginArgs(loginCmdPath)
	dlogf("logging in with %+v", loginArgs)

	environ, _, err := ia.forwardedEnviron()
	if err != nil {
		return err
	}

	// If Exec works, the Go code will not proceed past this:
	err = unix.Exec(loginCmdPath, loginArgs, environ)

	// If we made it here, Exec failed.
	return err
}

// trySU attempts to start a login shell using su. If su is available and
// supports the necessary arguments, this returns true, plus the result of
// executing su. Otherwise, it returns (false, nil).
//
// Creating a login shell in this way allows us to trigger PAM authentication
// and get the "login" PAM profile.
//
// Unlike login, su often does not require a TTY, so on Linux hosts that have
// an su command which accepts the right flags, we'll use su instead of login
// when no TTY is available.
func trySU(dlogf logger.Logf, ia incubatorArgs) (handled bool, err error) {
	if ia.forceV1Behavior {
		// v1 behavior did not use su.
		dlogf("Forcing v1 behavior, won't use su")
		return false, nil
	}

	su := findSU(dlogf, ia)
	if su == "" {
		return false, nil
	}

	sessionCloser := maybeStartLoginSession(dlogf, ia)
	if sessionCloser != nil {
		defer sessionCloser()
	}

	environ, allowListEnvKeys, err := ia.forwardedEnviron()
	if err != nil {
		return false, err
	}

	loginArgs := []string{
		su,
		"-w", strings.Join(allowListEnvKeys, ","),
		"-l",
		ia.localUser,
	}
	if ia.cmd != "" {
		// Note - unlike the login command, su allows using both -l and -c.
		loginArgs = append(loginArgs, "-c", ia.cmd)
	}

	dlogf("logging in with %+v", loginArgs)

	// If Exec works, the Go code will not proceed past this:
	err = unix.Exec(su, loginArgs, environ)

	// If we made it here, Exec failed.
	return true, err
}

// findSU attempts to find an su command which supports the -l and -c flags.
// This actually calls the su command, which can cause side effects like
// triggering pam_mkhomedir. If a suitable su is not available, this returns
// "".
func findSU(dlogf logger.Logf, ia incubatorArgs) string {
	// Currently, we only support falling back to su on Linux. This
	// potentially could work on BSDs as well, but requires testing.
	if runtime.GOOS != linux {
		return ""
	}

	// gokrazy doesn't include su. And, if someone installs a breakglass/
	// debugging package on gokrazy, we don't want to use its su.
	if distro.Get() == distro.Gokrazy {
		return ""
	}

	su, err := exec.LookPath("su")
	if err != nil {
		dlogf("can't find su command: %v", err)
		return ""
	}

	_, allowListEnvKeys, err := ia.forwardedEnviron()
	if err != nil {
		return ""
	}

	// First try to execute su -w <allow listed env> -l <user> -c true
	// to make sure su supports the necessary arguments.
	err = exec.Command(
		su,
		"-w", strings.Join(allowListEnvKeys, ","),
		"-l",
		ia.localUser,
		"-c", "true",
	).Run()
	if err != nil {
		dlogf("su check failed: %s", err)
		return ""
	}

	return su
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

	if err := dropPrivileges(dlogf, ia); err != nil {
		return err
	}

	environ, _, err := ia.forwardedEnviron()
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
			Foreground: true,
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

// dropPrivileges calls doDropPrivileges with uid, gid, and gids from the given
// incubatorArgs.
func dropPrivileges(dlogf logger.Logf, ia incubatorArgs) error {
	return doDropPrivileges(dlogf, ia.uid, ia.gid, ia.gids, ia.homeDir)
}

// doDropPrivileges contains all the logic for dropping privileges to a different
// UID, GID, and set of supplementary groups. This function is
// security-sensitive and ordering-dependent; please be very cautious if/when
// refactoring.
//
// WARNING: if you change this function, you *MUST* run the TestDoDropPrivileges
// test in this package as root on at least Linux, FreeBSD and Darwin. This can
// be done by running:
//
//	go test -c ./ssh/tailssh/ && sudo ./tailssh.test -test.v -test.run TestDoDropPrivileges
func doDropPrivileges(dlogf logger.Logf, wantUid, wantGid int, supplementaryGroups []int, homeDir string) error {
	dlogf("dropping privileges")
	fatalf := func(format string, args ...any) {
		dlogf("[unexpected] error dropping privileges: "+format, args...)
		os.Exit(1)
	}

	euid := os.Geteuid()
	egid := os.Getegid()

	if runtime.GOOS == darwin || runtime.GOOS == freebsd {
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
	if assertPrivilegesWereDroppedByAttemptingToUnDrop {
		if egid != wantGid {
			if err := syscall.Setegid(egid); err == nil {
				fatalf("able to set egid back to %d", egid)
			}
		}
		if euid != wantUid {
			if err := syscall.Seteuid(euid); err == nil {
				fatalf("able to set euid back to %d", euid)
			}
		}
	}
	if assertPrivilegesWereDropped {
		if got := os.Getegid(); got != wantGid {
			fatalf("got egid=%d, want %d", got, wantGid)
		}
		if got := os.Geteuid(); got != wantUid {
			fatalf("got euid=%d, want %d", got, wantUid)
		}
		// TODO(andrew-d): assert that our supplementary groups are correct
	}

	// Prefer to run in user's homedir if possible. We ignore a failure to Chdir,
	// which just leaves us at "/" where we launched in the first place.
	dlogf("attempting to chdir to user's home directory %q", homeDir)
	if err := os.Chdir(homeDir); err != nil {
		dlogf("failed to chdir to user's home directory %q, continuing in current directory", homeDir)
	}

	return nil
}

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

	if sshDisablePTY() {
		ss.logf("pty support disabled by envknob")
		return errors.New("pty support disabled by envknob")
	}

	ss.ptyReq = &ptyReq
	pty, tty, err := ss.startWithPTY()
	if err != nil {
		return err
	}

	// We need to be able to close stdin and stdout separately later so make a
	// dup.
	ptyDup, err := syscall.Dup(int(pty.Fd()))
	if err != nil {
		pty.Close()
		tty.Close()
		return err
	}
	go resizeWindow(ptyDup /* arbitrary fd */, winCh)

	ss.wrStdin = pty
	ss.rdStdout = os.NewFile(uintptr(ptyDup), pty.Name())
	ss.rdStderr = nil // not available for pty
	ss.childPipes = []io.Closer{tty}

	return nil
}

func resizeWindow(fd int, winCh <-chan ssh.Window) {
	for win := range winCh {
		unix.IoctlSetWinsize(fd, syscall.TIOCSWINSZ, &unix.Winsize{
			Row:    uint16(win.Height),
			Col:    uint16(win.Width),
			Xpixel: uint16(win.WidthPixels),
			Ypixel: uint16(win.HeightPixels),
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

// startWithPTY starts cmd with a pseudo-terminal attached to Stdin, Stdout and Stderr.
func (ss *sshSession) startWithPTY() (ptyFile, tty *os.File, err error) {
	ptyReq := ss.ptyReq
	cmd := ss.cmd
	if cmd == nil {
		return nil, nil, errors.New("nil ss.cmd")
	}
	if ptyReq == nil {
		return nil, nil, errors.New("nil ss.ptyReq")
	}

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
		return nil, nil, fmt.Errorf("SyscallConn: %w", err)
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
		return nil, nil, fmt.Errorf("ptyRawConn.Control: %w", err)
	}
	if ctlErr != nil {
		return nil, nil, fmt.Errorf("ptyRawConn.Control func: %w", ctlErr)
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
	return ptyFile, tty, nil
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

func setGroups(groupIDs []int) error {
	if runtime.GOOS == darwin && len(groupIDs) > 16 {
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
