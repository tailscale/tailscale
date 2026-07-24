// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// This file contains the plan9-specific version of the incubator. Tailscaled
// launches the incubator as the same user as it was launched as. The
// incubator then registers a new session with the OS, sets its UID
// and groups to the specified `--uid`, `--gid` and `--groups`, and
// then launches the requested `--cmd`.

package tailssh

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"

	"github.com/go4org/plan9netshell"
	"github.com/pkg/sftp"
	"tailscale.com/cmd/tailscaled/childproc"
	"tailscale.com/tailcfg"
	"tailscale.com/types/logger"
)

func init() {
	childproc.Add("ssh", beIncubator)
	childproc.Add("sftp", beSFTP)
	childproc.Add("plan9-netshell", beNetshell)
}

// newIncubatorCommand returns a new exec.Cmd configured with
// `tailscaled be-child ssh` as the entrypoint.
//
// If ss.srv.tailscaledPath is empty, this method is equivalent to
// exec.CommandContext.
//
// If the acceptEnv policy accepted any client-supplied environment variables,
// they are passed to the child over a pipe rather than on the argv or in the
// child's environment; the read end is returned as envFile and is already
// installed as cmd.ExtraFiles[0], with the matching --env-fd flag on the argv.
// The caller owns envFile and must close it once cmd has been started. See
// incubator.go's newIncubatorCommand and forwardedEnvPayload for the full
// rationale.
//
// The returned Cmd.Env is guaranteed to be nil; the caller populates it.
func (ss *sshSession) newIncubatorCommand(logf logger.Logf) (cmd *exec.Cmd, envFile *os.File, err error) {
	defer func() {
		if cmd == nil {
			return
		}
		if cmd.Env != nil {
			panic("internal error")
		}
		// The --env-fd flag and the extra file must stay in lockstep; see
		// incubator.go's newIncubatorCommand.
		if hasFlag := slices.Contains(cmd.Args, "--env-fd="+strconv.Itoa(incubatorEnvFD)); hasFlag != (envFile != nil) ||
			hasFlag != (len(cmd.ExtraFiles) == 1) {
			panic("internal error: --env-fd and ExtraFiles out of sync")
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
			return nil, nil, errors.New("no tailscaled found on path, can't serve SFTP")
		}

		loginShell := ss.conn.localUser.LoginShell()
		logf("directly running /bin/rc -c %q", ss.RawCommand())
		return exec.CommandContext(ss.ctx, loginShell, "-c", ss.RawCommand()), nil, nil
	}

	lu := ss.conn.localUser
	ci := ss.conn.info
	remoteUser := ci.uprof.LoginName
	if ci.node.IsTagged() {
		remoteUser = strings.Join(ci.node.Tags().AsSlice(), ",")
	}

	incubatorArgs := []string{
		"be-child",
		"ssh",
		// TODO: "--uid=" + lu.Uid,
		// TODO: "--gid=" + lu.Gid,
		"--local-user=" + lu.Username,
		"--home-dir=" + lu.HomeDir,
		"--remote-user=" + remoteUser,
		"--remote-ip=" + ci.src.Addr().String(),
		"--has-tty=false", // updated in-place by startWithPTY
		"--tty-name=",     // updated in-place by startWithPTY
	}

	nm := ss.conn.srv.lb.NetMapNoPeers()
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
			return nil, nil, err
		}

		if len(env) > 0 {
			// The accepted environment may contain secrets, in both the
			// values and the key names, so none of it is placed on the argv
			// or in the child's own environment. Only the file descriptor
			// number travels on the argv.
			envFile, err = forwardedEnvFile(logf, ss.conn.acceptEnv, env)
			if err != nil {
				return nil, nil, err
			}
			incubatorArgs = append(incubatorArgs, "--env-fd="+strconv.Itoa(incubatorEnvFD))
		}
	}

	cmd = exec.CommandContext(ss.ctx, ss.conn.srv.tailscaledPath, incubatorArgs...)
	if envFile != nil {
		// os/exec maps ExtraFiles[0] to fd incubatorEnvFD in the child.
		cmd.ExtraFiles = []*os.File{envFile}
	}
	return cmd, envFile, nil
}

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

	// envFD is the file descriptor from which to read the client-forwarded
	// environment: a JSON forwardedEnvPayload written by the parent. It is 0
	// (never a valid value, that is stdin) when the parent forwarded nothing.
	envFD int

	// DEPRECATED: encodedEnv is deprecated and must not be used by new code.
	// It is parsed only so this child keeps working when exec'd by an
	// outdated parent tailscaled that still passes it.
	encodedEnv string

	// forwardedEnv holds the client-forwarded "KEY=VALUE" pairs this incubator
	// has accepted, as populated by loadForwardedEnv. It is not set by
	// parseIncubatorArgs.
	forwardedEnv []string
}

func parseIncubatorArgs(args []string) (incubatorArgs, error) {
	var ia incubatorArgs

	flags := flag.NewFlagSet("", flag.ExitOnError)
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
	flags.IntVar(&ia.envFD, "env-fd", 0, "file descriptor to read the client-forwarded environment from, if any")
	// DEPRECATED: retained for version-skew compatibility only. DO NOT USE.
	flags.StringVar(&ia.encodedEnv, "encoded-env", "", "deprecated; do not use")
	flags.Parse(args)
	return ia, nil
}

// loadForwardedEnv reads the client-forwarded environment the parent sent,
// from the --env-fd pipe and/or the deprecated --encoded-env flag, filters it
// and stores the result in ia.forwardedEnv. See incubator.go's
// loadForwardedEnv, which this mirrors.
func (ia *incubatorArgs) loadForwardedEnv() error {
	if fd := ia.envFD; fd != 0 {
		if fd < 3 {
			return fmt.Errorf("invalid --env-fd %d", fd)
		}
		f := os.NewFile(uintptr(fd), "ssh-forwarded-env")
		if f == nil {
			return fmt.Errorf("invalid --env-fd %d", fd)
		}
		defer f.Close()
		env, err := receiveForwardedEnv(f)
		if err != nil {
			return err
		}
		ia.forwardedEnv = env
	}

	if ia.encodedEnv != "" { // Legacy path for an outdated parent tailscaled.
		env, err := parseLegacyEncodedEnv(ia.encodedEnv)
		if err != nil {
			return err
		}
		ia.forwardedEnv = append(ia.forwardedEnv, env...)
	}

	return nil
}

// forwardedEnviron returns the environment to hand to the user's process: this
// incubator's own environment plus the client-forwarded variables read by
// loadForwardedEnv, which never replace a value already present. It also
// returns the names of the forwarded variables that survived.
func (ia incubatorArgs) forwardedEnviron() (env, allowedExtraKeys []string) {
	env, keys := mergeForwardedEnv(os.Environ(), ia.forwardedEnv)
	return env, append([]string{"SSH_AUTH_SOCK"}, keys...)
}

func beNetshell(args []string) error {
	plan9netshell.Main()
	return nil
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
	if ia.encodedEnv != "" {
		log.Printf("WARNING: tailscaled be-child: accepted SSH environment variables were passed via the deprecated --encoded-env flag; " +
			"the running tailscaled is outdated. Update tailscaled to the latest version and restart for the latest security fixes.")
	}
	// Drain and validate the forwarded environment before anything else uses
	// it; the pipe can only be read once.
	if err := ia.loadForwardedEnv(); err != nil {
		return err
	}
	if ia.isSFTP && ia.isShell {
		return fmt.Errorf("--sftp and --shell are mutually exclusive")
	}

	if ia.isShell {
		plan9netshell.Main()
		return nil
	}

	dlogf := logger.Discard
	if ia.debugTest {
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

	return handleInProcess(dlogf, ia)
}

func handleInProcess(dlogf logger.Logf, ia incubatorArgs) error {
	if ia.isSFTP {
		return handleSFTPInProcess(dlogf, ia)
	}
	return handleSSHInProcess(dlogf, ia)
}

func handleSFTPInProcess(dlogf logger.Logf, ia incubatorArgs) error {
	dlogf("handling sftp")

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

// handleSSHInProcess is a last resort if we couldn't use login or su. It
// registers a new session with the OS, sets its UID, GID and groups to the
// specified values, and then launches the requested `--cmd` in the user's
// login shell.
func handleSSHInProcess(dlogf logger.Logf, ia incubatorArgs) error {

	environ, _ := ia.forwardedEnviron()

	dlogf("running /bin/rc -c %q", ia.cmd)
	cmd := newCommand("/bin/rc", environ, []string{"-c", ia.cmd})
	err := cmd.Run()
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

func newCommand(cmdPath string, cmdEnviron []string, cmdArgs []string) *exec.Cmd {
	cmd := exec.Command(cmdPath, cmdArgs...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = cmdEnviron

	return cmd
}

// launchProcess launches an incubator process for the provided session.
// It is responsible for configuring the process execution environment.
// The caller can wait for the process to exit by calling cmd.Wait().
//
// It sets ss.cmd, stdin, stdout, and stderr.
func (ss *sshSession) launchProcess() error {
	var err error
	var envFile *os.File
	ss.cmd, envFile, err = ss.newIncubatorCommand(ss.logf)
	if err != nil {
		return err
	}
	if envFile != nil {
		// The child receives its own descriptor for the forwarded environment
		// pipe when it starts, so our copy is no longer needed once we return.
		defer envFile.Close()
	}

	cmd := ss.cmd
	cmd.Dir = "/"
	cmd.Env = append(os.Environ(), envForUser(ss.conn.localUser)...)
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
		fmt.Sprintf("user=%s", u.Username),
		fmt.Sprintf("home=%s", u.HomeDir),
		fmt.Sprintf("path=%s", defaultPathForUser(&u.User)),
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
	// Never forward structurally invalid or unsafe names, even during
	// bringup, so a client cannot spoof the incubator's env.
	if !validEnvName(k) || isDangerousEnvVar(k) {
		return false
	}
	return true // permit anything else on plan9 during bringup, for debugging at least
}
