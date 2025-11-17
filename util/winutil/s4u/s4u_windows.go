// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package s4u is an API for accessing Service-For-User (S4U) functionality on Windows.
package s4u

import (
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"io"
	"math"
	"os"
	"os/user"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"unsafe"

	"golang.org/x/sys/windows"
	"tailscale.com/cmd/tailscaled/childproc"
	"tailscale.com/types/logger"
	"tailscale.com/util/winutil"
	"tailscale.com/util/winutil/conpty"
)

func init() {
	childproc.Add("s4u", beRelay)
}

var errInsufficientCapabilityLevel = errors.New("insufficient capability level")

// ListGroupIDsForSSHPreAuthOnly returns user u's group memberships as a slice
// containing group SIDs. srcName must contain the name of the service that is
// retrieving this information. srcName must be non-empty, ASCII-only, and no
// longer than 8 characters.
//
// NOTE: This should only be used by Tailscale SSH! It is not a generic
// mechanism for access checks!
func ListGroupIDsForSSHPreAuthOnly(srcName string, u *user.User) ([]string, error) {
	tok, err := createToken(srcName, u, tokenTypeIdentification, CapImpersonateOnly)
	if err != nil {
		return nil, err
	}
	defer tok.Close()

	tokenGroups, err := tok.GetTokenGroups()
	if err != nil {
		return nil, err
	}

	result := make([]string, 0, tokenGroups.GroupCount)
	for _, group := range tokenGroups.AllGroups() {
		if group.Attributes&windows.SE_GROUP_ENABLED != 0 {
			result = append(result, group.Sid.String())
		}
	}

	return result, nil
}

type tokenType uint

const (
	tokenTypeIdentification tokenType = iota
	tokenTypeImpersonation
)

// createToken creates a new S4U access token for user u for the purposes
// specified by s4uType, with capability capLevel. srcName must contain the name
// of the service that is intended to use the token. srcName must be non-empty,
// ASCII-only, and no longer than 8 characters.
//
// When s4uType is tokenTypeImpersonation, the current OS thread's access token must have SeTcbPrivilege.
func createToken(srcName string, u *user.User, s4uType tokenType, capLevel CapabilityLevel) (tok windows.Token, err error) {
	if u == nil {
		return 0, os.ErrInvalid
	}

	var lsa *lsaSession
	switch s4uType {
	case tokenTypeIdentification:
		lsa, err = newLSASessionForQuery()
	case tokenTypeImpersonation:
		lsa, err = newLSASessionForLogon("")
	default:
		return 0, os.ErrInvalid
	}
	if err != nil {
		return 0, err
	}
	defer lsa.Close()

	return lsa.logonAs(srcName, u, capLevel)
}

// Session encapsulates an S4U login session.
type Session struct {
	refCnt      atomic.Int32
	logf        logger.Logf
	token       windows.Token
	userProfile *winutil.UserProfile
	capLevel    CapabilityLevel
}

// CapabilityLevel specifies the desired capabilities that will be supported by a Session.
type CapabilityLevel uint

const (
	// The Session supports Do but none of the StartProcess* methods.
	CapImpersonateOnly CapabilityLevel = iota
	// The Session supports both Do and the StartProcess* methods.
	CapCreateProcess
)

// Login logs user u into Windows on behalf of service srcName, loads the user's
// profile, and returns a Session that may be used for impersonating that user,
// or optionally creating processes as that user. Logs will be written to logf,
// if provided. srcName must be non-empty, ASCII-only, and no longer than 8
// characters.
//
// The current OS thread's access token must have SeTcbPrivilege.
func Login(logf logger.Logf, srcName string, u *user.User, capLevel CapabilityLevel) (sess *Session, err error) {
	token, err := createToken(srcName, u, tokenTypeImpersonation, capLevel)
	if err != nil {
		return nil, err
	}
	tokenCloseOnce := sync.OnceFunc(func() { token.Close() })
	defer func() {
		if err != nil {
			tokenCloseOnce()
		}
	}()

	sessToken := token
	if capLevel == CapCreateProcess {
		// Obtain token's security descriptor so that it may be applied to
		// a primary token.
		sd, err := windows.GetSecurityInfo(windows.Handle(token),
			windows.SE_KERNEL_OBJECT, windows.DACL_SECURITY_INFORMATION)
		if err != nil {
			return nil, err
		}

		sa := windows.SecurityAttributes{
			Length:             uint32(unsafe.Sizeof(windows.SecurityAttributes{})),
			SecurityDescriptor: sd,
		}

		// token is an impersonation token. Upgrade us to a primary token so that
		// our StartProcess* methods will work correctly.
		var dupToken windows.Token
		if err := windows.DuplicateTokenEx(token, 0, &sa, windows.SecurityImpersonation,
			windows.TokenPrimary, &dupToken); err != nil {
			return nil, err
		}
		sessToken = dupToken
		defer func() {
			if err != nil {
				sessToken.Close()
			}
		}()
		tokenCloseOnce()
	}

	userProfile, err := winutil.LoadUserProfile(sessToken, u)
	if err != nil {
		return nil, err
	}

	if logf == nil {
		logf = logger.Discard
	} else {
		logf = logger.WithPrefix(logf, "(s4u) ")
	}

	return &Session{logf: logf, token: sessToken, userProfile: userProfile, capLevel: capLevel}, nil
}

// Close unloads the user profile and S4U access token associated with the
// session. The close operation is not guaranteed to have finished when Close
// returns; it may remain alive until all processes created by ss have
// themselves been closed, and no more Do requests are pending.
func (ss *Session) Close() error {
	refs := ss.refCnt.Load()
	if (refs & 1) != 0 {
		// Close already called
		return nil
	}

	// Set the low bit to indicate that a close operation has been requested.
	// We don't have atomic OR so we need to use CAS. Sigh.
	for !ss.refCnt.CompareAndSwap(refs, refs|1) {
		refs = ss.refCnt.Load()
	}

	if refs > 1 {
		// Still active processes, just return.
		return nil
	}

	return ss.closeInternal()
}

func (ss *Session) closeInternal() error {
	if ss.userProfile != nil {
		if err := ss.userProfile.Close(); err != nil {
			return err
		}
		ss.userProfile = nil
	}

	if ss.token != 0 {
		if err := ss.token.Close(); err != nil {
			return err
		}
		ss.token = 0
	}
	return nil
}

// CapabilityLevel returns the CapabilityLevel that was specified when the
// session was created.
func (ss *Session) CapabilityLevel() CapabilityLevel {
	return ss.capLevel
}

// Do executes fn while impersonating ss's user. Impersonation only affects
// the current goroutine; any new goroutines spawned by fn will not be
// impersonated. Do may be called concurrently by multiple goroutines.
//
// Do returns an error if impersonation did not succeed and fn could not be run.
// If called after ss has already been closed, it will panic.
func (ss *Session) Do(fn func()) error {
	if fn == nil {
		return os.ErrInvalid
	}

	ss.addRef()
	defer ss.release()

	// Impersonation touches thread-local state.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if err := impersonateLoggedOnUser(ss.token); err != nil {
		return err
	}
	defer func() {
		if err := windows.RevertToSelf(); err != nil {
			// This is not recoverable in any way, shape, or form!
			panic(fmt.Sprintf("RevertToSelf failed: %v", err))
		}
	}()

	fn()
	return nil
}

func (ss *Session) addRef() {
	if (ss.refCnt.Add(2) & 1) != 0 {
		panic("addRef after Close")
	}
}

func (ss *Session) release() {
	rc := ss.refCnt.Add(-2)
	if rc < 0 {
		panic("negative refcount")
	}
	if rc == 1 {
		ss.closeInternal()
	}
}

type startProcessOpts struct {
	token    windows.Token
	extraEnv map[string]string
	ptySize  windows.Coord
	pipes    bool
}

// StartProcess creates a new process running under ss via cmdLineInfo.
// The process will either be started with its working directory set to the S4U
// user's profile directory, or for Administrative users, the system32
// directory. The child process will receive the S4U user's environment.
// extraEnv, when specified, contains any additional environment
// variables to be inserted into the environment.
//
// If called after ss has already been closed, StartProcess will panic.
func (ss *Session) StartProcess(cmdLineInfo winutil.CommandLineInfo, extraEnv map[string]string) (psp *Process, err error) {
	if ss.capLevel != CapCreateProcess {
		return nil, errInsufficientCapabilityLevel
	}

	opts := startProcessOpts{
		token:    ss.token,
		extraEnv: extraEnv,
	}
	return startProcessInternal(ss, ss.logf, cmdLineInfo, opts)
}

// StartProcessWithPTY creates a new process running under ss via cmdLineInfo
// with a pseudoconsole initialized to initialPtySize. The resulting Process
// will return non-nil values from Stdin and Stdout, but Stderr will return nil.
// The process will either be started with its working directory set to the S4U
// user's profile directory, or for Administrative users, the system32
// directory. The child process will receive the S4U user's environment.
// extraEnv, when specified, contains any additional environment
// variables to be inserted into the environment.
//
// If called after ss has already been closed, StartProcessWithPTY will panic.
func (ss *Session) StartProcessWithPTY(cmdLineInfo winutil.CommandLineInfo, extraEnv map[string]string, initialPtySize windows.Coord) (psp *Process, err error) {
	if ss.capLevel != CapCreateProcess {
		return nil, errInsufficientCapabilityLevel
	}

	opts := startProcessOpts{
		token:    ss.token,
		extraEnv: extraEnv,
		ptySize:  initialPtySize,
	}
	return startProcessInternal(ss, ss.logf, cmdLineInfo, opts)
}

// StartProcessWithPipes creates a new process running under ss via cmdLineInfo
// with all standard handles set to pipes. The resulting Process will return
// non-nil values from Stdin, Stdout, and Stderr.
// The process will either be started with its working directory set to the S4U
// user's profile directory, or for Administrative users, the system32
// directory. The child process will receive the S4U user's environment.
// extraEnv, when specified, contains any additional environment
// variables to be inserted into the environment.
//
// If called after ss has already been closed, StartProcessWithPipes will panic.
func (ss *Session) StartProcessWithPipes(cmdLineInfo winutil.CommandLineInfo, extraEnv map[string]string) (psp *Process, err error) {
	if ss.capLevel != CapCreateProcess {
		return nil, errInsufficientCapabilityLevel
	}

	opts := startProcessOpts{
		token:    ss.token,
		extraEnv: extraEnv,
		pipes:    true,
	}
	return startProcessInternal(ss, ss.logf, cmdLineInfo, opts)
}

// startProcessInternal is the common implementation behind Session's exported
// StartProcess* methods. It uses opts to distinguish between the various
// requested modes of operation.
//
// A note on pseudoconsoles:
// The conpty API currently does not provide a way to create a pseudoconsole for
// a different user than the current process. The way we deal with this is
// to first create a "relay" process running with the desired user token,
// and then create the actual requested process as a child of the relay,
// at which time we create the pseudoconsole. The relay simply copies the
// PTY's I/O into/out of its own stdin and stdout, which are piped to the
// parent still running as LocalSystem. We also relay pseudoconsole resize requests.
func startProcessInternal(ss *Session, logf logger.Logf, cmdLineInfo winutil.CommandLineInfo, opts startProcessOpts) (psp *Process, err error) {
	var sib winutil.StartupInfoBuilder
	defer sib.Close()

	var sp Process
	defer func() {
		if err != nil {
			sp.Close()
		}
	}()

	var zeroCoord windows.Coord
	ptySizeValid := opts.ptySize != zeroCoord
	useToken := opts.token != 0
	usePty := ptySizeValid && !useToken
	useRelay := ptySizeValid && useToken
	useSystem32WD := useToken && opts.token.IsElevated()

	if usePty {
		sp.pty, err = conpty.NewPseudoConsole(opts.ptySize)
		if err != nil {
			return nil, err
		}

		if err := sp.pty.ConfigureStartupInfo(&sib); err != nil {
			return nil, err
		}

		sp.wStdin = sp.pty.InputPipe()
		sp.rStdout = sp.pty.OutputPipe()
	} else if useRelay || opts.pipes {
		if sp.wStdin, sp.rStdout, sp.rStderr, err = createStdPipes(&sib); err != nil {
			return nil, err
		}
	}

	var relayStderr io.ReadCloser
	if useRelay {
		// Later on we're going to use stderr for logging instead of providing it to the caller.
		relayStderr = sp.rStderr
		sp.rStderr = nil
		defer func() {
			if err != nil {
				relayStderr.Close()
			}
		}()

		// Set up a pipe to send PTY resize requests.
		var resizeRead, resizeWrite windows.Handle
		if err := windows.CreatePipe(&resizeRead, &resizeWrite, nil, 0); err != nil {
			return nil, err
		}
		sp.wResize = os.NewFile(uintptr(resizeWrite), "wPTYResizePipe")
		defer windows.CloseHandle(resizeRead)
		if err := sib.InheritHandles(resizeRead); err != nil {
			return nil, err
		}

		// Revise the command line. First, get the existing one.
		_, _, strCmdLine, err := cmdLineInfo.Resolve()
		if err != nil {
			return nil, err
		}

		// Now rebuild it, passing the strCmdLine as the --cmd argument...
		newArgs := []string{
			"be-child", "s4u",
			"--resize", fmt.Sprintf("0x%x", uintptr(resizeRead)),
			"--x", strconv.Itoa(int(opts.ptySize.X)),
			"--y", strconv.Itoa(int(opts.ptySize.Y)),
			"--cmd", strCmdLine,
		}

		// ...to be passed in as arguments to our own executable.
		cmdLineInfo.ExePath, err = os.Executable()
		if err != nil {
			return nil, err
		}
		cmdLineInfo.SetArgs(newArgs)
	}

	exePath, cmdLine, cmdLineStr, err := cmdLineInfo.Resolve()
	if err != nil {
		return nil, err
	}
	logf("starting %s", cmdLineStr)

	var env []string
	var wd16 *uint16
	if useToken {
		env, err = opts.token.Environ(false)
		if err != nil {
			return nil, err
		}

		folderID := windows.FOLDERID_Profile
		if useSystem32WD {
			folderID = windows.FOLDERID_System
		}
		wd, err := opts.token.KnownFolderPath(folderID, windows.KF_FLAG_DEFAULT)
		if err != nil {
			return nil, err
		}
		wd16, err = windows.UTF16PtrFromString(wd)
		if err != nil {
			return nil, err
		}
	} else {
		env = os.Environ()
	}

	env = mergeEnv(env, opts.extraEnv)

	var env16 *uint16
	if useToken || len(opts.extraEnv) > 0 {
		env16 = winutil.NewEnvBlock(env)
	}

	if useToken {
		// We want the child process to be assigned to job such that when it exits,
		// its descendents within the job will be terminated as well.
		job, err := createJob()
		if err != nil {
			return nil, err
		}
		// We don't need to hang onto job beyond this func...
		defer job.Close()

		if err := sib.AssignToJob(job.Handle()); err != nil {
			return nil, err
		}

		// ...because we're now gonna make a read-only copy...
		qjob, err := job.QueryOnlyClone()
		if err != nil {
			return nil, err
		}
		defer qjob.Close()

		// ...which will be inherited by the child process.
		// When the child process terminates, the job will too.
		if err := sib.InheritHandles(qjob.Handle()); err != nil {
			return nil, err
		}
	}

	si, inheritHandles, creationFlags, err := sib.Resolve()
	if err != nil {
		return nil, err
	}

	var pi windows.ProcessInformation
	if useToken {
		// DETACHED_PROCESS so that the child does not receive a console.
		// CREATE_NEW_PROCESS_GROUP so that the child's console group is isolated from ours.
		creationFlags |= windows.DETACHED_PROCESS | windows.CREATE_NEW_PROCESS_GROUP
		doCreate := func() {
			err = windows.CreateProcessAsUser(opts.token, exePath, cmdLine, nil, nil, inheritHandles, creationFlags, env16, wd16, si, &pi)
		}
		switch {
		case useRelay:
			doCreate()
		case ss != nil:
			// We want to ensure that the executable is accessible via the token's
			// security context, not ours.
			if err := ss.Do(doCreate); err != nil {
				return nil, err
			}
		default:
			panic("should not have reached here")
		}
	} else {
		err = windows.CreateProcess(exePath, cmdLine, nil, nil, inheritHandles, creationFlags, env16, wd16, si, &pi)
	}
	if err != nil {
		return nil, err
	}
	windows.CloseHandle(pi.Thread)

	if relayStderr != nil {
		logw := logger.FuncWriter(logger.WithPrefix(logf, fmt.Sprintf("(s4u relay process %d [0x%x]) ", pi.ProcessId, pi.ProcessId)))
		go func() {
			defer relayStderr.Close()
			io.Copy(logw, relayStderr)
		}()
	}

	sp.hproc = pi.Process
	sp.pid = pi.ProcessId
	if ss != nil {
		ss.addRef()
		sp.sess = ss
	}
	return &sp, nil
}

type jobObject windows.Handle

func createJob() (job *jobObject, err error) {
	hjob, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			windows.CloseHandle(hjob)
		}
	}()

	limitInfo := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{
		BasicLimitInformation: windows.JOBOBJECT_BASIC_LIMIT_INFORMATION{
			// We want every process within the job to terminate when the job is closed.
			// We also want to allow processes within the job to create child processes
			// that are outside the job (otherwise you couldn't leave background
			// processes running after exiting a session, for example).
			// These flags also match those used by the Win32 port of OpenSSH.
			LimitFlags: windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | windows.JOB_OBJECT_LIMIT_BREAKAWAY_OK,
		},
	}
	_, err = windows.SetInformationJobObject(hjob,
		windows.JobObjectExtendedLimitInformation, uintptr(unsafe.Pointer(&limitInfo)),
		uint32(unsafe.Sizeof(limitInfo)))
	if err != nil {
		return nil, err
	}

	jo := jobObject(hjob)
	return &jo, nil
}

func (job *jobObject) Close() error {
	if hjob := job.Handle(); hjob != 0 {
		windows.CloseHandle(hjob)
		*job = 0
	}
	return nil
}

func (job *jobObject) Handle() windows.Handle {
	if job == nil {
		return 0
	}
	return windows.Handle(*job)
}

const _JOB_OBJECT_QUERY = 0x0004

func (job *jobObject) QueryOnlyClone() (*jobObject, error) {
	hjob := job.Handle()
	cp := windows.CurrentProcess()

	var dupe windows.Handle
	err := windows.DuplicateHandle(cp, hjob, cp, &dupe, _JOB_OBJECT_QUERY, true, 0)
	if err != nil {
		return nil, err
	}

	result := jobObject(dupe)
	return &result, nil
}

func createStdPipes(sib *winutil.StartupInfoBuilder) (stdin io.WriteCloser, stdout, stderr io.ReadCloser, err error) {
	var rStdin, wStdin windows.Handle
	if err := windows.CreatePipe(&rStdin, &wStdin, nil, 0); err != nil {
		return nil, nil, nil, err
	}
	defer func() {
		if err != nil {
			windows.CloseHandle(rStdin)
			windows.CloseHandle(wStdin)
		}
	}()

	var rStdout, wStdout windows.Handle
	if err := windows.CreatePipe(&rStdout, &wStdout, nil, 0); err != nil {
		return nil, nil, nil, err
	}
	defer func() {
		if err != nil {
			windows.CloseHandle(rStdout)
			windows.CloseHandle(wStdout)
		}
	}()

	var rStderr, wStderr windows.Handle
	if err := windows.CreatePipe(&rStderr, &wStderr, nil, 0); err != nil {
		return nil, nil, nil, err
	}
	defer func() {
		if err != nil {
			windows.CloseHandle(rStderr)
			windows.CloseHandle(wStderr)
		}
	}()

	if err := sib.SetStdHandles(rStdin, wStdout, wStderr); err != nil {
		return nil, nil, nil, err
	}

	stdin = os.NewFile(uintptr(wStdin), "wStdin")
	stdout = os.NewFile(uintptr(rStdout), "rStdout")
	stderr = os.NewFile(uintptr(rStderr), "rStderr")
	return stdin, stdout, stderr, nil
}

// Process encapsulates a child process started with a Session.
type Process struct {
	sess    *Session
	wStdin  io.WriteCloser
	rStdout io.ReadCloser
	rStderr io.ReadCloser
	wResize io.WriteCloser
	pty     *conpty.PseudoConsole
	hproc   windows.Handle
	pid     uint32
}

// Stdin returns the write side of a pipe connected to the child process's
// stdin, or nil if no I/O was requested.
func (sp *Process) Stdin() io.WriteCloser {
	return sp.wStdin
}

// Stdout returns the read side of a pipe connected to the child process's
// stdout, or nil if no I/O was requested.
func (sp *Process) Stdout() io.ReadCloser {
	return sp.rStdout
}

// Stderr returns the read side of a pipe connected to the child process's
// stderr, or nil if no I/O was requested.
func (sp *Process) Stderr() io.ReadCloser {
	return sp.rStderr
}

// Terminate kills the process.
func (sp *Process) Terminate() {
	if sp.hproc != 0 {
		windows.TerminateProcess(sp.hproc, 255)
	}
}

// Close waits for sp to complete and then cleans up any resources owned by it.
// Close must wait because the Session associated with sp should not be destroyed
// until all its processes have terminated. If necessary, call Terminate to
// forcibly end the process.
//
// If the process was created with a pseudoconsole then the caller must continue
// concurrently draining sp's stdout until either Close finishes executing, or EOF.
func (sp *Process) Close() error {
	for _, pc := range []*io.WriteCloser{&sp.wStdin, &sp.wResize} {
		if *pc == nil {
			continue
		}
		(*pc).Close()
		(*pc) = nil
	}

	if sp.pty != nil {
		if err := sp.pty.Close(); err != nil {
			return err
		}
		sp.pty = nil
	}

	if sp.hproc != 0 {
		if _, err := sp.Wait(); err != nil {
			return err
		}
		windows.CloseHandle(sp.hproc)
		sp.hproc = 0
		sp.pid = 0
		if sp.sess != nil {
			sp.sess.release()
			sp.sess = nil
		}
	}

	// Order is important here. Do not close sp.rStdout until _after_
	// ss.pty (when present) has been closed! We're going to do one better by
	// doing this after the process is done.
	for _, pc := range []*io.ReadCloser{&sp.rStdout, &sp.rStderr} {
		if *pc == nil {
			continue
		}
		(*pc).Close()
		(*pc) = nil
	}
	return nil
}

// Wait blocks the caller until sp terminates. It returns the process exit code.
// exitCode will be set to 254 if the process terminated but the exit code could
// not be retrieved.
func (sp *Process) Wait() (exitCode uint32, err error) {
	_, err = windows.WaitForSingleObject(sp.hproc, windows.INFINITE)
	if err == nil {
		if err := windows.GetExitCodeProcess(sp.hproc, &exitCode); err != nil {
			exitCode = 254
		}
	}
	return exitCode, err
}

// OSProcess returns an *os.Process associated with sp. This is useful for
// integration with external code that expects an os.Process.
func (sp *Process) OSProcess() (*os.Process, error) {
	if sp.hproc == 0 {
		return nil, winutil.ErrDefunctProcess
	}
	return os.FindProcess(int(sp.pid))
}

// PTYResizer returns a function to be called to resize the pseudoconsole.
// It returns nil if no pseudoconsole was requested when creating sp.
func (sp *Process) PTYResizer() func(windows.Coord) error {
	if sp.wResize != nil {
		wResize := sp.wResize
		return func(c windows.Coord) error {
			return binary.Write(wResize, binary.LittleEndian, c)
		}
	}

	if sp.pty != nil {
		pty := sp.pty
		return func(c windows.Coord) error {
			return pty.Resize(c)
		}
	}

	return nil
}

type relayArgs struct {
	command string
	resize  string
	ptyX    int
	ptyY    int
}

func parseRelayArgs(args []string) (a relayArgs) {
	flags := flag.NewFlagSet("", flag.ExitOnError)
	flags.StringVar(&a.command, "cmd", "", "the command to run")
	flags.StringVar(&a.resize, "resize", "", "handle to resize pipe")
	flags.IntVar(&a.ptyX, "x", 80, "initial width of pty")
	flags.IntVar(&a.ptyY, "y", 25, "initial height of pty")
	flags.Parse(args)
	return a
}

func flagSizeErr(flagName byte) error {
	return fmt.Errorf("--%c must be greater than zero and less than %d", flagName, math.MaxInt16)
}

const debugRelay = false

func beRelay(args []string) error {
	ra := parseRelayArgs(args)
	if ra.command == "" {
		return fmt.Errorf("--cmd must be specified")
	}

	bitSize := int(unsafe.Sizeof(windows.Handle(0)) * 8)
	resize64, err := strconv.ParseUint(ra.resize, 0, bitSize)
	if err != nil {
		return err
	}
	hResize := windows.Handle(resize64)
	if ft, _ := windows.GetFileType(hResize); ft != windows.FILE_TYPE_PIPE {
		return fmt.Errorf("--resize is an invalid handle type")
	}
	resize := os.NewFile(uintptr(hResize), "rPTYResizePipe")
	defer resize.Close()

	switch {
	case ra.ptyX <= 0 || ra.ptyX > math.MaxInt16:
		return flagSizeErr('x')
	case ra.ptyY <= 0 || ra.ptyY > math.MaxInt16:
		return flagSizeErr('y')
	default:
	}

	logf := logger.Discard
	if debugRelay {
		// Our parent process will write our stderr to its log.
		logf = func(format string, args ...any) {
			fmt.Fprintf(os.Stderr, format, args...)
		}
	}

	logf("starting")
	argv, err := windows.DecomposeCommandLine(ra.command)
	if err != nil {
		logf("DecomposeCommandLine failed: %v", err)
		return err
	}

	cli := winutil.CommandLineInfo{
		ExePath: argv[0],
	}
	cli.SetArgs(argv[1:])

	opts := startProcessOpts{
		ptySize: windows.Coord{X: int16(ra.ptyX), Y: int16(ra.ptyY)},
	}
	psp, err := startProcessInternal(nil, logf, cli, opts)
	if err != nil {
		logf("startProcessInternal failed: %v", err)
		return err
	}
	defer psp.Close()

	go resizeLoop(logf, resize, psp.PTYResizer())
	if debugRelay {
		go debugLogPTYInput(logf, psp.wStdin, os.Stdin)
		go debugLogPTYOutput(logf, os.Stdout, psp.rStdout)
	} else {
		go io.Copy(psp.wStdin, os.Stdin)
		go io.Copy(os.Stdout, psp.rStdout)
	}

	exitCode, err := psp.Wait()
	if err != nil {
		logf("waiting on relayed process: %v", err)
		return err
	}
	if exitCode > 0 {
		logf("relayed process returned %v", exitCode)
	}

	if err := psp.Close(); err != nil {
		logf("s4u.Process.Close error: %v", err)
		return err
	}
	return nil
}

func resizeLoop(logf logger.Logf, resizePipe io.Reader, resizeFn func(windows.Coord) error) {
	var coord windows.Coord
	for binary.Read(resizePipe, binary.LittleEndian, &coord) == nil {
		logf("resizing pty window to %#v", coord)
		resizeFn(coord)
	}
}

func debugLogPTYInput(logf logger.Logf, w io.Writer, r io.Reader) {
	logw := logger.FuncWriter(logger.WithPrefix(logf, "(pty input) "))
	io.Copy(io.MultiWriter(w, logw), r)
}

func debugLogPTYOutput(logf logger.Logf, w io.Writer, r io.Reader) {
	logw := logger.FuncWriter(logger.WithPrefix(logf, "(pty output) "))
	io.Copy(w, io.TeeReader(r, logw))
}

// mergeEnv returns the union of existingEnv and extraEnv, deduplicated and
// sorted.
func mergeEnv(existingEnv []string, extraEnv map[string]string) []string {
	if len(extraEnv) == 0 {
		return existingEnv
	}

	mergedMap := make(map[string]string, len(existingEnv)+len(extraEnv))
	for _, line := range existingEnv {
		k, v, _ := strings.Cut(line, "=")
		mergedMap[strings.ToUpper(k)] = v
	}

	for k, v := range extraEnv {
		mergedMap[strings.ToUpper(k)] = v
	}

	result := make([]string, 0, len(mergedMap))
	for k, v := range mergedMap {
		result = append(result, strings.Join([]string{k, v}, "="))
	}

	slices.SortFunc(result, func(a, b string) int {
		ka, _, _ := strings.Cut(a, "=")
		kb, _, _ := strings.Cut(b, "=")
		return strings.Compare(ka, kb)
	})
	return result
}
