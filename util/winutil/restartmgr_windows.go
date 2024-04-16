// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package winutil

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
	"unicode/utf16"
	"unsafe"

	"github.com/dblohm7/wingoes"
	"golang.org/x/sys/windows"
	"tailscale.com/types/logger"
	"tailscale.com/util/multierr"
)

var (
	// ErrDefunctProcess is returned by (*UniqueProcess).AsRestartableProcess
	// when the process no longer exists.
	ErrDefunctProcess = errors.New("process is defunct")
	// ErrProcessNotRestartable is returned by (*UniqueProcess).AsRestartableProcess
	// when the process has previously indicated that it must not be restarted
	// during a patch/upgrade.
	ErrProcessNotRestartable = errors.New("process is not restartable")
)

// Implementation note: the code in this file will be invoked from within
// MSI custom actions, so please try to return windows.Errno error codes
// whenever possible; this makes the action return more accurate errors to
// the installer engine.

const (
	_RESTART_NO_CRASH  = 1
	_RESTART_NO_HANG   = 2
	_RESTART_NO_PATCH  = 4
	_RESTART_NO_REBOOT = 8
)

func registerForRestart(opts RegisterForRestartOpts) error {
	var flags uint32

	if !opts.RestartOnCrash {
		flags |= _RESTART_NO_CRASH
	}
	if !opts.RestartOnHang {
		flags |= _RESTART_NO_HANG
	}
	if !opts.RestartOnUpgrade {
		flags |= _RESTART_NO_PATCH
	}
	if !opts.RestartOnReboot {
		flags |= _RESTART_NO_REBOOT
	}

	var cmdLine *uint16
	if opts.UseCmdLineArgs {
		if len(opts.CmdLineArgs) == 0 {
			// re-use our current args, excluding the exe name itself
			opts.CmdLineArgs = os.Args[1:]
		}

		var b strings.Builder
		for _, arg := range opts.CmdLineArgs {
			if b.Len() > 0 {
				b.WriteByte(' ')
			}
			b.WriteString(windows.EscapeArg(arg))
		}

		if b.Len() > 0 {
			var err error
			cmdLine, err = windows.UTF16PtrFromString(b.String())
			if err != nil {
				return err
			}
		}
	}

	hr := registerApplicationRestart(cmdLine, flags)
	if e := wingoes.ErrorFromHRESULT(hr); e.Failed() {
		return e
	}

	return nil
}

type _RMHANDLE uint32

// See https://web.archive.org/web/20231128212837/https://learn.microsoft.com/en-us/windows/win32/rstmgr/using-restart-manager-with-a-secondary-installer
const _INVALID_RMHANDLE = ^_RMHANDLE(0)

type _RM_UNIQUE_PROCESS struct {
	PID              uint32
	ProcessStartTime windows.Filetime
}

type _RM_APP_TYPE int32

const (
	_RmUnknownApp  _RM_APP_TYPE = 0
	_RmMainWindow  _RM_APP_TYPE = 1
	_RmOtherWindow _RM_APP_TYPE = 2
	_RmService     _RM_APP_TYPE = 3
	_RmExplorer    _RM_APP_TYPE = 4
	_RmConsole     _RM_APP_TYPE = 5
	_RmCritical    _RM_APP_TYPE = 1000
)

type _RM_APP_STATUS uint32

const (
	//lint:ignore U1000 maps to a win32 API
	_RmStatusUnknown        _RM_APP_STATUS = 0x0
	_RmStatusRunning        _RM_APP_STATUS = 0x1
	_RmStatusStopped        _RM_APP_STATUS = 0x2
	_RmStatusStoppedOther   _RM_APP_STATUS = 0x4
	_RmStatusRestarted      _RM_APP_STATUS = 0x8
	_RmStatusErrorOnStop    _RM_APP_STATUS = 0x10
	_RmStatusErrorOnRestart _RM_APP_STATUS = 0x20
	_RmStatusShutdownMasked _RM_APP_STATUS = 0x40
	_RmStatusRestartMasked  _RM_APP_STATUS = 0x80
)

type _RM_PROCESS_INFO struct {
	Process          _RM_UNIQUE_PROCESS
	AppName          [256]uint16
	ServiceShortName [64]uint16
	AppType          _RM_APP_TYPE
	AppStatus        _RM_APP_STATUS
	TSSessionID      uint32
	Restartable      int32 // Win32 BOOL
}

// RestartManagerSession represents an open Restart Manager session.
type RestartManagerSession interface {
	io.Closer
	// AddPaths adds the fully-qualified paths in fqPaths to the set of binaries
	// that will be monitored by this restart manager session. NOTE: This
	// method is expensive to call, so it is better to make a single call with
	// a larger slice than to make multiple calls with smaller slices.
	AddPaths(fqPaths []string) error
	// AffectedProcesses returns the UniqueProcess information for all running
	// processes that utilize the binaries previously specified by calls to
	// AddPaths.
	AffectedProcesses() ([]UniqueProcess, error)
	// Key returns the session key associated with this instance.
	Key() string
}

// rmSession encapsulates the necessary information to represent an open
// restart manager session.
//
// Implementation note: rmSession methods that return errors should use
// windows.Errno codes whenever possible, as we call them from the custom
// action DLL. MSI custom actions are expected to return windows.Errno values;
// to ensure our compliance with this expectation, we should also use those
// values. Failure to do so will result in a generic windows.Errno being
// returned to the Windows Installer, which obviously is less than ideal.
type rmSession struct {
	session _RMHANDLE
	key     string
	logf    logger.Logf
}

const _CCH_RM_SESSION_KEY = 32 // (excludes NUL terminator)

// NewRestartManagerSession creates a new RestartManagerSession that utilizes
// logf for logging.
func NewRestartManagerSession(logf logger.Logf) (RestartManagerSession, error) {
	var sessionKeyBuf [_CCH_RM_SESSION_KEY + 1]uint16
	result := rmSession{
		logf: logf,
	}
	if err := rmStartSession(&result.session, 0, &sessionKeyBuf[0]); err != nil {
		return nil, err
	}

	result.key = windows.UTF16ToString(sessionKeyBuf[:_CCH_RM_SESSION_KEY])
	return &result, nil
}

// AttachRestartManagerSession opens a connection to an existing session
// specified by sessionKey, using logf for logging.
func AttachRestartManagerSession(logf logger.Logf, sessionKey string) (RestartManagerSession, error) {
	sessionKey16, err := windows.UTF16PtrFromString(sessionKey)
	if err != nil {
		return nil, err
	}

	result := rmSession{
		key:  sessionKey,
		logf: logf,
	}
	if err := rmJoinSession(&result.session, sessionKey16); err != nil {
		return nil, err
	}
	return &result, nil
}

func (rms *rmSession) Close() error {
	if rms == nil || rms.session == _INVALID_RMHANDLE {
		return nil
	}
	if err := rmEndSession(rms.session); err != nil {
		return err
	}
	rms.session = _INVALID_RMHANDLE
	return nil
}

func (rms *rmSession) Key() string {
	return rms.key
}

func (rms *rmSession) AffectedProcesses() ([]UniqueProcess, error) {
	infos, err := rms.processList()
	if err != nil {
		return nil, err
	}

	result := make([]UniqueProcess, 0, len(infos))
	for _, info := range infos {
		result = append(result, UniqueProcess{
			_RM_UNIQUE_PROCESS: info.Process,
			CanReceiveGUIMsgs:  info.AppType == _RmMainWindow || info.AppType == _RmOtherWindow,
		})
	}

	return result, nil
}

func (rms *rmSession) processList() ([]_RM_PROCESS_INFO, error) {
	const maxAttempts = 5
	var avail, rebootReasons uint32
	needed := uint32(1)

	var buf []_RM_PROCESS_INFO
	err := error(windows.ERROR_MORE_DATA)
	numAttempts := 0
	for err == windows.ERROR_MORE_DATA && numAttempts < maxAttempts {
		numAttempts++
		buf = make([]_RM_PROCESS_INFO, needed)
		avail = needed
		err = rmGetList(rms.session, &needed, &avail, unsafe.SliceData(buf), &rebootReasons)
	}

	if err != nil {
		if err == windows.ERROR_SESSION_CREDENTIAL_CONFLICT {
			// Add some more context about the meaning of this error.
			err = fmt.Errorf("%w (the Restart Manager does not permit calling RmGetList from a process that did not originally create the session)", err)
		}
		return nil, err
	}

	return buf[:avail], nil
}

func (rms *rmSession) AddPaths(fqPaths []string) error {
	if len(fqPaths) == 0 {
		return nil
	}

	fqPaths16 := make([]*uint16, 0, len(fqPaths))
	for _, fqPath := range fqPaths {
		if !filepath.IsAbs(fqPath) {
			return fmt.Errorf("%w: paths must be fully-qualified", windows.ERROR_BAD_PATHNAME)
		}

		fqPath16, err := windows.UTF16PtrFromString(fqPath)
		if err != nil {
			return err
		}

		fqPaths16 = append(fqPaths16, fqPath16)
	}

	return rmRegisterResources(rms.session, uint32(len(fqPaths16)), unsafe.SliceData(fqPaths16), 0, nil, 0, nil)
}

// UniqueProcess contains the necessary information to uniquely identify a
// process in the face of potential PID reuse.
type UniqueProcess struct {
	_RM_UNIQUE_PROCESS
	// CanReceiveGUIMsgs is true when the process has open top-level windows.
	CanReceiveGUIMsgs bool
}

// AsRestartableProcess obtains a RestartableProcess populated using the
// information obtained from up.
func (up *UniqueProcess) AsRestartableProcess() (*RestartableProcess, error) {
	// We need PROCESS_QUERY_INFORMATION instead of PROCESS_QUERY_LIMITED_INFORMATION
	// in order for ProcessImageName to be able to work from within a privileged
	// Windows Installer process.
	// We need PROCESS_VM_READ for GetApplicationRestartSettings.
	// We need PROCESS_TERMINATE and SYNCHRONIZE to terminate the process and
	// to be able to wait for the terminated process's handle to signal.
	access := uint32(windows.PROCESS_QUERY_INFORMATION | windows.PROCESS_TERMINATE | windows.PROCESS_VM_READ | windows.SYNCHRONIZE)
	h, err := windows.OpenProcess(access, false, up.PID)
	if err != nil {
		return nil, fmt.Errorf("OpenProcess(%d[%#X]): %w", up.PID, up.PID, err)
	}
	defer func() {
		if h == 0 {
			return
		}
		windows.CloseHandle(h)
	}()

	var creationTime, exitTime, kernelTime, userTime windows.Filetime
	if err := windows.GetProcessTimes(h, &creationTime, &exitTime, &kernelTime, &userTime); err != nil {
		return nil, fmt.Errorf("GetProcessTimes: %w", err)
	}
	if creationTime != up.ProcessStartTime {
		// The PID has been reused and does not actually reference the original process.
		return nil, ErrDefunctProcess
	}

	var tok windows.Token
	if err := windows.OpenProcessToken(h, windows.TOKEN_QUERY, &tok); err != nil {
		return nil, fmt.Errorf("OpenProcessToken: %w", err)
	}
	defer tok.Close()

	tsSessionID, err := TSSessionID(tok)
	if err != nil {
		return nil, fmt.Errorf("TSSessionID: %w", err)
	}

	logonSessionID, err := LogonSessionID(tok)
	if err != nil {
		return nil, fmt.Errorf("LogonSessionID: %w", err)
	}

	img, err := ProcessImageName(h)
	if err != nil {
		return nil, fmt.Errorf("ProcessImageName: %w", err)
	}

	const _RESTART_MAX_CMD_LINE = 1024
	var cmdLine [_RESTART_MAX_CMD_LINE]uint16
	cmdLineLen := uint32(len(cmdLine))
	var rmFlags uint32
	hr := getApplicationRestartSettings(h, &cmdLine[0], &cmdLineLen, &rmFlags)
	// Not found is not an error; it just means that the app never set any restart settings.
	if e := wingoes.ErrorFromHRESULT(hr); e.Failed() && e != wingoes.ErrorFromErrno(windows.ERROR_NOT_FOUND) {
		return nil, fmt.Errorf("GetApplicationRestartSettings: %w", error(e))
	}
	if (rmFlags & _RESTART_NO_PATCH) != 0 {
		// The application explicitly stated that it cannot be restarted during
		// an upgrade.
		return nil, ErrProcessNotRestartable
	}

	var logonSID string
	// Non-fatal, so we'll proceed with best-effort.
	if tokenGroups, err := tok.GetTokenGroups(); err == nil {
		for _, group := range tokenGroups.AllGroups() {
			if (group.Attributes & windows.SE_GROUP_LOGON_ID) != 0 {
				logonSID = group.Sid.String()
				break
			}
		}
	}

	var userSID string
	// Non-fatal, so we'll proceed with best-effort.
	if tokenUser, err := tok.GetTokenUser(); err == nil {
		// Save the user's SID so that we can later check it against the currently
		// logged-in Tailscale profile.
		userSID = tokenUser.User.Sid.String()
	}

	result := &RestartableProcess{
		Process: *up,
		SessionInfo: SessionID{
			LogonSession: logonSessionID,
			TSSession:    tsSessionID,
		},
		CommandLineInfo: CommandLineInfo{
			ExePath: img,
			Args:    windows.UTF16ToString(cmdLine[:cmdLineLen]),
		},
		LogonSID: logonSID,
		UserSID:  userSID,
		handle:   h,
	}

	runtime.SetFinalizer(result, func(rp *RestartableProcess) { rp.Close() })
	h = 0
	return result, nil
}

// RestartableProcess contains the necessary information to uniquely identify
// an existing process, as well as the necessary information to be able to
// terminate it and later start a new instance in the identical logon session
// to the previous instance.
type RestartableProcess struct {
	// Process uniquely identifies the existing process.
	Process UniqueProcess
	// SessionInfo uniquely identifies the Terminal Services (RDP) and logon
	// sessions the existing process is running under.
	SessionInfo SessionID
	// CommandLineInfo contains the command line information necessary for restarting.
	CommandLineInfo CommandLineInfo
	// LogonSID contains the stringified SID of the existing process's token's logon session.
	LogonSID string
	// UserSID contains the stringified SID of the existing process's token's user.
	UserSID string
	// handle specifies the Win32 HANDLE associated with the existing process.
	// When non-zero, it includes access rights for querying, terminating, and synchronizing.
	handle windows.Handle
	// hasExitCode is true when the exitCode field is valid.
	hasExitCode bool
	// exitCode contains exit code returned by this RestartableProcess once
	// its termination has been recorded by (RestartableProcesses).Terminate.
	// It is only valid when hasExitCode == true.
	exitCode uint32
}

func (rp *RestartableProcess) Close() error {
	if rp.handle == 0 {
		return nil
	}
	windows.CloseHandle(rp.handle)
	runtime.SetFinalizer(rp, nil)
	rp.handle = 0
	return nil
}

// RestartableProcesses is a map of PID to *RestartableProcess instance.
type RestartableProcesses map[uint32]*RestartableProcess

// NewRestartableProcesses instantiates a new RestartableProcesses.
func NewRestartableProcesses() RestartableProcesses {
	return make(RestartableProcesses)
}

// Add inserts rp into rps.
func (rps RestartableProcesses) Add(rp *RestartableProcess) {
	if rp != nil {
		rps[rp.Process.PID] = rp
	}
}

// Delete removes rp from rps.
func (rps RestartableProcesses) Delete(rp *RestartableProcess) {
	if rp != nil {
		delete(rps, rp.Process.PID)
	}
}

// Close invokes (*RestartableProcess).Close on every value in rps, and then
// clears rps.
func (rps RestartableProcesses) Close() error {
	for _, v := range rps {
		v.Close()
	}
	clear(rps)
	return nil
}

// _MAXIMUM_WAIT_OBJECTS is the Win32 constant for the maximum number of
// handles that a call to WaitForMultipleObjects may receive at once.
const _MAXIMUM_WAIT_OBJECTS = 64

// Terminate forcibly terminates all processes in rps using exitCode, and then
// waits for their process handles to signal, up to timeout.
func (rps RestartableProcesses) Terminate(logf logger.Logf, exitCode uint32, timeout time.Duration) error {
	if len(rps) == 0 {
		return nil
	}

	millis, err := wingoes.DurationToTimeoutMilliseconds(timeout)
	if err != nil {
		return err
	}

	errs := make([]error, 0, len(rps))
	procs := make([]*RestartableProcess, 0, len(rps))
	handles := make([]windows.Handle, 0, len(rps))
	for _, v := range rps {
		if err := windows.TerminateProcess(v.handle, exitCode); err != nil {
			if err == windows.ERROR_ACCESS_DENIED {
				// If v terminated before we attempted to terminate, we'll receive
				// ERROR_ACCESS_DENIED, which is not really an error worth reporting in
				// our use case. Just obtain the exit code and then close the process.
				if err := windows.GetExitCodeProcess(v.handle, &v.exitCode); err != nil {
					logf("GetExitCodeProcess failed: %v", err)
				} else {
					v.hasExitCode = true
				}
				v.Close()
			} else {
				errs = append(errs, &terminationError{rp: v, err: err})
			}
			continue
		}
		procs = append(procs, v)
		handles = append(handles, v.handle)
	}

	for len(handles) > 0 {
		// WaitForMultipleObjects can only wait on _MAXIMUM_WAIT_OBJECTS handles per
		// call, so we batch them as necessary.
		count := uint32(min(len(handles), _MAXIMUM_WAIT_OBJECTS))
		waitCode, err := windows.WaitForMultipleObjects(handles[:count], true, millis)
		if err != nil {
			errs = append(errs, fmt.Errorf("waiting on terminated process handles: %w", err))
			break
		}
		if e := windows.Errno(waitCode); e == windows.WAIT_TIMEOUT {
			errs = append(errs, fmt.Errorf("waiting on terminated process handles: %w", error(e)))
			break
		}
		if waitCode >= windows.WAIT_OBJECT_0 && waitCode < (windows.WAIT_OBJECT_0+count) {
			// The first count process handles have all been signaled. Close them out.
			for _, proc := range procs[:count] {
				if err := windows.GetExitCodeProcess(proc.handle, &proc.exitCode); err != nil {
					logf("GetExitCodeProcess failed: %v", err)
				} else {
					proc.hasExitCode = true
				}
				proc.Close()
			}
			procs = procs[count:]
			handles = handles[count:]
			continue
		}
		// We really shouldn't be reaching this point
		panic(fmt.Sprintf("unexpected state from WaitForMultipleObjects: %d", waitCode))
	}

	if len(errs) != 0 {
		return multierr.New(errs...)
	}
	return nil
}

type terminationError struct {
	rp  *RestartableProcess
	err error
}

func (te *terminationError) Error() string {
	pid := te.rp.Process.PID
	return fmt.Sprintf("terminating process %d (%#X): %v", pid, pid, te.err)
}

func (te *terminationError) Unwrap() error {
	return te.err
}

// SessionID encapsulates the necessary information for uniquely identifying
// sessions. In particular, SessionID contains enough information to detect
// reuse of Terminal Service session IDs.
type SessionID struct {
	// LogonSession is the NT logon session ID.
	LogonSession windows.LUID
	// TSSession is the terminal services session ID.
	TSSession uint32
}

// OpenToken obtains the security token associated with sessID.
func (sessID *SessionID) OpenToken() (windows.Token, error) {
	var token windows.Token
	if err := windows.WTSQueryUserToken(sessID.TSSession, &token); err != nil {
		return 0, err
	}

	var err error
	defer func() {
		if err != nil {
			token.Close()
		}
	}()

	tokenLogonSession, err := LogonSessionID(token)
	if err != nil {
		return 0, err
	}

	if tokenLogonSession != sessID.LogonSession {
		err = windows.ERROR_NO_SUCH_LOGON_SESSION
		return 0, err
	}

	return token, nil
}

// ContainsToken determines whether token is contained within sessID.
func (sessID *SessionID) ContainsToken(token windows.Token) (bool, error) {
	tokenTSSessionID, err := TSSessionID(token)
	if err != nil {
		return false, err
	}

	if tokenTSSessionID != sessID.TSSession {
		return false, nil
	}

	tokenLogonSession, err := LogonSessionID(token)
	if err != nil {
		return false, err
	}

	return tokenLogonSession == sessID.LogonSession, nil
}

// This is the Window Station and Desktop within a particular session that must
// be specified for interactive processes: "Winsta0\\default\x00"
var defaultDesktop = unsafe.SliceData([]uint16{'W', 'i', 'n', 's', 't', 'a', '0', '\\', 'd', 'e', 'f', 'a', 'u', 'l', 't', 0})

// CommandLineInfo manages the necessary information for creating a Win32
// process using a specific command line.
type CommandLineInfo struct {
	// ExePath must be a fully-qualified path to a Windows executable binary.
	ExePath string
	// Args must be any arguments supplied to the process, excluding the
	// path to the binary itself. Args must be properly quoted according to
	// Windows path rules. To create a properly quoted Args from scratch, call the
	// SetArgs method instead.
	Args string `json:",omitempty"`
}

// SetArgs converts args to a string quoted as necessary to satisfy the rules
// for Win32 command lines, and sets cli.Args to that string.
func (cli *CommandLineInfo) SetArgs(args []string) {
	var buf strings.Builder
	for _, arg := range args {
		if buf.Len() > 0 {
			buf.WriteByte(' ')
		}
		buf.WriteString(windows.EscapeArg(arg))
	}

	cli.Args = buf.String()
}

// Validate ensures that cli.ExePath contains an absolute path.
func (cli *CommandLineInfo) Validate() error {
	if cli == nil {
		return windows.ERROR_INVALID_PARAMETER
	}

	if !filepath.IsAbs(cli.ExePath) {
		return fmt.Errorf("%w: CommandLineInfo requires absolute ExePath", windows.ERROR_BAD_PATHNAME)
	}

	return nil
}

// Resolve converts the information in cli to a format compatible with the Win32
// CreateProcess* family of APIs, as pointers to C-style UTF-16 strings. It also
// returns the full command line as a Go string for logging purposes.
func (cli *CommandLineInfo) Resolve() (exePath *uint16, cmdLine *uint16, cmdLineStr string, err error) {
	// Resolve cmdLine first since that also does a Validate.
	cmdLineStr, cmdLine, err = cli.resolveArgsAsUTF16Ptr()
	if err != nil {
		return nil, nil, "", err
	}

	exePath, err = windows.UTF16PtrFromString(cli.ExePath)
	if err != nil {
		return nil, nil, "", err
	}

	return exePath, cmdLine, cmdLineStr, nil
}

// resolveArgs quotes cli.ExePath as necessary, appends Args, and returns the result.
func (cli *CommandLineInfo) resolveArgs() (string, error) {
	if err := cli.Validate(); err != nil {
		return "", err
	}

	var cmdLineBuf strings.Builder
	cmdLineBuf.WriteString(windows.EscapeArg(cli.ExePath))
	if args := cli.Args; args != "" {
		cmdLineBuf.WriteByte(' ')
		cmdLineBuf.WriteString(args)
	}

	return cmdLineBuf.String(), nil
}

func (cli *CommandLineInfo) resolveArgsAsUTF16Ptr() (string, *uint16, error) {
	s, err := cli.resolveArgs()
	if err != nil {
		return "", nil, err
	}
	s16, err := windows.UTF16PtrFromString(s)
	if err != nil {
		return "", nil, err
	}
	return s, s16, nil
}

// StartProcessInSession creates a new process using cmdLineInfo that will
// reside inside the session identified by sessID, with the security token whose
// logon is associated with sessID. The child process's environment will be
// inherited from the session token's environment.
func StartProcessInSession(sessID SessionID, cmdLineInfo CommandLineInfo) error {
	return StartProcessInSessionWithHandler(sessID, cmdLineInfo, nil)
}

// PostCreateProcessHandler is a function that is invoked by
// StartProcessInSessionWithHandler when the child process has been successfully
// created. It is the responsibility of the handler to close the pi.Thread and
// pi.Process handles.
type PostCreateProcessHandler func(pi *windows.ProcessInformation)

// StartProcessInSessionWithHandler creates a new process using cmdLineInfo that
// will reside inside the session identified by sessID, with the security token
// whose logon is associated with sessID. The child process's environment will be
// inherited from the session token's environment. When the child process has
// been successfully created, handler is invoked with the windows.ProcessInformation
// that was returned by the OS.
func StartProcessInSessionWithHandler(sessID SessionID, cmdLineInfo CommandLineInfo, handler PostCreateProcessHandler) error {
	pi, err := startProcessInSessionInternal(sessID, cmdLineInfo, 0)
	if err != nil {
		return err
	}
	if handler != nil {
		handler(pi)
		return nil
	}
	windows.CloseHandle(pi.Process)
	windows.CloseHandle(pi.Thread)
	return nil
}

// RunProcessInSession creates a new process and waits up to timeout for that
// child process to complete its execution. The process is created using
// cmdLineInfo and will reside inside the session identified by sessID, with the
// security token whose logon is associated with sessID. The child process's
// environment will be inherited from the session token's environment.
func RunProcessInSession(sessID SessionID, cmdLineInfo CommandLineInfo, timeout time.Duration) (uint32, error) {
	timeoutMillis, err := wingoes.DurationToTimeoutMilliseconds(timeout)
	if err != nil {
		return 1, err
	}

	pi, err := startProcessInSessionInternal(sessID, cmdLineInfo, 0)
	if err != nil {
		return 1, err
	}
	windows.CloseHandle(pi.Thread)
	defer windows.CloseHandle(pi.Process)

	waitCode, err := windows.WaitForSingleObject(pi.Process, timeoutMillis)
	if err != nil {
		return 1, fmt.Errorf("WaitForSingleObject: %w", err)
	}
	if e := windows.Errno(waitCode); e == windows.WAIT_TIMEOUT {
		return 1, e
	}
	if waitCode != windows.WAIT_OBJECT_0 {
		// This should not be possible; log
		return 1, fmt.Errorf("unexpected state from WaitForSingleObject: %d", waitCode)
	}

	var exitCode uint32
	if err := windows.GetExitCodeProcess(pi.Process, &exitCode); err != nil {
		return 1, err
	}
	return exitCode, nil
}

func startProcessInSessionInternal(sessID SessionID, cmdLineInfo CommandLineInfo, extraFlags uint32) (*windows.ProcessInformation, error) {
	if err := cmdLineInfo.Validate(); err != nil {
		return nil, err
	}

	token, err := sessID.OpenToken()
	if err != nil {
		return nil, fmt.Errorf("(*SessionID).OpenToken: %w", err)
	}
	defer token.Close()

	exePath16, commandLine16, _, err := cmdLineInfo.Resolve()
	if err != nil {
		return nil, fmt.Errorf("(*CommandLineInfo).Resolve(): %w", err)
	}

	wd16, err := windows.UTF16PtrFromString(filepath.Dir(cmdLineInfo.ExePath))
	if err != nil {
		return nil, fmt.Errorf("UTF16PtrFromString(wd): %w", err)
	}

	env, err := token.Environ(false)
	if err != nil {
		return nil, fmt.Errorf("token environment: %w", err)
	}
	env16 := newEnvBlock(env)

	// The privileges in privNames are required for CreateProcessAsUser to be
	// able to start processes as other users in other logon sessions.
	privNames := []string{
		"SeAssignPrimaryTokenPrivilege",
		"SeIncreaseQuotaPrivilege",
	}
	dropPrivs, err := EnableCurrentThreadPrivileges(privNames)
	if err != nil {
		return nil, fmt.Errorf("EnableCurrentThreadPrivileges(%#v): %w", privNames, err)
	}
	defer dropPrivs()

	createFlags := extraFlags | windows.CREATE_UNICODE_ENVIRONMENT | windows.DETACHED_PROCESS
	si := windows.StartupInfo{
		Cb:      uint32(unsafe.Sizeof(windows.StartupInfo{})),
		Desktop: defaultDesktop,
	}
	var pi windows.ProcessInformation
	if err := windows.CreateProcessAsUser(token, exePath16, commandLine16, nil, nil,
		false, createFlags, env16, wd16, &si, &pi); err != nil {
		return nil, fmt.Errorf("CreateProcessAsUser: %w", err)
	}
	return &pi, nil
}

func newEnvBlock(env []string) *uint16 {
	// Intentionally using bytes.Buffer here because we're writing nul bytes (the standard library does this too).
	var buf bytes.Buffer
	for _, v := range env {
		buf.WriteString(v)
		buf.WriteByte(0)
	}
	if buf.Len() == 0 {
		// So that we end with a double-null in the empty env case
		buf.WriteByte(0)
	}
	buf.WriteByte(0)
	return unsafe.SliceData(utf16.Encode([]rune(string(buf.Bytes()))))
}
