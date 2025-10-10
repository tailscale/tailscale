// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package winutil

import (
	"errors"
	"fmt"
	"log"
	"math"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/exp/constraints"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

const (
	regBase       = `SOFTWARE\Tailscale IPN`
	regPolicyBase = `SOFTWARE\Policies\Tailscale`
)

// ErrNoShell is returned when the shell process is not found.
var ErrNoShell = errors.New("no Shell process is present")

// ErrNoValue is returned when the value doesn't exist in the registry.
var ErrNoValue = registry.ErrNotExist

// ErrBadRegValueFormat is returned when a string value does not match the
// expected format.
var ErrBadRegValueFormat = errors.New("registry value formatted incorrectly")

// GetDesktopPID searches the PID of the process that's running the
// currently active desktop. Returns ErrNoShell if the shell is not present.
// Usually the PID will be for explorer.exe.
func GetDesktopPID() (uint32, error) {
	hwnd := windows.GetShellWindow()
	if hwnd == 0 {
		return 0, ErrNoShell
	}

	var pid uint32
	windows.GetWindowThreadProcessId(hwnd, &pid)
	if pid == 0 {
		return 0, fmt.Errorf("invalid PID for HWND %v", hwnd)
	}

	return pid, nil
}

func getPolicyString(name string) (string, error) {
	s, err := getRegStringInternal(registry.LOCAL_MACHINE, regPolicyBase, name)
	if err != nil {
		// Fall back to the legacy path
		return getRegString(name)
	}
	return s, err
}

func getPolicyStringArray(name string) ([]string, error) {
	return getRegStringsInternal(regPolicyBase, name)
}

func getRegString(name string) (string, error) {
	s, err := getRegStringInternal(registry.LOCAL_MACHINE, regBase, name)
	if err != nil {
		return "", err
	}
	return s, err
}

func getPolicyInteger(name string) (uint64, error) {
	i, err := getRegIntegerInternal(regPolicyBase, name)
	if err != nil {
		// Fall back to the legacy path
		return getRegInteger(name)
	}
	return i, err
}

func getRegInteger(name string) (uint64, error) {
	i, err := getRegIntegerInternal(regBase, name)
	if err != nil {
		return 0, err
	}
	return i, err
}

func getRegStringInternal(key registry.Key, subKey, name string) (string, error) {
	key, err := registry.OpenKey(key, subKey, registry.READ)
	if err != nil {
		if err != ErrNoValue {
			log.Printf("registry.OpenKey(%v): %v", subKey, err)
		}
		return "", err
	}
	defer key.Close()

	val, _, err := key.GetStringValue(name)
	if err != nil {
		if err != ErrNoValue {
			log.Printf("registry.GetStringValue(%v): %v", name, err)
		}
		return "", err
	}
	return val, nil
}

// GetRegUserString looks up a registry path in the current user key, or returns
// an empty string and error.
func GetRegUserString(name string) (string, error) {
	return getRegStringInternal(registry.CURRENT_USER, regBase, name)
}

// SetRegUserString sets a SZ value identified by name in the current user key
// to the string specified by value.
func SetRegUserString(name, value string) error {
	key, _, err := registry.CreateKey(registry.CURRENT_USER, regBase, registry.SET_VALUE)
	if err != nil {
		log.Printf("registry.CreateKey(%v): %v", regBase, err)
	}
	defer key.Close()

	return key.SetStringValue(name, value)
}

// GetRegStrings looks up a registry value in the local machine path, or returns
// the given default if it can't.
func GetRegStrings(name string, defval []string) []string {
	s, err := getRegStringsInternal(regBase, name)
	if err != nil {
		return defval
	}
	return s
}

func getRegStringsInternal(subKey, name string) ([]string, error) {
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, subKey, registry.READ)
	if err != nil {
		if err != ErrNoValue {
			log.Printf("registry.OpenKey(%v): %v", subKey, err)
		}
		return nil, err
	}
	defer key.Close()

	val, _, err := key.GetStringsValue(name)
	if err != nil {
		if err != ErrNoValue {
			log.Printf("registry.GetStringValue(%v): %v", name, err)
		}
		return nil, err
	}
	return val, nil
}

// SetRegStrings sets a MULTI_SZ value in the in the local machine path
// to the strings specified by values.
func SetRegStrings(name string, values []string) error {
	return setRegStringsInternal(regBase, name, values)
}

func setRegStringsInternal(subKey, name string, values []string) error {
	key, _, err := registry.CreateKey(registry.LOCAL_MACHINE, subKey, registry.SET_VALUE)
	if err != nil {
		log.Printf("registry.CreateKey(%v): %v", subKey, err)
	}
	defer key.Close()

	return key.SetStringsValue(name, values)
}

// DeleteRegValue removes a registry value in the local machine path.
func DeleteRegValue(name string) error {
	return deleteRegValueInternal(regBase, name)
}

func deleteRegValueInternal(subKey, name string) error {
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, subKey, registry.SET_VALUE)
	if err == ErrNoValue {
		return nil
	}
	if err != nil {
		log.Printf("registry.OpenKey(%v): %v", subKey, err)
		return err
	}
	defer key.Close()

	err = key.DeleteValue(name)
	if err == ErrNoValue {
		err = nil
	}
	return err
}

func getRegIntegerInternal(subKey, name string) (uint64, error) {
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, subKey, registry.READ)
	if err != nil {
		if err != ErrNoValue {
			log.Printf("registry.OpenKey(%v): %v", subKey, err)
		}
		return 0, err
	}
	defer key.Close()

	val, _, err := key.GetIntegerValue(name)
	if err != nil {
		if err != ErrNoValue {
			log.Printf("registry.GetIntegerValue(%v): %v", name, err)
		}
		return 0, err
	}
	return val, nil
}

var (
	kernel32                         = syscall.NewLazyDLL("kernel32.dll")
	procWTSGetActiveConsoleSessionId = kernel32.NewProc("WTSGetActiveConsoleSessionId")
)

// TODO(crawshaw): replace with x/sys/windows... one day.
// https://go-review.googlesource.com/c/sys/+/331909
func WTSGetActiveConsoleSessionId() uint32 {
	r1, _, _ := procWTSGetActiveConsoleSessionId.Call()
	return uint32(r1)
}

func isSIDValidPrincipal(uid string) bool {
	usid, err := syscall.StringToSid(uid)
	if err != nil {
		return false
	}

	_, _, accType, err := usid.LookupAccount("")
	if err != nil {
		return false
	}

	switch accType {
	case syscall.SidTypeUser, syscall.SidTypeGroup, syscall.SidTypeDomain, syscall.SidTypeAlias, syscall.SidTypeWellKnownGroup, syscall.SidTypeComputer:
		return true
	default:
		// Reject deleted users, invalid SIDs, unknown SIDs, mandatory label SIDs, etc.
		return false
	}
}

// EnableCurrentThreadPrivilege enables the named privilege
// in the current thread's access token. The current goroutine is also locked to
// the OS thread (runtime.LockOSThread). Callers must call the returned disable
// function when done with the privileged task.
func EnableCurrentThreadPrivilege(name string) (disable func(), err error) {
	return EnableCurrentThreadPrivileges([]string{name})
}

// EnableCurrentThreadPrivileges enables the named privileges
// in the current thread's access token. The current goroutine is also locked to
// the OS thread (runtime.LockOSThread). Callers must call the returned disable
// function when done with the privileged task.
func EnableCurrentThreadPrivileges(names []string) (disable func(), err error) {
	runtime.LockOSThread()
	if len(names) == 0 {
		// Nothing to enable; no-op isn't really an error...
		return runtime.UnlockOSThread, nil
	}

	if err := windows.ImpersonateSelf(windows.SecurityImpersonation); err != nil {
		runtime.UnlockOSThread()
		return nil, err
	}

	disable = func() {
		defer runtime.UnlockOSThread()
		// If RevertToSelf fails, it's not really recoverable and we should panic.
		// Failure to do so would leak the privileges we're enabling, which is a
		// security issue.
		if err := windows.RevertToSelf(); err != nil {
			panic(fmt.Sprintf("RevertToSelf failed: %v", err))
		}
	}

	defer func() {
		if err != nil {
			disable()
		}
	}()

	var t windows.Token
	err = windows.OpenThreadToken(windows.CurrentThread(),
		windows.TOKEN_QUERY|windows.TOKEN_ADJUST_PRIVILEGES, false, &t)
	if err != nil {
		return nil, err
	}
	defer t.Close()

	tp := newTokenPrivileges(len(names))
	privs := tp.AllPrivileges()
	for i := range privs {
		var privStr *uint16
		privStr, err = windows.UTF16PtrFromString(names[i])
		if err != nil {
			return nil, err
		}
		err = windows.LookupPrivilegeValue(nil, privStr, &privs[i].Luid)
		if err != nil {
			return nil, err
		}
		privs[i].Attributes = windows.SE_PRIVILEGE_ENABLED
	}

	err = windows.AdjustTokenPrivileges(t, false, tp, 0, nil, nil)
	if err != nil {
		return nil, err
	}

	return disable, nil
}

func newTokenPrivileges(numPrivs int) *windows.Tokenprivileges {
	if numPrivs <= 0 {
		panic("numPrivs must be > 0")
	}
	numBytes := unsafe.Sizeof(windows.Tokenprivileges{}) + (uintptr(numPrivs-1) * unsafe.Sizeof(windows.LUIDAndAttributes{}))
	buf := make([]byte, numBytes)
	result := (*windows.Tokenprivileges)(unsafe.Pointer(unsafe.SliceData(buf)))
	result.PrivilegeCount = uint32(numPrivs)
	return result
}

// StartProcessAsChild starts exePath process as a child of parentPID.
// StartProcessAsChild copies parentPID's environment variables into
// the new process, along with any optional environment variables in extraEnv.
func StartProcessAsChild(parentPID uint32, exePath string, extraEnv []string) error {
	// The rest of this function requires SeDebugPrivilege to be held.
	//
	// According to https://docs.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights
	//
	// ... To open a handle to another process and obtain full access rights,
	// you must enable the SeDebugPrivilege privilege. ...
	//
	// But we only need PROCESS_CREATE_PROCESS. So perhaps SeDebugPrivilege is too much.
	//
	// https://devblogs.microsoft.com/oldnewthing/20080314-00/?p=23113
	//
	// TODO: try look for something less than SeDebugPrivilege

	disableSeDebug, err := EnableCurrentThreadPrivilege("SeDebugPrivilege")
	if err != nil {
		return err
	}
	defer disableSeDebug()

	ph, err := windows.OpenProcess(
		windows.PROCESS_CREATE_PROCESS|windows.PROCESS_QUERY_INFORMATION|windows.PROCESS_DUP_HANDLE,
		false, parentPID)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(ph)

	var pt windows.Token
	err = windows.OpenProcessToken(ph, windows.TOKEN_QUERY, &pt)
	if err != nil {
		return err
	}
	defer pt.Close()

	env, err := pt.Environ(false)
	if err != nil {
		return err

	}
	env = append(env, extraEnv...)

	sys := &syscall.SysProcAttr{ParentProcess: syscall.Handle(ph)}

	cmd := exec.Command(exePath)
	cmd.Env = env
	cmd.SysProcAttr = sys

	return cmd.Start()
}

// StartProcessAsCurrentGUIUser is like StartProcessAsChild, but if finds
// current logged in user desktop process (normally explorer.exe),
// and passes found PID to StartProcessAsChild.
func StartProcessAsCurrentGUIUser(exePath string, extraEnv []string) error {
	// as described in https://devblogs.microsoft.com/oldnewthing/20190425-00/?p=102443
	desktop, err := GetDesktopPID()
	if err != nil {
		return fmt.Errorf("failed to find desktop: %v", err)
	}
	err = StartProcessAsChild(desktop, exePath, extraEnv)
	if err != nil {
		return fmt.Errorf("failed to start executable: %v", err)
	}
	return nil
}

// CreateAppMutex creates a named Windows mutex, returning nil if the mutex
// is created successfully or an error if the mutex already exists or could not
// be created for some other reason.
func CreateAppMutex(name string) (windows.Handle, error) {
	return windows.CreateMutex(nil, false, windows.StringToUTF16Ptr(name))
}

// getTokenInfoFixedLen obtains known fixed-length token information. Use this
// function for information classes that output enumerations, BOOLs, integers etc.
func getTokenInfoFixedLen[T any](token windows.Token, infoClass uint32) (result T, err error) {
	var actualLen uint32
	p := (*byte)(unsafe.Pointer(&result))
	err = windows.GetTokenInformation(token, infoClass, p, uint32(unsafe.Sizeof(result)), &actualLen)
	return result, err
}

type tokenElevationType int32

const (
	tokenElevationTypeDefault tokenElevationType = 1
	tokenElevationTypeFull    tokenElevationType = 2
	tokenElevationTypeLimited tokenElevationType = 3
)

// IsTokenLimited returns whether token is a limited UAC token.
func IsTokenLimited(token windows.Token) (bool, error) {
	elevationType, err := getTokenInfoFixedLen[tokenElevationType](token, windows.TokenElevationType)
	if err != nil {
		return false, err
	}
	return elevationType == tokenElevationTypeLimited, nil
}

// UserSIDs contains the SIDs for a Windows NT token object's associated user
// as well as its primary group.
type UserSIDs struct {
	User         *windows.SID
	PrimaryGroup *windows.SID
}

// GetCurrentUserSIDs returns a UserSIDs struct containing SIDs for the
// current process' user and primary group.
func GetCurrentUserSIDs() (*UserSIDs, error) {
	token, err := windows.OpenCurrentProcessToken()
	if err != nil {
		return nil, err
	}
	defer token.Close()

	userInfo, err := token.GetTokenUser()
	if err != nil {
		return nil, err
	}

	primaryGroup, err := token.GetTokenPrimaryGroup()
	if err != nil {
		return nil, err
	}

	return &UserSIDs{userInfo.User.Sid, primaryGroup.PrimaryGroup}, nil
}

// IsCurrentProcessElevated returns true when the current process is
// running with an elevated token, implying Administrator access.
func IsCurrentProcessElevated() bool {
	token, err := windows.OpenCurrentProcessToken()
	if err != nil {
		return false
	}
	defer token.Close()

	return token.IsElevated()
}

// keyOpenTimeout is how long we wait for a registry key to appear. For some
// reason, registry keys tied to ephemeral interfaces can take a long while to
// appear after interface creation, and we can end up racing with that.
const keyOpenTimeout = 20 * time.Second

// RegistryPath represents a path inside a root registry.Key.
type RegistryPath string

// RegistryPathPrefix specifies a RegistryPath prefix that must be suffixed with
// another RegistryPath to make a valid RegistryPath.
type RegistryPathPrefix string

// WithSuffix returns a RegistryPath with the given suffix appended.
func (p RegistryPathPrefix) WithSuffix(suf string) RegistryPath {
	return RegistryPath(string(p) + suf)
}

const (
	IPv4TCPIPBase RegistryPath = `SYSTEM\CurrentControlSet\Services\Tcpip\Parameters`
	IPv6TCPIPBase RegistryPath = `SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters`
	NetBTBase     RegistryPath = `SYSTEM\CurrentControlSet\Services\NetBT\Parameters`

	IPv4TCPIPInterfacePrefix RegistryPathPrefix = `SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\`
	IPv6TCPIPInterfacePrefix RegistryPathPrefix = `SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\Interfaces\`
	NetBTInterfacePrefix     RegistryPathPrefix = `SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces\Tcpip_`
)

// ErrKeyWaitTimeout is returned by OpenKeyWait when calls timeout.
var ErrKeyWaitTimeout = errors.New("timeout waiting for registry key")

// OpenKeyWait opens a registry key, waiting for it to appear if necessary. It
// returns the opened key, or ErrKeyWaitTimeout if the key does not appear
// within 20s. The caller must call Close on the returned key.
func OpenKeyWait(k registry.Key, path RegistryPath, access uint32) (registry.Key, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	deadline := time.Now().Add(keyOpenTimeout)
	pathSpl := strings.Split(string(path), "\\")
	for i := 0; ; i++ {
		keyName := pathSpl[i]
		isLast := i+1 == len(pathSpl)

		event, err := windows.CreateEvent(nil, 0, 0, nil)
		if err != nil {
			return 0, fmt.Errorf("windows.CreateEvent: %w", err)
		}
		defer windows.CloseHandle(event)

		var key registry.Key
		for {
			err = windows.RegNotifyChangeKeyValue(windows.Handle(k), false, windows.REG_NOTIFY_CHANGE_NAME, event, true)
			if err != nil {
				return 0, fmt.Errorf("windows.RegNotifyChangeKeyValue: %w", err)
			}

			var accessFlags uint32
			if isLast {
				accessFlags = access
			} else {
				accessFlags = registry.NOTIFY
			}
			key, err = registry.OpenKey(k, keyName, accessFlags)
			if err == windows.ERROR_FILE_NOT_FOUND || err == windows.ERROR_PATH_NOT_FOUND {
				timeout := time.Until(deadline) / time.Millisecond
				if timeout < 0 {
					timeout = 0
				}
				s, err := windows.WaitForSingleObject(event, uint32(timeout))
				if err != nil {
					return 0, fmt.Errorf("windows.WaitForSingleObject: %w", err)
				}
				if s == uint32(windows.WAIT_TIMEOUT) { // windows.WAIT_TIMEOUT status const is misclassified as error in golang.org/x/sys/windows
					return 0, ErrKeyWaitTimeout
				}
			} else if err != nil {
				return 0, fmt.Errorf("registry.OpenKey(%v): %w", path, err)
			} else {
				if isLast {
					return key, nil
				}
				defer key.Close()
				break
			}
		}

		k = key
	}
}

func lookupPseudoUser(uid string) (*user.User, error) {
	sid, err := windows.StringToSid(uid)
	if err != nil {
		return nil, err
	}

	// We're looking for SIDs "S-1-5-x" where 17 <= x <= 20.
	// This is checking for the the "5"
	if sid.IdentifierAuthority() != windows.SECURITY_NT_AUTHORITY {
		return nil, fmt.Errorf(`SID %q does not use "NT AUTHORITY"`, uid)
	}

	// This is ensuring that there is only one sub-authority.
	// In other words, only one value after the "5".
	if sid.SubAuthorityCount() != 1 {
		return nil, fmt.Errorf("SID %q should have only one subauthority", uid)
	}

	// Get that sub-authority value (this is "x" above) and check it.
	rid := sid.SubAuthority(0)
	if rid < 17 || rid > 20 {
		return nil, fmt.Errorf("SID %q does not represent a known pseudo-user", uid)
	}

	// We've got one of the known pseudo-users. Look up the localized name of the
	// account.
	username, domain, _, err := sid.LookupAccount("")
	if err != nil {
		return nil, err
	}

	// This call is best-effort. If it fails, homeDir will be empty.
	homeDir, _ := findHomeDirInRegistry(uid)

	result := &user.User{
		Uid:      uid,
		Gid:      uid, // Gid == Uid with these accounts.
		Username: fmt.Sprintf(`%s\%s`, domain, username),
		Name:     username,
		HomeDir:  homeDir,
	}
	return result, nil
}

// findHomeDirInRegistry finds the user home path based on the uid.
// This is borrowed from Go's std lib.
func findHomeDirInRegistry(uid string) (dir string, err error) {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\`+uid, registry.QUERY_VALUE)
	if err != nil {
		return "", err
	}
	defer k.Close()
	dir, _, err = k.GetStringValue("ProfileImagePath")
	if err != nil {
		return "", err
	}
	return dir, nil
}

// ProcessImageName returns the fully-qualified path to the executable image
// associated with process.
func ProcessImageName(process windows.Handle) (string, error) {
	var pathBuf [windows.MAX_PATH]uint16
	pathBufLen := uint32(len(pathBuf))
	if err := windows.QueryFullProcessImageName(process, 0, &pathBuf[0], &pathBufLen); err != nil {
		return "", err
	}
	return windows.UTF16ToString(pathBuf[:pathBufLen]), nil
}

// TSSessionIDToLogonSessionID retrieves the logon session ID associated with
// tsSessionId, which is a Terminal Services / RDP session ID. The calling
// process must be running as LocalSystem.
func TSSessionIDToLogonSessionID(tsSessionID uint32) (logonSessionID windows.LUID, err error) {
	var token windows.Token
	if err := windows.WTSQueryUserToken(tsSessionID, &token); err != nil {
		return logonSessionID, fmt.Errorf("WTSQueryUserToken: %w", err)
	}
	defer token.Close()
	return LogonSessionID(token)
}

// TSSessionID obtains the Terminal Services (RDP) session ID associated with token.
func TSSessionID(token windows.Token) (tsSessionID uint32, err error) {
	return getTokenInfoFixedLen[uint32](token, windows.TokenSessionId)
}

type tokenOrigin struct {
	originatingLogonSession windows.LUID
}

// LogonSessionID obtains the logon session ID associated with token.
func LogonSessionID(token windows.Token) (logonSessionID windows.LUID, err error) {
	origin, err := getTokenInfoFixedLen[tokenOrigin](token, windows.TokenOrigin)
	if err != nil {
		return logonSessionID, err
	}

	return origin.originatingLogonSession, nil
}

// BufUnit is a type constraint for buffers passed into AllocateContiguousBuffer
// and SetNTString.
type BufUnit interface {
	byte | uint16
}

// AllocateContiguousBuffer allocates memory to satisfy the Windows idiom where
// some structs contain pointers that are expected to refer to memory within the
// same buffer containing the struct itself. T is the type that contains
// the pointers. values must contain the actual data that is to be copied
// into the buffer after T. AllocateContiguousBuffer returns a pointer to the
// struct, the total length of the buffer in bytes, and a slice containing
// each value within the buffer. The caller may use slcs to populate any
// pointers in t as needed. Each element of slcs corresponds to the element of
// values in the same position.
//
// It is the responsibility of the caller to ensure that any values expected
// to contain null-terminated strings are in fact null-terminated!
//
// AllocateContiguousBuffer panics if no values are passed in, as there are
// better alternatives for allocating a struct in that case.
func AllocateContiguousBuffer[T any, BU BufUnit](values ...[]BU) (t *T, tLenBytes uint32, slcs [][]BU) {
	if len(values) == 0 {
		panic("len(values) must be > 0")
	}

	// Get the sizes of T and BU, then compute a preferred alignment for T.
	tT := reflect.TypeFor[T]()
	szT := tT.Size()
	szBU := int(unsafe.Sizeof(BU(0)))
	alignment := max(tT.Align(), szBU)

	// Our buffers for values will start at the next szBU boundary.
	tLenBytes = alignUp(uint32(szT), szBU)
	firstValueOffset := tLenBytes

	// Accumulate the length of each value into tLenBytes
	for _, v := range values {
		tLenBytes += uint32(len(v) * szBU)
	}

	// Now that we know the final length, align up to our preferred boundary.
	tLenBytes = alignUp(tLenBytes, alignment)

	// Allocate the buffer. We choose a type for the slice that is appropriate
	// for the desired alignment. Note that we do not have a strict requirement
	// that T contain pointer fields; we could just be appending more data
	// within the same buffer.
	bufLen := tLenBytes / uint32(alignment)
	var pt unsafe.Pointer
	switch alignment {
	case 1:
		pt = unsafe.Pointer(unsafe.SliceData(make([]byte, bufLen)))
	case 2:
		pt = unsafe.Pointer(unsafe.SliceData(make([]uint16, bufLen)))
	case 4:
		pt = unsafe.Pointer(unsafe.SliceData(make([]uint32, bufLen)))
	case 8:
		pt = unsafe.Pointer(unsafe.SliceData(make([]uint64, bufLen)))
	default:
		panic(fmt.Sprintf("bad alignment %d", alignment))
	}

	t = (*T)(pt)
	slcs = make([][]BU, 0, len(values))

	// Use the limits of the buffer area after t to construct a slice representing the remaining buffer.
	firstValuePtr := unsafe.Pointer(uintptr(pt) + uintptr(firstValueOffset))
	buf := unsafe.Slice((*BU)(firstValuePtr), (tLenBytes-firstValueOffset)/uint32(szBU))

	// Copy each value into the buffer and record a slice describing each value's limits into slcs.
	var index int
	for _, v := range values {
		if len(v) == 0 {
			// We allow zero-length values; we simply append a nil slice.
			slcs = append(slcs, nil)
			continue
		}
		valueSlice := buf[index : index+len(v)]
		copy(valueSlice, v)
		slcs = append(slcs, valueSlice)
		index += len(v)
	}

	return t, tLenBytes, slcs
}

// alignment must be a power of 2
func alignUp[V constraints.Integer](v V, alignment int) V {
	return v + ((-v) & (V(alignment) - 1))
}

// NTStr is a type constraint requiring the type to be either a
// windows.NTString or a windows.NTUnicodeString.
type NTStr interface {
	windows.NTString | windows.NTUnicodeString
}

// SetNTString sets the value of nts in-place to point to the string contained
// within buf. A nul terminator is optional in buf.
func SetNTString[NTS NTStr, BU BufUnit](nts *NTS, buf []BU) {
	isEmpty := len(buf) == 0
	codeUnitSize := uint16(unsafe.Sizeof(BU(0)))
	lenBytes := len(buf) * int(codeUnitSize)
	if lenBytes > math.MaxUint16 {
		panic("buffer length must fit into uint16")
	}
	lenBytes16 := uint16(lenBytes)

	switch p := any(nts).(type) {
	case *windows.NTString:
		if isEmpty {
			*p = windows.NTString{}
			break
		}
		p.Buffer = unsafe.SliceData(any(buf).([]byte))
		p.MaximumLength = lenBytes16
		p.Length = lenBytes16
		// account for nul terminator when present
		if buf[len(buf)-1] == 0 {
			p.Length -= codeUnitSize
		}
	case *windows.NTUnicodeString:
		if isEmpty {
			*p = windows.NTUnicodeString{}
			break
		}
		p.Buffer = unsafe.SliceData(any(buf).([]uint16))
		p.MaximumLength = lenBytes16
		p.Length = lenBytes16
		// account for nul terminator when present
		if buf[len(buf)-1] == 0 {
			p.Length -= codeUnitSize
		}
	default:
		panic("unknown type")
	}
}

type domainControllerAddressType uint32

const (
	//lint:ignore U1000 maps to a win32 API
	_DS_INET_ADDRESS    domainControllerAddressType = 1
	_DS_NETBIOS_ADDRESS domainControllerAddressType = 2
)

type domainControllerFlag uint32

const (
	//lint:ignore U1000 maps to a win32 API
	_DS_PDC_FLAG                    domainControllerFlag = 0x00000001
	_DS_GC_FLAG                     domainControllerFlag = 0x00000004
	_DS_LDAP_FLAG                   domainControllerFlag = 0x00000008
	_DS_DS_FLAG                     domainControllerFlag = 0x00000010
	_DS_KDC_FLAG                    domainControllerFlag = 0x00000020
	_DS_TIMESERV_FLAG               domainControllerFlag = 0x00000040
	_DS_CLOSEST_FLAG                domainControllerFlag = 0x00000080
	_DS_WRITABLE_FLAG               domainControllerFlag = 0x00000100
	_DS_GOOD_TIMESERV_FLAG          domainControllerFlag = 0x00000200
	_DS_NDNC_FLAG                   domainControllerFlag = 0x00000400
	_DS_SELECT_SECRET_DOMAIN_6_FLAG domainControllerFlag = 0x00000800
	_DS_FULL_SECRET_DOMAIN_6_FLAG   domainControllerFlag = 0x00001000
	_DS_WS_FLAG                     domainControllerFlag = 0x00002000
	_DS_DS_8_FLAG                   domainControllerFlag = 0x00004000
	_DS_DS_9_FLAG                   domainControllerFlag = 0x00008000
	_DS_DS_10_FLAG                  domainControllerFlag = 0x00010000
	_DS_KEY_LIST_FLAG               domainControllerFlag = 0x00020000
	_DS_PING_FLAGS                  domainControllerFlag = 0x000FFFFF
	_DS_DNS_CONTROLLER_FLAG         domainControllerFlag = 0x20000000
	_DS_DNS_DOMAIN_FLAG             domainControllerFlag = 0x40000000
	_DS_DNS_FOREST_FLAG             domainControllerFlag = 0x80000000
)

type _DOMAIN_CONTROLLER_INFO struct {
	DomainControllerName        *uint16
	DomainControllerAddress     *uint16
	DomainControllerAddressType domainControllerAddressType
	DomainGuid                  windows.GUID
	DomainName                  *uint16
	DnsForestName               *uint16
	Flags                       domainControllerFlag
	DcSiteName                  *uint16
	ClientSiteName              *uint16
}

func (dci *_DOMAIN_CONTROLLER_INFO) Close() error {
	if dci == nil {
		return nil
	}
	return windows.NetApiBufferFree((*byte)(unsafe.Pointer(dci)))
}

type dsGetDcNameFlag uint32

const (
	//lint:ignore U1000 maps to a win32 API
	_DS_FORCE_REDISCOVERY             dsGetDcNameFlag = 0x00000001
	_DS_DIRECTORY_SERVICE_REQUIRED    dsGetDcNameFlag = 0x00000010
	_DS_DIRECTORY_SERVICE_PREFERRED   dsGetDcNameFlag = 0x00000020
	_DS_GC_SERVER_REQUIRED            dsGetDcNameFlag = 0x00000040
	_DS_PDC_REQUIRED                  dsGetDcNameFlag = 0x00000080
	_DS_BACKGROUND_ONLY               dsGetDcNameFlag = 0x00000100
	_DS_IP_REQUIRED                   dsGetDcNameFlag = 0x00000200
	_DS_KDC_REQUIRED                  dsGetDcNameFlag = 0x00000400
	_DS_TIMESERV_REQUIRED             dsGetDcNameFlag = 0x00000800
	_DS_WRITABLE_REQUIRED             dsGetDcNameFlag = 0x00001000
	_DS_GOOD_TIMESERV_PREFERRED       dsGetDcNameFlag = 0x00002000
	_DS_AVOID_SELF                    dsGetDcNameFlag = 0x00004000
	_DS_ONLY_LDAP_NEEDED              dsGetDcNameFlag = 0x00008000
	_DS_IS_FLAT_NAME                  dsGetDcNameFlag = 0x00010000
	_DS_IS_DNS_NAME                   dsGetDcNameFlag = 0x00020000
	_DS_TRY_NEXTCLOSEST_SITE          dsGetDcNameFlag = 0x00040000
	_DS_DIRECTORY_SERVICE_6_REQUIRED  dsGetDcNameFlag = 0x00080000
	_DS_WEB_SERVICE_REQUIRED          dsGetDcNameFlag = 0x00100000
	_DS_DIRECTORY_SERVICE_8_REQUIRED  dsGetDcNameFlag = 0x00200000
	_DS_DIRECTORY_SERVICE_9_REQUIRED  dsGetDcNameFlag = 0x00400000
	_DS_DIRECTORY_SERVICE_10_REQUIRED dsGetDcNameFlag = 0x00800000
	_DS_KEY_LIST_SUPPORT_REQUIRED     dsGetDcNameFlag = 0x01000000
	_DS_RETURN_DNS_NAME               dsGetDcNameFlag = 0x40000000
	_DS_RETURN_FLAT_NAME              dsGetDcNameFlag = 0x80000000
)

func resolveDomainController(domainName *uint16, domainGUID *windows.GUID) (*_DOMAIN_CONTROLLER_INFO, error) {
	const flags = _DS_DIRECTORY_SERVICE_REQUIRED | _DS_IS_FLAT_NAME | _DS_RETURN_DNS_NAME
	var dcInfo *_DOMAIN_CONTROLLER_INFO
	if err := dsGetDcName(nil, domainName, domainGUID, nil, flags, &dcInfo); err != nil {
		return nil, err
	}
	return dcInfo, nil
}

// ResolveDomainController resolves the DNS name of the nearest available
// domain controller for the domain specified by domainName.
func ResolveDomainController(domainName string) (string, error) {
	domainName16, err := windows.UTF16PtrFromString(domainName)
	if err != nil {
		return "", err
	}

	dcInfo, err := resolveDomainController(domainName16, nil)
	if err != nil {
		return "", err
	}
	defer dcInfo.Close()

	return windows.UTF16PtrToString(dcInfo.DomainControllerName), nil
}

type _NETSETUP_NAME_TYPE int32

const (
	_NetSetupUnknown           _NETSETUP_NAME_TYPE = 0
	_NetSetupMachine           _NETSETUP_NAME_TYPE = 1
	_NetSetupWorkgroup         _NETSETUP_NAME_TYPE = 2
	_NetSetupDomain            _NETSETUP_NAME_TYPE = 3
	_NetSetupNonExistentDomain _NETSETUP_NAME_TYPE = 4
	_NetSetupDnsMachine        _NETSETUP_NAME_TYPE = 5
)

func isDomainName(name *uint16) (bool, error) {
	err := netValidateName(nil, name, nil, nil, _NetSetupDomain)
	switch err {
	case nil:
		return true, nil
	case windows.ERROR_NO_SUCH_DOMAIN:
		return false, nil
	default:
		return false, err
	}
}

// IsDomainName checks whether name represents an existing domain reachable by
// the current machine.
func IsDomainName(name string) (bool, error) {
	name16, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return false, err
	}

	return isDomainName(name16)
}

// GUIPathFromReg obtains the path to the client GUI executable from the
// registry value that was written during installation.
func GUIPathFromReg() (string, error) {
	regPath, err := GetRegString("GUIPath")
	if err != nil {
		return "", err
	}

	if !filepath.IsAbs(regPath) {
		return "", ErrBadRegValueFormat
	}

	if _, err := os.Stat(regPath); err != nil {
		return "", err
	}

	return regPath, nil
}
