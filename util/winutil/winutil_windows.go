// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package winutil

import (
	"errors"
	"fmt"
	"log"
	"os/exec"
	"os/user"
	"runtime"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

const (
	regBase       = `SOFTWARE\Tailscale IPN`
	regPolicyBase = `SOFTWARE\Policies\Tailscale`
)

// ErrNoShell is returned when the shell process is not found.
var ErrNoShell = errors.New("no Shell process is present")

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

func getPolicyString(name, defval string) string {
	s, err := getRegStringInternal(regPolicyBase, name)
	if err != nil {
		// Fall back to the legacy path
		return getRegString(name, defval)
	}
	return s
}

func getPolicyInteger(name string, defval uint64) uint64 {
	i, err := getRegIntegerInternal(regPolicyBase, name)
	if err != nil {
		// Fall back to the legacy path
		return getRegInteger(name, defval)
	}
	return i
}

func getRegString(name, defval string) string {
	s, err := getRegStringInternal(regBase, name)
	if err != nil {
		return defval
	}
	return s
}

func getRegInteger(name string, defval uint64) uint64 {
	i, err := getRegIntegerInternal(regBase, name)
	if err != nil {
		return defval
	}
	return i
}

func getRegStringInternal(subKey, name string) (string, error) {
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, subKey, registry.READ)
	if err != nil {
		if err != registry.ErrNotExist {
			log.Printf("registry.OpenKey(%v): %v", subKey, err)
		}
		return "", err
	}
	defer key.Close()

	val, _, err := key.GetStringValue(name)
	if err != nil {
		if err != registry.ErrNotExist {
			log.Printf("registry.GetStringValue(%v): %v", name, err)
		}
		return "", err
	}
	return val, nil
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
		if err != registry.ErrNotExist {
			log.Printf("registry.OpenKey(%v): %v", subKey, err)
		}
		return nil, err
	}
	defer key.Close()

	val, _, err := key.GetStringsValue(name)
	if err != nil {
		if err != registry.ErrNotExist {
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
	if err == registry.ErrNotExist {
		return nil
	}
	if err != nil {
		log.Printf("registry.OpenKey(%v): %v", subKey, err)
		return err
	}
	defer key.Close()

	err = key.DeleteValue(name)
	if err == registry.ErrNotExist {
		err = nil
	}
	return err
}

func getRegIntegerInternal(subKey, name string) (uint64, error) {
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, subKey, registry.READ)
	if err != nil {
		if err != registry.ErrNotExist {
			log.Printf("registry.OpenKey(%v): %v", subKey, err)
		}
		return 0, err
	}
	defer key.Close()

	val, _, err := key.GetIntegerValue(name)
	if err != nil {
		if err != registry.ErrNotExist {
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
// in the current thread access token.
func EnableCurrentThreadPrivilege(name string) error {
	var t windows.Token
	err := windows.OpenThreadToken(windows.CurrentThread(),
		windows.TOKEN_QUERY|windows.TOKEN_ADJUST_PRIVILEGES, false, &t)
	if err != nil {
		return err
	}
	defer t.Close()

	var tp windows.Tokenprivileges

	privStr, err := syscall.UTF16PtrFromString(name)
	if err != nil {
		return err
	}
	err = windows.LookupPrivilegeValue(nil, privStr, &tp.Privileges[0].Luid)
	if err != nil {
		return err
	}
	tp.PrivilegeCount = 1
	tp.Privileges[0].Attributes = windows.SE_PRIVILEGE_ENABLED
	return windows.AdjustTokenPrivileges(t, false, &tp, 0, nil, nil)
}

// StartProcessAsChild starts exePath process as a child of parentPID.
// StartProcessAsChild copies parentPID's environment variables into
// the new process, along with any optional environment variables in extraEnv.
func StartProcessAsChild(parentPID uint32, exePath string, extraEnv []string) error {
	// The rest of this function requires SeDebugPrivilege to be held.

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	err := windows.ImpersonateSelf(windows.SecurityImpersonation)
	if err != nil {
		return err
	}
	defer windows.RevertToSelf()

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

	err = EnableCurrentThreadPrivilege("SeDebugPrivilege")
	if err != nil {
		return err
	}

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

func getTokenInfo(token windows.Token, infoClass uint32) ([]byte, error) {
	var desiredLen uint32
	err := windows.GetTokenInformation(token, infoClass, nil, 0, &desiredLen)
	if err != nil && err != windows.ERROR_INSUFFICIENT_BUFFER {
		return nil, err
	}

	buf := make([]byte, desiredLen)
	actualLen := desiredLen
	err = windows.GetTokenInformation(token, infoClass, &buf[0], desiredLen, &actualLen)
	return buf, err
}

func getTokenUserInfo(token windows.Token) (*windows.Tokenuser, error) {
	buf, err := getTokenInfo(token, windows.TokenUser)
	if err != nil {
		return nil, err
	}

	return (*windows.Tokenuser)(unsafe.Pointer(&buf[0])), nil
}

func getTokenPrimaryGroupInfo(token windows.Token) (*windows.Tokenprimarygroup, error) {
	buf, err := getTokenInfo(token, windows.TokenPrimaryGroup)
	if err != nil {
		return nil, err
	}

	return (*windows.Tokenprimarygroup)(unsafe.Pointer(&buf[0])), nil
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

	userInfo, err := getTokenUserInfo(token)
	if err != nil {
		return nil, err
	}

	primaryGroup, err := getTokenPrimaryGroupInfo(token)
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
