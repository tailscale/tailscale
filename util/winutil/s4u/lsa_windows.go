// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package s4u

import (
	"errors"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"unicode"
	"unsafe"

	"github.com/dblohm7/wingoes"
	"golang.org/x/sys/windows"
	"tailscale.com/types/lazy"
	"tailscale.com/util/winutil"
	"tailscale.com/util/winutil/winenv"
)

const (
	_MICROSOFT_KERBEROS_NAME = "Kerberos"
	_MSV1_0_PACKAGE_NAME     = "MICROSOFT_AUTHENTICATION_PACKAGE_V1_0"
)

type _LSAHANDLE windows.Handle
type _LSA_OPERATIONAL_MODE uint32

type _KERB_LOGON_SUBMIT_TYPE int32

const (
	_KerbInteractiveLogon       _KERB_LOGON_SUBMIT_TYPE = 2
	_KerbSmartCardLogon         _KERB_LOGON_SUBMIT_TYPE = 6
	_KerbWorkstationUnlockLogon _KERB_LOGON_SUBMIT_TYPE = 7
	_KerbSmartCardUnlockLogon   _KERB_LOGON_SUBMIT_TYPE = 8
	_KerbProxyLogon             _KERB_LOGON_SUBMIT_TYPE = 9
	_KerbTicketLogon            _KERB_LOGON_SUBMIT_TYPE = 10
	_KerbTicketUnlockLogon      _KERB_LOGON_SUBMIT_TYPE = 11
	_KerbS4ULogon               _KERB_LOGON_SUBMIT_TYPE = 12
	_KerbCertificateLogon       _KERB_LOGON_SUBMIT_TYPE = 13
	_KerbCertificateS4ULogon    _KERB_LOGON_SUBMIT_TYPE = 14
	_KerbCertificateUnlockLogon _KERB_LOGON_SUBMIT_TYPE = 15
	_KerbNoElevationLogon       _KERB_LOGON_SUBMIT_TYPE = 83
	_KerbLuidLogon              _KERB_LOGON_SUBMIT_TYPE = 84
)

type _KERB_S4U_LOGON_FLAGS uint32

const (
	_KERB_S4U_LOGON_FLAG_CHECK_LOGONHOURS _KERB_S4U_LOGON_FLAGS = 0x2
	//lint:ignore U1000 maps to a win32 API
	_KERB_S4U_LOGON_FLAG_IDENTIFY _KERB_S4U_LOGON_FLAGS = 0x8
)

type _KERB_S4U_LOGON struct {
	MessageType _KERB_LOGON_SUBMIT_TYPE
	Flags       _KERB_S4U_LOGON_FLAGS
	ClientUpn   windows.NTUnicodeString
	ClientRealm windows.NTUnicodeString
}

type _MSV1_0_LOGON_SUBMIT_TYPE int32

const (
	_MsV1_0InteractiveLogon       _MSV1_0_LOGON_SUBMIT_TYPE = 2
	_MsV1_0Lm20Logon              _MSV1_0_LOGON_SUBMIT_TYPE = 3
	_MsV1_0NetworkLogon           _MSV1_0_LOGON_SUBMIT_TYPE = 4
	_MsV1_0SubAuthLogon           _MSV1_0_LOGON_SUBMIT_TYPE = 5
	_MsV1_0WorkstationUnlockLogon _MSV1_0_LOGON_SUBMIT_TYPE = 7
	_MsV1_0S4ULogon               _MSV1_0_LOGON_SUBMIT_TYPE = 12
	_MsV1_0VirtualLogon           _MSV1_0_LOGON_SUBMIT_TYPE = 82
	_MsV1_0NoElevationLogon       _MSV1_0_LOGON_SUBMIT_TYPE = 83
	_MsV1_0LuidLogon              _MSV1_0_LOGON_SUBMIT_TYPE = 84
)

type _MSV1_0_S4U_LOGON_FLAGS uint32

const (
	_MSV1_0_S4U_LOGON_FLAG_CHECK_LOGONHOURS _MSV1_0_S4U_LOGON_FLAGS = 0x2
)

type _MSV1_0_S4U_LOGON struct {
	MessageType       _MSV1_0_LOGON_SUBMIT_TYPE
	Flags             _MSV1_0_S4U_LOGON_FLAGS
	UserPrincipalName windows.NTUnicodeString
	DomainName        windows.NTUnicodeString
}

type _SECURITY_LOGON_TYPE int32

const (
	_UndefinedLogonType      _SECURITY_LOGON_TYPE = 0
	_Interactive             _SECURITY_LOGON_TYPE = 2
	_Network                 _SECURITY_LOGON_TYPE = 3
	_Batch                   _SECURITY_LOGON_TYPE = 4
	_Service                 _SECURITY_LOGON_TYPE = 5
	_Proxy                   _SECURITY_LOGON_TYPE = 6
	_Unlock                  _SECURITY_LOGON_TYPE = 7
	_NetworkCleartext        _SECURITY_LOGON_TYPE = 8
	_NewCredentials          _SECURITY_LOGON_TYPE = 9
	_RemoteInteractive       _SECURITY_LOGON_TYPE = 10
	_CachedInteractive       _SECURITY_LOGON_TYPE = 11
	_CachedRemoteInteractive _SECURITY_LOGON_TYPE = 12
	_CachedUnlock            _SECURITY_LOGON_TYPE = 13
)

const _TOKEN_SOURCE_LENGTH = 8

type _TOKEN_SOURCE struct {
	SourceName       [_TOKEN_SOURCE_LENGTH]byte
	SourceIdentifier windows.LUID
}

type _QUOTA_LIMITS struct {
	PagedPoolLimit        uintptr
	NonPagedPoolLimit     uintptr
	MinimumWorkingSetSize uintptr
	MaximumWorkingSetSize uintptr
	PagefileLimit         uintptr
	TimeLimit             int64
}

var (
	// ErrBadSrcName is returned if srcName contains non-ASCII characters, is
	// empty, or is too long. It may be wrapped with additional information; use
	// errors.Is when checking for it.
	ErrBadSrcName = errors.New("srcName must be ASCII with length > 0 and <= 8")
)

// LSA packages (and their IDs) are always initialized during system startup,
// so we can retain their resolved IDs for the lifetime of our process.
var (
	authPkgIDKerberos lazy.SyncValue[uint32]
	authPkgIDMSV1_0   lazy.SyncValue[uint32]
)

type lsaSession struct {
	handle _LSAHANDLE
}

func newLSASessionForQuery() (lsa *lsaSession, err error) {
	var h _LSAHANDLE
	if e := wingoes.ErrorFromNTStatus(lsaConnectUntrusted(&h)); e.Failed() {
		return nil, e
	}

	return &lsaSession{handle: h}, nil
}

func newLSASessionForLogon(processName string) (lsa *lsaSession, err error) {
	// processName is used by LSA for audit logging purposes.
	// If empty, the current process name is used.
	if processName == "" {
		exe, err := os.Executable()
		if err != nil {
			return nil, err
		}

		processName = strings.TrimSuffix(filepath.Base(exe), filepath.Ext(exe))
	}

	if err := checkASCII(processName); err != nil {
		return nil, err
	}

	logonProcessName, err := windows.NewNTString(processName)
	if err != nil {
		return nil, err
	}

	var h _LSAHANDLE
	var mode _LSA_OPERATIONAL_MODE
	if e := wingoes.ErrorFromNTStatus(lsaRegisterLogonProcess(logonProcessName, &h, &mode)); e.Failed() {
		return nil, e
	}

	return &lsaSession{handle: h}, nil
}

func (ls *lsaSession) getAuthPkgID(pkgName string) (id uint32, err error) {
	ntPkgName, err := windows.NewNTString(pkgName)
	if err != nil {
		return 0, err
	}

	if e := wingoes.ErrorFromNTStatus(lsaLookupAuthenticationPackage(ls.handle, ntPkgName, &id)); e.Failed() {
		return 0, e
	}

	return id, nil
}

func (ls *lsaSession) Close() error {
	if e := wingoes.ErrorFromNTStatus(lsaDeregisterLogonProcess(ls.handle)); e.Failed() {
		return e
	}
	ls.handle = 0
	return nil
}

func checkASCII(s string) error {
	for _, c := range []byte(s) {
		if c > unicode.MaxASCII {
			return fmt.Errorf("%q must be ASCII but contains value 0x%02X", s, c)
		}
	}

	return nil
}

var (
	thisComputer = []uint16{'.', 0}
	computerName lazy.SyncValue[string]
)

func getComputerName() (string, error) {
	var buf [windows.MAX_COMPUTERNAME_LENGTH + 1]uint16
	size := uint32(len(buf))
	if err := windows.GetComputerName(&buf[0], &size); err != nil {
		return "", err
	}

	return windows.UTF16ToString(buf[:size]), nil
}

// checkDomainAccount strips out the computer name (if any) from
// username and returns the result in sanitizedUserName. isDomainAccount is set
// to true if username contains a domain component that does not refer to the
// local computer.
func checkDomainAccount(username string) (sanitizedUserName string, isDomainAccount bool, err error) {
	before, after, hasBackslash := strings.Cut(username, `\`)
	if !hasBackslash {
		return username, false, nil
	}
	if before == "." {
		return after, false, nil
	}

	comp, err := computerName.GetErr(getComputerName)
	if err != nil {
		return username, false, err
	}

	if strings.EqualFold(before, comp) {
		return after, false, nil
	}
	return username, true, nil
}

// logonAs performs a S4U logon for u on behalf of srcName, and returns an
// access token for the user if successful. srcName must be non-empty, ASCII,
// and no more than 8 characters long. If srcName does not meet this criteria,
// LogonAs will return ErrBadSrcName wrapped with additional information; use
// errors.Is to check for it. When capLevel == CapCreateProcess, the logon
// enforces the user's logon hours policy (when present).
func (ls *lsaSession) logonAs(srcName string, u *user.User, capLevel CapabilityLevel) (token windows.Token, err error) {
	if ln := len(srcName); ln == 0 || ln > _TOKEN_SOURCE_LENGTH {
		return 0, fmt.Errorf("%w, actual length is %d", ErrBadSrcName, ln)
	}
	if err := checkASCII(srcName); err != nil {
		return 0, fmt.Errorf("%w: %v", ErrBadSrcName, err)
	}

	sanitizedUserName, isDomainUser, err := checkDomainAccount(u.Username)
	if err != nil {
		return 0, err
	}
	if isDomainUser && !winenv.IsDomainJoined() {
		return 0, fmt.Errorf("%w: cannot logon as domain user without being joined to a domain", os.ErrInvalid)
	}

	var pkgID uint32
	var authInfo unsafe.Pointer
	var authInfoLen uint32
	enforceLogonHours := capLevel == CapCreateProcess
	if isDomainUser {
		pkgID, err = authPkgIDKerberos.GetErr(func() (uint32, error) {
			return ls.getAuthPkgID(_MICROSOFT_KERBEROS_NAME)
		})
		if err != nil {
			return 0, err
		}

		upn16, err := samToUPN16(sanitizedUserName)
		if err != nil {
			return 0, fmt.Errorf("samToUPN16: %w", err)
		}

		logonInfo, logonInfoLen, slcs := winutil.AllocateContiguousBuffer[_KERB_S4U_LOGON](upn16)
		logonInfo.MessageType = _KerbS4ULogon
		if enforceLogonHours {
			logonInfo.Flags = _KERB_S4U_LOGON_FLAG_CHECK_LOGONHOURS
		}
		winutil.SetNTString(&logonInfo.ClientUpn, slcs[0])

		authInfo = unsafe.Pointer(logonInfo)
		authInfoLen = logonInfoLen
	} else {
		pkgID, err = authPkgIDMSV1_0.GetErr(func() (uint32, error) {
			return ls.getAuthPkgID(_MSV1_0_PACKAGE_NAME)
		})
		if err != nil {
			return 0, err
		}

		upn16, err := windows.UTF16FromString(sanitizedUserName)
		if err != nil {
			return 0, err
		}

		logonInfo, logonInfoLen, slcs := winutil.AllocateContiguousBuffer[_MSV1_0_S4U_LOGON](upn16, thisComputer)
		logonInfo.MessageType = _MsV1_0S4ULogon
		if enforceLogonHours {
			logonInfo.Flags = _MSV1_0_S4U_LOGON_FLAG_CHECK_LOGONHOURS
		}
		for i, nts := range []*windows.NTUnicodeString{&logonInfo.UserPrincipalName, &logonInfo.DomainName} {
			winutil.SetNTString(nts, slcs[i])
		}

		authInfo = unsafe.Pointer(logonInfo)
		authInfoLen = logonInfoLen
	}

	var srcContext _TOKEN_SOURCE
	copy(srcContext.SourceName[:], []byte(srcName))
	if err := allocateLocallyUniqueId(&srcContext.SourceIdentifier); err != nil {
		return 0, err
	}

	originName, err := windows.NewNTString(srcName)
	if err != nil {
		return 0, err
	}

	var profileBuf uintptr
	var profileBufLen uint32
	var logonID windows.LUID
	var quotas _QUOTA_LIMITS
	var subNTStatus windows.NTStatus
	ntStatus := lsaLogonUser(ls.handle, originName, _Network, pkgID, authInfo, authInfoLen, nil, &srcContext, &profileBuf, &profileBufLen, &logonID, &token, &quotas, &subNTStatus)
	if e := wingoes.ErrorFromNTStatus(ntStatus); e.Failed() {
		return 0, fmt.Errorf("LsaLogonUser(%q): %w, SubStatus: %v", u.Username, e, subNTStatus)
	}
	if profileBuf != 0 {
		lsaFreeReturnBuffer(profileBuf)
	}
	return token, nil
}

// samToUPN16 converts SAM-style account name samName to a UPN account name,
// returned as a UTF-16 slice.
func samToUPN16(samName string) (upn16 []uint16, err error) {
	_, samAccount, hasSep := strings.Cut(samName, `\`)
	if !hasSep {
		return nil, fmt.Errorf("%w: expected samName to contain a backslash", os.ErrInvalid)
	}

	// This is essentially the same algorithm used by Win32-OpenSSH:
	// First, try obtaining a UPN directly...
	upn16, err = translateName(samName, windows.NameSamCompatible, windows.NameUserPrincipal)
	if err == nil {
		return upn16, err
	}

	// Fallback: Try manually composing a UPN. First obtain the canonical name...
	canonical16, err := translateName(samName, windows.NameSamCompatible, windows.NameCanonical)
	if err != nil {
		return nil, err
	}
	canonical := windows.UTF16ToString(canonical16)

	// Extract the domain name...
	domain, _, _ := strings.Cut(canonical, "/")

	// ...and finally create the UPN by joining the samAccount and domain.
	upn := strings.Join([]string{samAccount, domain}, "@")
	return windows.UTF16FromString(upn)
}

func translateName(from string, fromFmt uint32, toFmt uint32) (result []uint16, err error) {
	from16, err := windows.UTF16PtrFromString(from)
	if err != nil {
		return nil, err
	}

	var to16Len uint32
	if err := windows.TranslateName(from16, fromFmt, toFmt, nil, &to16Len); err != nil {
		return nil, err
	}

	to16Buf := make([]uint16, to16Len)
	if err := windows.TranslateName(from16, fromFmt, toFmt, unsafe.SliceData(to16Buf), &to16Len); err != nil {
		return nil, err
	}

	return to16Buf, nil
}
