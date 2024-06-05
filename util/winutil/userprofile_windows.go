// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package winutil

import (
	"os/user"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"tailscale.com/types/logger"
	"tailscale.com/util/winutil/winenv"
)

type _PROFILEINFO struct {
	Size        uint32
	Flags       uint32
	UserName    *uint16
	ProfilePath *uint16
	DefaultPath *uint16
	ServerName  *uint16
	PolicyPath  *uint16
	Profile     registry.Key
}

// _PROFILEINFO flags
const (
	_PI_NOUI = 0x00000001
)

type _USER_INFO_4 struct {
	Name            *uint16
	Password        *uint16
	PasswordAge     uint32
	Priv            uint32
	HomeDir         *uint16
	Comment         *uint16
	Flags           uint32
	ScriptPath      *uint16
	AuthFlags       uint32
	FullName        *uint16
	UsrComment      *uint16
	Parms           *uint16
	Workstations    *uint16
	LastLogon       uint32
	LastLogoff      uint32
	AcctExpires     uint32
	MaxStorage      uint32
	UnitsPerWeek    uint32
	LogonHours      *byte
	BadPwCount      uint32
	NumLogons       uint32
	LogonServer     *uint16
	CountryCode     uint32
	CodePage        uint32
	UserSID         *windows.SID
	PrimaryGroupID  uint32
	Profile         *uint16
	HomeDirDrive    *uint16
	PasswordExpired uint32
}

// UserProfile encapsulates a loaded Windows user profile.
type UserProfile struct {
	token      windows.Token
	profileKey registry.Key
}

// LoadUserProfile loads the Windows user profile associated with token and u.
// u serves simply as a hint for speeding up resolution of the username and thus
// must reference the same user as token. u may also be nil, in which case token
// is queried for the username.
func LoadUserProfile(token windows.Token, u *user.User) (up *UserProfile, err error) {
	computerName, userName, err := getComputerAndUserName(token, u)
	if err != nil {
		return nil, err
	}

	var roamingProfilePath *uint16
	if winenv.IsDomainJoined() {
		roamingProfilePath, err = getRoamingProfilePath(nil, computerName, userName)
		if err != nil {
			return nil, err
		}
	}

	pi := _PROFILEINFO{
		Size:        uint32(unsafe.Sizeof(_PROFILEINFO{})),
		Flags:       _PI_NOUI,
		UserName:    userName,
		ProfilePath: roamingProfilePath,
		ServerName:  computerName,
	}
	if err := loadUserProfile(token, &pi); err != nil {
		return nil, err
	}

	// Duplicate the token so that we have a copy to use during cleanup without
	// consuming the token passed into this function.
	var dupToken windows.Handle
	cp := windows.CurrentProcess()
	if err := windows.DuplicateHandle(cp, windows.Handle(token), cp, &dupToken, 0,
		false, windows.DUPLICATE_SAME_ACCESS); err != nil {
		return nil, err
	}

	return &UserProfile{
		token:      windows.Token(dupToken),
		profileKey: pi.Profile,
	}, nil
}

// RegKey returns the registry key associated with the user profile.
// The caller must not close the returned key.
func (up *UserProfile) RegKey() registry.Key {
	return up.profileKey
}

// Close unloads the user profile and cleans up any other resources held by up.
func (up *UserProfile) Close() error {
	if up.profileKey != 0 {
		if err := unloadUserProfile(up.token, up.profileKey); err != nil {
			return err
		}
		up.profileKey = 0
	}

	if up.token != 0 {
		up.token.Close()
		up.token = 0
	}
	return nil
}

func getRoamingProfilePath(logf logger.Logf, computerName, userName *uint16) (path *uint16, err error) {
	// logf is for debugging/testing.
	if logf == nil {
		logf = logger.Discard
	}

	var pbuf *byte
	if err := windows.NetUserGetInfo(computerName, userName, 4, &pbuf); err != nil {
		return nil, err
	}
	defer windows.NetApiBufferFree(pbuf)

	ui4 := (*_USER_INFO_4)(unsafe.Pointer(pbuf))
	logf("getRoamingProfilePath: got %#v", *ui4)
	profilePath := ui4.Profile
	if profilePath == nil {
		return nil, nil
	}

	var sz int
	for ptr := unsafe.Pointer(profilePath); *(*uint16)(ptr) != 0; sz++ {
		ptr = unsafe.Pointer(uintptr(ptr) + unsafe.Sizeof(*profilePath))
	}

	if sz == 0 {
		return nil, nil
	}

	buf := unsafe.Slice(profilePath, sz+1)
	cp := append([]uint16{}, buf...)
	return unsafe.SliceData(cp), nil
}

func getComputerAndUserName(token windows.Token, u *user.User) (computerName *uint16, userName *uint16, err error) {
	if u == nil {
		tokenUser, err := token.GetTokenUser()
		if err != nil {
			return nil, nil, err
		}

		u, err = user.LookupId(tokenUser.User.Sid.String())
		if err != nil {
			return nil, nil, err
		}
	}

	var strComputer, strUser string
	before, after, hasBackslash := strings.Cut(u.Username, `\`)
	if hasBackslash {
		strComputer = before
		strUser = after
	} else {
		strUser = before
	}

	if strComputer != "" {
		computerName, err = windows.UTF16PtrFromString(strComputer)
		if err != nil {
			return nil, nil, err
		}
	}

	userName, err = windows.UTF16PtrFromString(strUser)
	if err != nil {
		return nil, nil, err
	}

	return computerName, userName, nil
}
