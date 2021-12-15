// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package paths

import (
	"os"
	"path/filepath"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

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

type userSids struct {
	User         *windows.SID
	PrimaryGroup *windows.SID
}

func getCurrentUserSids() (*userSids, error) {
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

	return &userSids{userInfo.User.Sid, primaryGroup.PrimaryGroup}, nil
}

// ensureStateDirPerms applies a restrictive ACL to the directory specified by dirPath.
// It sets the following security attributes on the directory:
// Owner: The user for the current process;
// Primary Group: The primary group for the current process;
// DACL: Full control to the current user and to the Administrators group.
//       (We include Administrators so that admin users may still access logs;
//        granting access exclusively to LocalSystem would require admins to use
//        special tools to access the Log directory)
// Inheritance: The directory does not inherit the ACL from its parent.
//              However, any directories and/or files created within this
//              directory *do* inherit the ACL that we are setting.
func ensureStateDirPerms(dirPath string) error {
	fi, err := os.Stat(dirPath)
	if err != nil {
		return err
	}
	if !fi.IsDir() {
		return os.ErrInvalid
	}
	if strings.ToLower(filepath.Base(dirPath)) != "tailscale" {
		return nil
	}

	// We need the info for our current user as SIDs
	sids, err := getCurrentUserSids()
	if err != nil {
		return err
	}

	// We also need the SID for the Administrators group so that admins may
	// easily access logs.
	adminGroupSid, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return err
	}

	// Munge the SIDs into the format required by EXPLICIT_ACCESS.
	userTrustee := windows.TRUSTEE{nil, windows.NO_MULTIPLE_TRUSTEE,
		windows.TRUSTEE_IS_SID, windows.TRUSTEE_IS_USER,
		windows.TrusteeValueFromSID(sids.User)}

	adminTrustee := windows.TRUSTEE{nil, windows.NO_MULTIPLE_TRUSTEE,
		windows.TRUSTEE_IS_SID, windows.TRUSTEE_IS_WELL_KNOWN_GROUP,
		windows.TrusteeValueFromSID(adminGroupSid)}

	// We declare our access rights via this array of EXPLICIT_ACCESS structures.
	// We set full access to our user and to Administrators.
	// We configure the DACL such that any files or directories created within
	// dirPath will also inherit this DACL.
	explicitAccess := []windows.EXPLICIT_ACCESS{
		{
			windows.GENERIC_ALL,
			windows.SET_ACCESS,
			windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT,
			userTrustee,
		},
		{
			windows.GENERIC_ALL,
			windows.SET_ACCESS,
			windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT,
			adminTrustee,
		},
	}

	dacl, err := windows.ACLFromEntries(explicitAccess, nil)
	if err != nil {
		return err
	}

	// We now reset the file's owner, primary group, and DACL.
	// We also must pass PROTECTED_DACL_SECURITY_INFORMATION so that our new ACL
	// does not inherit any ACL entries from the parent directory.
	const flags = windows.OWNER_SECURITY_INFORMATION |
		windows.GROUP_SECURITY_INFORMATION |
		windows.DACL_SECURITY_INFORMATION |
		windows.PROTECTED_DACL_SECURITY_INFORMATION
	return windows.SetNamedSecurityInfo(dirPath, windows.SE_FILE_OBJECT, flags,
		sids.User, sids.PrimaryGroup, dacl, nil)
}

// LegacyStateFilePath returns the legacy path to the state file when it was stored under the
// current user's %LocalAppData%.
func LegacyStateFilePath() string {
	return filepath.Join(os.Getenv("LocalAppData"), "Tailscale", "server-state.conf")
}
