// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package paths

import (
	"log"
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

func getTokenInfo(token windows.Token, infoClass uint32) ([]byte, error) {
	var desiredLen uint32
	err := windows.GetTokenInformation(token, infoClass, nil, 0, &desiredLen)
	if err != nil && err != windows.ERROR_INSUFFICIENT_BUFFER {
		log.Printf("getTokenInfo failed; obtaining info length: %v", err)
		return nil, err
	}

	buf := make([]byte, desiredLen)
	actualLen := desiredLen
	err = windows.GetTokenInformation(token, infoClass, &buf[0], desiredLen, &actualLen)
	if err != nil {
		log.Printf("getTokenInfo failed; obtaining info: %v", err)
	}
	return buf, err
}

func getTokenUserInfo(token windows.Token) (*windows.Tokenuser, error) {
	buf, err := getTokenInfo(token, windows.TokenUser)
	if err != nil {
		log.Printf("getTokenUserInfo failed; getTokenInfo error: %v", err)
		return nil, err
	}

	return (*windows.Tokenuser)(unsafe.Pointer(&buf[0])), nil
}

func getTokenPrimaryGroupInfo(token windows.Token) (*windows.Tokenprimarygroup, error) {
	buf, err := getTokenInfo(token, windows.TokenPrimaryGroup)
	if err != nil {
		log.Printf("getTokenPrimaryGroupInfo failed; getTokenInfo error: %v", err)
		return nil, err
	}

	return (*windows.Tokenprimarygroup)(unsafe.Pointer(&buf[0])), nil
}

type UserSids struct {
	User         *windows.SID
	PrimaryGroup *windows.SID
}

func getCurrentUserSids() (*UserSids, error) {
	token := windows.GetCurrentProcessToken()
	userInfo, err := getTokenUserInfo(token)
	if err != nil {
		log.Printf("getCurrentUserSids failed; getTokenUserInfo error: %v", err)
		return nil, err
	}

	primaryGroup, err := getTokenPrimaryGroupInfo(token)
	if err != nil {
		log.Printf("getCurrentUserSids failed; getTokenPrimaryGroupInfo error: %v", err)
		return nil, err
	}

	return &UserSids{userInfo.User.Sid, primaryGroup.PrimaryGroup}, nil
}

// SetStateDirPerms applies a restrictive ACL to the directory specified by dirPath.
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
func SetStateDirPerms(dirPath string) error {
	info, err := os.Stat(dirPath)
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return os.ErrInvalid
	}

	// We need the info for our current user as SIDs
	sids, err := getCurrentUserSids()
	if err != nil {
		return err
	}

	// We also need the SID for the Administrators group so that admins may
	// easily access logs.
	administratorsGroupSid, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		log.Printf("SetStateDirPerms failed; get Administrators SID: %v", err)
		return err
	}

	// Munge the SIDs into the format required by EXPLICIT_ACCESS.
	userTrustee := windows.TRUSTEE{nil, windows.NO_MULTIPLE_TRUSTEE,
		windows.TRUSTEE_IS_SID, windows.TRUSTEE_IS_USER,
		windows.TrusteeValueFromSID(sids.User)}

	adminTrustee := windows.TRUSTEE{nil, windows.NO_MULTIPLE_TRUSTEE,
		windows.TRUSTEE_IS_SID, windows.TRUSTEE_IS_WELL_KNOWN_GROUP,
		windows.TrusteeValueFromSID(administratorsGroupSid)}

	// We declare our access rights via this array of EXPLICIT_ACCESS structures.
	// We set full access to our user and to Administrators.
	// We configure the DACL such that any Files or directories created within
	// dirPath will also inherit this DACL.
	explicitAccess := []windows.EXPLICIT_ACCESS{
		windows.EXPLICIT_ACCESS{
			windows.GENERIC_ALL,
			windows.SET_ACCESS,
			windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT,
			userTrustee,
		},
		windows.EXPLICIT_ACCESS{
			windows.GENERIC_ALL,
			windows.SET_ACCESS,
			windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT,
			adminTrustee,
		},
	}

	dacl, err := windows.ACLFromEntries(explicitAccess, nil)
	if err != nil {
		log.Printf("SetStateDirPerms failed; build DACL: %v", err)
		return err
	}

	// We now reset the file's owner, primary group, and DACL.
	// We also must pass PROTECTED_DACL_SECURITY_INFORMATION so that our new ACL
	// does not inherit any ACL entries from the parent directory.
	const setFlags windows.SECURITY_INFORMATION = windows.OWNER_SECURITY_INFORMATION |
		windows.GROUP_SECURITY_INFORMATION |
		windows.DACL_SECURITY_INFORMATION |
		windows.PROTECTED_DACL_SECURITY_INFORMATION
	err = windows.SetNamedSecurityInfo(dirPath, windows.SE_FILE_OBJECT, setFlags,
		sids.User, sids.PrimaryGroup, dacl, nil)
	if err != nil {
		log.Printf("SetStateDirPerms failed; set ACL on dirPath: %v", err)
	}

	return err
}
