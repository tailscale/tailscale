// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package paths

import (
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows"
	"tailscale.com/util/winutil"
)

func init() {
	ensureStateDirPerms = ensureStateDirPermsWindows
}

// ensureStateDirPermsWindows applies a restrictive ACL to the directory specified by dirPath.
// It sets the following security attributes on the directory:
// Owner: The user for the current process;
// Primary Group: The primary group for the current process;
// DACL: Full control to the current user and to the Administrators group.
//
//	(We include Administrators so that admin users may still access logs;
//	 granting access exclusively to LocalSystem would require admins to use
//	 special tools to access the Log directory)
//
// Inheritance: The directory does not inherit the ACL from its parent.
//
//	However, any directories and/or files created within this
//	directory *do* inherit the ACL that we are setting.
func ensureStateDirPermsWindows(dirPath string) error {
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
	sids, err := winutil.GetCurrentUserSIDs()
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
