// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package atomicfile

import (
	"os"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

var _SECURITY_RESOURCE_MANAGER_AUTHORITY = windows.SidIdentifierAuthority{[6]byte{0, 0, 0, 0, 0, 9}}

// makeRandomSID generates a SID derived from a v4 GUID.
// This is basically the same algorithm used by browser sandboxes for generating
// random SIDs.
func makeRandomSID() (*windows.SID, error) {
	guid, err := windows.GenerateGUID()
	if err != nil {
		return nil, err
	}

	rids := *((*[4]uint32)(unsafe.Pointer(&guid)))

	var pSID *windows.SID
	if err := windows.AllocateAndInitializeSid(&_SECURITY_RESOURCE_MANAGER_AUTHORITY, 4, rids[0], rids[1], rids[2], rids[3], 0, 0, 0, 0, &pSID); err != nil {
		return nil, err
	}
	defer windows.FreeSid(pSID)

	// Make a copy that lives on the Go heap
	return pSID.Copy()
}

func getExistingFileSD(name string) (*windows.SECURITY_DESCRIPTOR, error) {
	const infoFlags = windows.DACL_SECURITY_INFORMATION
	return windows.GetNamedSecurityInfo(name, windows.SE_FILE_OBJECT, infoFlags)
}

func getExistingFileDACL(name string) (*windows.ACL, error) {
	sd, err := getExistingFileSD(name)
	if err != nil {
		return nil, err
	}

	dacl, _, err := sd.DACL()
	return dacl, err
}

func addDenyACEForRandomSID(dacl *windows.ACL) (*windows.ACL, error) {
	randomSID, err := makeRandomSID()
	if err != nil {
		return nil, err
	}

	randomSIDTrustee := windows.TRUSTEE{nil, windows.NO_MULTIPLE_TRUSTEE,
		windows.TRUSTEE_IS_SID, windows.TRUSTEE_IS_UNKNOWN,
		windows.TrusteeValueFromSID(randomSID)}

	entries := []windows.EXPLICIT_ACCESS{
		{
			windows.GENERIC_ALL,
			windows.DENY_ACCESS,
			windows.NO_INHERITANCE,
			randomSIDTrustee,
		},
	}

	return windows.ACLFromEntries(entries, dacl)
}

func setExistingFileDACL(name string, dacl *windows.ACL) error {
	return windows.SetNamedSecurityInfo(name, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION, nil, nil, dacl, nil)
}

// makeOrigFileWithCustomDACL creates a new, temporary file with a custom
// DACL that we can check for later. It returns the name of the temporary
// file and the security descriptor for the file in SDDL format.
func makeOrigFileWithCustomDACL() (name, sddl string, err error) {
	f, err := os.CreateTemp("", "foo*.tmp")
	if err != nil {
		return "", "", err
	}
	name = f.Name()
	if err := f.Close(); err != nil {
		return "", "", err
	}
	f = nil
	defer func() {
		if err != nil {
			os.Remove(name)
		}
	}()

	dacl, err := getExistingFileDACL(name)
	if err != nil {
		return "", "", err
	}

	// Add a harmless, deny-only ACE for a random SID that isn't used for anything
	// (but that we can check for later).
	dacl, err = addDenyACEForRandomSID(dacl)
	if err != nil {
		return "", "", err
	}

	if err := setExistingFileDACL(name, dacl); err != nil {
		return "", "", err
	}

	sd, err := getExistingFileSD(name)
	if err != nil {
		return "", "", err
	}

	return name, sd.String(), nil
}

func TestPreserveSecurityInfo(t *testing.T) {
	// Make a test file with a custom ACL.
	origFileName, want, err := makeOrigFileWithCustomDACL()
	if err != nil {
		t.Fatalf("makeOrigFileWithCustomDACL returned %v", err)
	}
	t.Cleanup(func() {
		os.Remove(origFileName)
	})

	if err := WriteFile(origFileName, []byte{}, 0); err != nil {
		t.Fatalf("WriteFile returned %v", err)
	}

	// We expect origFileName's security descriptor to be unchanged despite
	// the WriteFile call.
	sd, err := getExistingFileSD(origFileName)
	if err != nil {
		t.Fatalf("getExistingFileSD(%q) returned %v", origFileName, err)
	}

	if got := sd.String(); got != want {
		t.Errorf("security descriptor comparison failed: got %q, want %q", got, want)
	}
}
