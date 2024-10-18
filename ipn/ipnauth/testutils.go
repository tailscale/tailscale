// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package ipnauth

import (
	"errors"
	"runtime"

	"tailscale.com/ipn"
	"tailscale.com/types/ptr"
)

// TestIdentity is an identity with a predefined UID, Name and access rights.
// It should only be used for testing purposes, and allows external packages
// to test against a specific set of access rights.
type TestIdentity struct {
	UID                  string        // UID is an OS-specific user id of the test user.
	Name                 string        // Name is the login name of the test user.
	DeviceAccess         DeviceAccess  // DeviceAccess is the test user's access rights on the device.
	ProfileAccess        ProfileAccess // ProfileAccess is the test user's access rights to Tailscale profiles.
	AccessOthersProfiles bool          // AccessOthersProfiles indicates whether the test user can access all profiles, regardless of their ownership.
}

var (
	// TestAdmin is a test identity that has unrestricted access to the device
	// and all Tailscale profiles on it. It should only be used for testing purposes.
	TestAdmin = &TestIdentity{
		Name:                 "admin",
		DeviceAccess:         UnrestrictedDeviceAccess,
		ProfileAccess:        UnrestrictedProfileAccess,
		AccessOthersProfiles: true,
	}
)

// NewTestIdentityWithGOOS returns a new test identity for the given GOOS,
// with the specified user name and the isAdmin flag indicating
// whether the user has administrative access on the local machine.
//
// When goos is windows, it returns an identity representing an elevated admin
// or a regular user account on a non-managed non-server environment. Callers
// that require fine-grained control over user's privileges or environment
// should use NewWindowsIdentity instead.
func NewTestIdentityWithGOOS(goos, name string, isAdmin bool) Identity {
	if goos == "windows" {
		token := &testToken{
			SID:      ipn.WindowsUserID(name),
			Name:     name,
			Admin:    isAdmin,
			Elevated: isAdmin,
		}
		return newWindowsIdentity(token, WindowsEnvironment{})
	}
	identity := &unixIdentity{goos: goos}
	identity.forceForTest.username = ptr.To(name)
	identity.forceForTest.isAdmin = ptr.To(isAdmin)
	if isAdmin {
		identity.forceForTest.uid = ptr.To("0")
	} else {
		identity.forceForTest.uid = ptr.To("1000")
	}
	return identity
}

// NewTestIdentity is like NewTestIdentityWithGOOS, but returns a test identity
// for the current platform.
func NewTestIdentity(name string, isAdmin bool) Identity {
	return NewTestIdentityWithGOOS(runtime.GOOS, name, isAdmin)
}

// UserID returns t.ID.
func (t *TestIdentity) UserID() ipn.WindowsUserID {
	return ipn.WindowsUserID(t.UID)
}

// Username returns t.Name.
func (t *TestIdentity) Username() (string, error) {
	return t.Name, nil
}

// CheckAccess reports whether the requested access is allowed or denied
// based on t.DeviceAccess.
func (t *TestIdentity) CheckAccess(requested DeviceAccess) AccessCheckResult {
	if requested&t.DeviceAccess == requested {
		return AllowAccess()
	}
	return DenyAccess(errors.New("access denied"))
}

// CheckProfileAccess reports whether the requested profile access is allowed or denied
// based on t.ProfileAccess.
func (t *TestIdentity) CheckProfileAccess(profile ipn.LoginProfileView, prefs ipn.PrefsGetter, requested ProfileAccess) AccessCheckResult {
	if !t.AccessOthersProfiles && profile.LocalUserID() != t.UserID() && profile.LocalUserID() != "" {
		return DenyAccess(errors.New("the requested profile is owned by another user"))
	}
	if t.ProfileAccess&requested == requested {
		return AllowAccess()
	}
	return DenyAccess(errors.New("access denied"))
}

// testToken implements WindowsToken and should only be used for testing purposes.
type testToken struct {
	SID             ipn.WindowsUserID
	Name            string
	Admin, Elevated bool
	LocalSystem     bool
}

// UID returns t's Security Identifier (SID).
func (t *testToken) UID() (ipn.WindowsUserID, error) {
	return t.SID, nil
}

// Username returns t's username.
func (t *testToken) Username() (string, error) {
	return t.Name, nil
}

// IsAdministrator reports whether t represents an admin's,
// but not necessarily elevated, security context.
func (t *testToken) IsAdministrator() (bool, error) {
	return t.Admin, nil
}

// IsElevated reports whether t represents an elevated security context,
// such as of LocalSystem or "Run as administrator".
func (t *testToken) IsElevated() bool {
	return t.Elevated || t.IsLocalSystem()
}

// IsLocalSystem reports whether t represents a LocalSystem's security context.
func (t *testToken) IsLocalSystem() bool {
	return t.LocalSystem
}

// UserDir is not implemented.
func (t *testToken) UserDir(folderID string) (string, error) {
	return "", errors.New("Not implemented")
}

// Close is a no-op.
func (t *testToken) Close() error {
	return nil
}

// EqualUIDs reports whether two WindowsTokens have the same UIDs.
func (t *testToken) EqualUIDs(other WindowsToken) bool {
	if t != nil && other == nil || t == nil && other != nil {
		return false
	}
	ot, ok := other.(*testToken)
	if !ok {
		return false
	}
	return t == ot || t.SID == ot.SID
}

// IsUID reports whether t has the specified UID.
func (t *testToken) IsUID(uid ipn.WindowsUserID) bool {
	return t.SID == uid
}
