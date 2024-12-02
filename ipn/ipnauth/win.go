// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package ipnauth

import (
	"errors"
	"runtime"

	"tailscale.com/ipn"
)

var _ Identity = (*windowsIdentity)(nil)

// windowsIdentity represents identity of a Windows user.
type windowsIdentity struct {
	tok WindowsToken
	env WindowsEnvironment
}

// newWindowsIdentity returns a new WindowsIdentity with the specified token and environment.
func newWindowsIdentity(tok WindowsToken, env WindowsEnvironment) *windowsIdentity {
	identity := &windowsIdentity{tok, env}
	runtime.SetFinalizer(identity, func(i *windowsIdentity) { i.Close() })
	return identity
}

// UserID returns SID of a Windows user account.
func (wi *windowsIdentity) UserID() ipn.WindowsUserID {
	if uid, err := wi.tok.UID(); err == nil {
		return uid
	}
	return ""
}

// UserID returns SID of a Windows user account.
func (wi *windowsIdentity) Username() (string, error) {
	return wi.tok.Username()
}

// CheckAccess reports whether wi is allowed or denied the requested access.
func (wi *windowsIdentity) CheckAccess(requested DeviceAccess) AccessCheckResult {
	checker := newAccessChecker(requested)

	// Debug and ResetAllProfiles access rights can only be granted to elevated admins.
	if res := checker.mustGrant(DeleteAllProfiles|Debug, wi.checkElevatedAdmin); res.HasResult() {
		return res
	}

	if wi.env.IsServer {
		// Only admins can create new profiles or install client updates on Windows Server devices.
		// However, we should allow these operations from non-elevated contexts (e.g GUI).
		if res := checker.tryGrant(CreateProfile|InstallUpdates, wi.checkAdmin); res.HasResult() {
			return res
		}
	} else {
		// But any user should be able to create a profile or initiate an update on non-server (e.g. Windows 10/11) devices.
		if res := checker.grant(CreateProfile | InstallUpdates); res.HasResult() {
			return res
		}
	}

	// Unconditionally grant ReadStatus and GenerateBugReport to all authenticated users, regardless of the environment.
	if res := checker.grant(ReadDeviceStatus | GenerateBugReport); res.HasResult() {
		return res
	}

	// Grant unrestricted device access to elevated admins.
	if res := checker.tryGrant(UnrestrictedDeviceAccess, wi.checkElevatedAdmin); res.HasResult() {
		return res
	}

	// Returns the final access check result, implicitly denying any access rights that have not been explicitly granted.
	return checker.result()
}

// CheckProfileAccess reports whether wi is allowed or denied the requested access to the profile.
func (wi *windowsIdentity) CheckProfileAccess(profile ipn.LoginProfileView, prefs ipn.PrefsGetter, requested ProfileAccess) AccessCheckResult {
	checker := newAccessChecker(requested)

	// To avoid privilege escalation, the ServePath access right must only be granted to elevated admins.
	// The access request will be immediately denied if wi is not an elevated admin.
	if res := checker.mustGrant(ServePath, wi.checkElevatedAdmin); res.HasResult() {
		return res
	}

	// Profile owners have unrestricted access to their own profiles.
	if wi.isProfileOwner(profile) {
		if res := checker.grant(UnrestrictedProfileAccess); res.HasResult() {
			return res
		}
	}

	if isProfileShared(profile, prefs) {
		// Allow all users to read basic profile info (e.g. profile and tailnet name)
		// and list network device for shared profiles.
		// Profile is considered shared if it has unattended mode enabled
		// and/or is not owned by a specific user (e.g. created via MDM/GP).
		sharedProfileRights := ReadProfileInfo | ListPeers
		if !wi.env.IsServer && !wi.env.IsManaged {
			// Additionally, on non-managed Windows client devices we should allow users to
			// connect / disconnect, read preferences and select exit nodes.
			sharedProfileRights |= Connect | Disconnect | ReadPrefs | ChangeExitNode
		}
		if res := checker.grant(sharedProfileRights); res.HasResult() {
			return res
		}
	}

	if !wi.env.IsServer && !isProfileEnforced(profile, prefs) {
		// Allow any user to disconnect from non-enforced Tailnets on non-Windows Server devices.
		// TODO(nickkhyl): automatically disconnect from the current Tailnet
		// when a different user logs in or unlocks their Windows session,
		// unless the unattended mode is enabled. But in the meantime, we should allow users
		// to disconnect themselves.
		if res := checker.grant(Disconnect); res.HasResult() {
			return res
		}
	}

	if isAdmin, _ := wi.tok.IsAdministrator(); isAdmin {
		// Allow local admins to disconnect from any tailnet.
		localAdminRights := Disconnect
		if wi.tok.IsElevated() {
			// Allow elevated admins unrestricted access to all local profiles,
			// except for reading private keys.
			localAdminRights |= UnrestrictedProfileAccess & ^ReadPrivateKeys
		}
		if isProfileShared(profile, prefs) {
			// Allow all admins unrestricted access to shared profiles,
			// except for reading private keys.
			// This is to allow shared profiles created by others (admins or users)
			// to be managed from the GUI client.
			localAdminRights |= UnrestrictedProfileAccess & ^ReadPrivateKeys
		}
		if res := checker.grant(localAdminRights); res.HasResult() {
			return res
		}
	}

	return checker.result()
}

// Close implements io.Closer by releasing resources associated with the Windows user identity.
func (wi *windowsIdentity) Close() error {
	if wi == nil || wi.tok == nil {
		return nil
	}
	if err := wi.tok.Close(); err != nil {
		return err
	}
	runtime.SetFinalizer(wi, nil)
	wi.tok = nil
	return nil
}

func (wi *windowsIdentity) checkAdmin() error {
	isAdmin, err := wi.tok.IsAdministrator()
	if err != nil {
		return err
	}
	if !isAdmin {
		return errors.New("the requested operation requires local admin rights")
	}
	return nil
}

func (wi *windowsIdentity) checkElevatedAdmin() error {
	if !wi.tok.IsElevated() {
		return errors.New("the requested operation requires elevation")
	}
	return nil
}

func (wi *windowsIdentity) isProfileOwner(profile ipn.LoginProfileView) bool {
	return wi.tok.IsUID(profile.LocalUserID())
}

// isProfileShared reports whether the specified profile is considered shared,
// meaning that all local users should have at least ReadProfileInfo and ListPeers
// access to it, but may be granted additional access rights based on the environment
// and their role on the device.
func isProfileShared(profile ipn.LoginProfileView, prefs ipn.PrefsGetter) bool {
	if profile.LocalUserID() == "" {
		// Profiles created as LocalSystem (e.g. via MDM) can be used by everyone on the device.
		return true
	}
	if prefs, err := prefs(); err == nil {
		// Profiles that have unattended mode enabled can be used by everyone on the device.
		return prefs.ForceDaemon()
	}
	return false
}

func isProfileEnforced(ipn.LoginProfileView, ipn.PrefsGetter) bool {
	// TODO(nickkhyl): allow to mark profiles as enforced to prevent
	// regular users from disconnecting.
	return false
}

// WindowsEnvironment describes the current Windows environment.
type WindowsEnvironment struct {
	IsServer  bool // whether running on a server edition of Windows
	IsManaged bool // whether the device is managed (domain-joined or MDM-enrolled)
}

// String returns a string representation of the environment.
func (env WindowsEnvironment) String() string {
	switch {
	case env.IsManaged && env.IsServer:
		return "Managed Server"
	case env.IsManaged && !env.IsServer:
		return "Managed Client"
	case !env.IsManaged && env.IsServer:
		return "Non-Managed Server"
	case !env.IsManaged && !env.IsServer:
		return "Non-Managed Client"
	default:
		panic("unreachable")
	}
}
