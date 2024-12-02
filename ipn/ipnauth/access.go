// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package ipnauth

import (
	"math/bits"
	"strconv"
	"strings"
)

// DeviceAccess is a bitmask representing the requested, required, or granted
// access rights to a device.
type DeviceAccess uint32

// ProfileAccess is a bitmask representing the requested, required, or granted
// access rights to a Tailscale login profile.
type ProfileAccess uint32

// Define access rights for general device management tasks and operations that affect all profiles.
// They are allowed or denied based on the environment and user's role on the device,
// rather than the currently active Tailscale profile.
const (
	// ReadDeviceStatus is the access right required to read non-profile specific device statuses,
	// such as the IP forwarding status. It is a non-privileged access right generally available to all users.
	// It must not grant access to any sensitive or private information,
	// including Tailscale profile names, network devices, etc.
	ReadDeviceStatus DeviceAccess = 1 << iota
	// GenerateBugReport is the access right required to generate a bug report
	// (e.g. `tailscale bugreport` in CLI or Debug > Bug Report in GUI).
	// It is a non-privileged access right granted to all users.
	GenerateBugReport
	// CreateProfile is the access right required to create new Tailscale profiles on the device.
	// This operation is privileged on Unix-like platforms, including Linux,
	// but is available to all users on non-Server Windows devices.
	CreateProfile
	// Debug is required for debugging operations that could expose sensitive information.
	// Many such operations are accessible via `tailscale debug` subcommands.
	// It is considered privileged access on all platforms, requiring root access on Unix-like systems
	// and elevated admin access on Windows.
	Debug
	// InstallUpdates is required to initiate a Tailscale client self-update on platforms that support it.
	// It is available to all users on all platforms except for Windows Server,
	// where it requires admin rights.
	InstallUpdates
	// DeleteAllProfiles is required to log out from and delete all Tailscale profiles on a device.
	// It is considered a privileged operation, requiring root access on Unix-like systems
	// and elevated admin access on Windows.
	DeleteAllProfiles

	// UnrestrictedDeviceAccess combines all possible device access rights.
	UnrestrictedDeviceAccess = ^DeviceAccess(0)
)

var deviceAccessNames = map[DeviceAccess]string{
	CreateProfile:     "CreateProfile",
	Debug:             "Debug",
	DeleteAllProfiles: "DeleteAllProfiles",
	GenerateBugReport: "GenerateBugReport",
	InstallUpdates:    "InstallUpdates",
	ReadDeviceStatus:  "ReadDeviceStatus",
}

// Define access rights that are specific to individual profiles,
// granted or denied on a per-profile basis.
const (
	// ReadProfileInfo is required to view a profile in the list of available profiles and
	// to read basic profile info like the user name and tailnet name.
	// It also allows to read profile/connection-specific status details, excluding information about peers,
	// but must not grant access to any sensitive information, such as private keys.
	//
	// This access right is granted to all users on Unix-like platforms.
	//
	// On Windows, any user should have access to their own profiles as well as profiles shared with them.
	// NOTE: As of 2024-04-08, the following are the only two ways to share a profile:
	// - Create a profile in local system's security context (e.g. via a GP/MDM/SCCM-deployed script);
	// - Enable Unattended Mode (ipn.Prefs.ForceDaemon) for the profile.
	// We'll reconsider this in tailscale/corp#18342 or subsequent tickets.
	// Additionally, Windows admins should be able to list all profiles when running elevated.
	//
	// If a user does not have ReadProfileInfo access to the current profile, its details will be masked.
	ReadProfileInfo ProfileAccess = 1 << iota
	// Connect is required to connect to and use a Tailscale profile.
	// It is considered a privileged operation on Unix-like platforms and Windows Server.
	// On Windows client devices, however, users have the Connect access right
	// to the profiles they can read.
	Connect
	// Disconnect is required to disconnect (or switch from) a Tailscale profile.
	// It is considered a privileged operation on Unix-like platforms and Windows Server.
	// On Windows Client and other platforms any user should be able to disconnect
	// from an active Tailnet.
	Disconnect
	// DeleteProfile is required to delete a local Tailscale profile.
	// Root (or operator) access is required on Unix-like platforms.
	// On Windows, profiles can be deleted by their owners. Additionally,
	// on Windows Server and managed Windows Client devices, elevated admins have the right
	// to delete any profile.
	DeleteProfile
	// ReauthProfile is required to re-authenticate a Tailscale profile.
	// Root (or operator) access is required on Unix-like platforms,
	// profile ownership or elevated admin rights is required on Windows.
	ReauthProfile
	// ListPeers is required to view peer users and devices.
	// It is granted to all users on Unix-like platform,
	// and to the same users as ReadProfileInfo on Windows.
	ListPeers

	// ReadPrefs is required to read ipn.Prefs associated with a profile,
	// but must not grant access to any sensitive information, such as private keys.
	//
	// As a general rule, the same users who have ReadProfileInfo access to a profile
	// also have the ReadPrefs access right.
	ReadPrefs
	// ChangePrefs allows changing any preference in ipn.Prefs.
	// Root (or operator) access is required on Unix-like platforms.
	// Profile ownership or elevated admin rights are required on Windows.
	ChangePrefs
	// ChangeExitNode allows users without the full ChangePrefs access to select an exit node.
	// As of 2024-04-08, it is only used to allow users on non-server, non-managed Windows devices to
	// to change an exit node on admin-configured unattended profiles.
	ChangeExitNode

	// ReadServe is required to read a serve config.
	ReadServe
	// ChangeServe allows to change a serve config, except for serving a path.
	ChangeServe
	// ServePath allows to serve an arbitrary path.
	// It is a privileged operation that is only available to users that have
	// administrative access to the local machine.
	ServePath

	// SetDNS allows sending a SetDNSRequest request to the control plane server,
	// requesting a DNS record be created or updated.
	// Root (or operator) access is required on Unix-like platforms.
	// Profile ownership or elevated admin rights are required on Windows.
	SetDNS
	// FetchCerts allows to get an ipnlocal.TLSCertKeyPair for domain, either from cache or via the ACME process.
	// On Windows, it's available to the profile owner. On Unix-like platforms, it requires root or operator access,
	// or the TS_PERMIT_CERT_UID environment variable set to the userid.
	FetchCerts
	// ReadPrivateKeys allows reading node's private key.
	// Root (or operator) access is required on Unix-like platforms.
	// Profile ownership is required on Windows.
	ReadPrivateKeys

	// ReadTKA allows reading tailnet key authority info.
	// Root (or operator) access is required on Unix-like platforms.
	// Profile ownership or elevated admin rights are required on Windows.
	ReadTKA
	// ManageTKA allows managing TKA for a profile.
	// Root (or operator) access is required on Unix-like platforms.
	// Profile ownership or elevated admin rights are required on Windows.
	ManageTKA

	// ReceiveFiles allows to receive files via Taildrop.
	// Root (or operator) access is required on Unix-like platforms.
	// Profile ownership or elevated admin rights are required on Windows.
	ReceiveFiles

	// UnrestrictedProfileAccess combines all possible profile access rights,
	// granting full access to a profile.
	UnrestrictedProfileAccess = ^ProfileAccess(0)
)

// Placeholder values for clients to use when rendering the current ipn.LoginProfile
// if the client's user does not have ipnauth.ReadProfileInfo access to the profile.
// However, clients supporting this feature should use UserProfile.ID.IsZero() to determine
// when profile information is not accessible, and render masked profiles
// in a platform-specific, localizable way.
// Clients should avoid checking against these constants, as they are subject to change.
const (
	maskedLoginName     = "Other User's Account"
	maskedDisplayName   = "Other User"
	maskedProfilePicURL = ""
	maskedDomainName    = ""
)

var profileAccessNames = map[ProfileAccess]string{
	ChangeExitNode:  "ChangeExitNode",
	ChangePrefs:     "ChangePrefs",
	ChangeServe:     "ChangeServe",
	Connect:         "Connect",
	DeleteProfile:   "DeleteProfile",
	Disconnect:      "Disconnect",
	FetchCerts:      "FetchCerts",
	ListPeers:       "ListPeers",
	ManageTKA:       "ManageTKA",
	ReadPrefs:       "ReadPrefs",
	ReadPrivateKeys: "ReadPrivateKeys",
	ReadProfileInfo: "ReadProfileInfo",
	ReadServe:       "ReadServe",
	ReadTKA:         "ReadTKA",
	ReauthProfile:   "ReauthProfile",
	ReceiveFiles:    "ReceiveFiles",
	ServePath:       "ServePath",
	SetDNS:          "SetDNS",
}

var (
	deviceAccessBitNames  = make([]string, 32)
	profileAccessBitNames = make([]string, 32)
)

func init() {
	for da, name := range deviceAccessNames {
		deviceAccessBitNames[bits.Len32(uint32(da))-1] = name
	}
	for pa, name := range profileAccessNames {
		profileAccessBitNames[bits.Len32(uint32(pa))-1] = name
	}
}

// Add adds a to da.
// It is a no-op if da already contains a.
func (da *DeviceAccess) Add(a DeviceAccess) {
	*da |= a
}

// Remove removes a from da.
// It is a no-op if da does not contain a.
func (da *DeviceAccess) Remove(a DeviceAccess) {
	*da &= ^a
}

// ContainsAll reports whether da contains all access rights specified in a.
func (da *DeviceAccess) ContainsAll(a DeviceAccess) bool {
	return (*da & a) == a
}

// Overlaps reports whether da contains any of the access rights specified in a.
func (da *DeviceAccess) Overlaps(a DeviceAccess) bool {
	return (*da & a) != 0
}

// String returns a string representation of one or more access rights in da.
// It returns (None) if da is zero.
func (da *DeviceAccess) String() string {
	return formatAccessMask(uint32(*da), deviceAccessBitNames)
}

// Add adds a to pa.
// It is a no-op if pa already contains a.
func (pa *ProfileAccess) Add(a ProfileAccess) {
	*pa |= a
}

// Remove removes a from pa.
// It is a no-op if pa does not contain a.
func (pa *ProfileAccess) Remove(a ProfileAccess) {
	*pa &= ^a
}

// Contains reports whether pa contains all access rights specified in a.
func (pa *ProfileAccess) Contains(a ProfileAccess) bool {
	return (*pa & a) == a
}

// Overlaps reports whether pa contains any of the access rights specified in a.
func (pa *ProfileAccess) Overlaps(a ProfileAccess) bool {
	return (*pa & a) != 0
}

// String returns a string representation of one or more access rights in pa.
// It returns (None) if pa is zero.
func (pa *ProfileAccess) String() string {
	return formatAccessMask(uint32(*pa), profileAccessBitNames)
}

func formatAccessMask(v uint32, flagNames []string) string {
	switch {
	case v == 0:
		return "(None)"
	case v == ^uint32(0):
		return "(Unrestricted)"
	case (v & (v - 1)) == 0:
		return flagNames[bits.Len32(v)-1]
	default:
		return formatAccessMaskSlow(v, flagNames)
	}
}

func formatAccessMaskSlow(v uint32, flagNames []string) string {
	var rem uint32
	flags := make([]string, 0, bits.OnesCount32(v))
	for i := 0; i < 32 && v != 0; i++ {
		if bf := uint32(1 << i); v&bf != 0 {
			if name := flagNames[i]; name != "" {
				flags = append(flags, name)
			} else {
				rem |= bf
			}
			v &= ^bf
		}
	}
	if rem != 0 {
		flags = append(flags, "0x"+strings.ToUpper(strconv.FormatUint(uint64(rem), 16)))
	}
	return strings.Join(flags, "|")
}
