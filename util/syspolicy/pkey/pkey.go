// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package pkey defines the keys used to store system policies in the registry.
//
// This is a leaf package meant to only contain string constants, not code.
package pkey

// Key is a string that uniquely identifies a policy and must remain unchanged
// once established and documented for a given policy setting. It may contain
// alphanumeric characters and zero or more [KeyPathSeparator]s to group
// individual policy settings into categories.
type Key string

// KeyPathSeparator allows logical grouping of policy settings into categories.
const KeyPathSeparator = '/'

// The const block below lists known policy keys.
// When adding a key to this list, remember to add a corresponding
// [setting.Definition] to [implicitDefinitions] in util/syspolicy/policy_keys.go.
// Otherwise, the [TestKnownKeysRegistered] test will fail as a reminder.

const (
	// Keys with a string value
	ControlURL Key = "LoginURL"  // default ""; if blank, ipn uses ipn.DefaultControlURL.
	LogTarget  Key = "LogTarget" // default ""; if blank logging uses logtail.DefaultHost.
	Tailnet    Key = "Tailnet"   // default ""; if blank, no tailnet name is sent to the server.

	// AlwaysOn is a boolean key that controls whether Tailscale
	// should always remain in a connected state, and the user should
	// not be able to disconnect at their discretion.
	//
	// Warning: This policy setting is experimental and may change or be removed in the future.
	// It may also not be fully supported by all Tailscale clients until it is out of experimental status.
	// See tailscale/corp#26247, tailscale/corp#26248 and tailscale/corp#26249 for more information.
	AlwaysOn Key = "AlwaysOn.Enabled"

	// AlwaysOnOverrideWithReason is a boolean key that alters the behavior
	// of [AlwaysOn]. When true, the user is allowed to disconnect Tailscale
	// by providing a reason. The reason is logged and sent to the control
	// for auditing purposes. It has no effect when [AlwaysOn] is false.
	AlwaysOnOverrideWithReason Key = "AlwaysOn.OverrideWithReason"

	// ReconnectAfter is a string value formatted for use with time.ParseDuration()
	// that defines the duration after which the client should automatically reconnect
	// to the Tailscale network following a user-initiated disconnect.
	// An empty string or a zero duration disables automatic reconnection.
	ReconnectAfter Key = "ReconnectAfter"

	// AllowTailscaledRestart is a boolean key that controls whether users with write access
	// to the LocalAPI are allowed to shutdown tailscaled with the intention of restarting it.
	// On Windows, tailscaled will be restarted automatically by the service process
	// (see babysitProc in cmd/tailscaled/tailscaled_windows.go).
	// On other platforms, it is the client's responsibility to restart tailscaled.
	AllowTailscaledRestart Key = "AllowTailscaledRestart"

	// ExitNodeID is the exit node's node id. default ""; if blank, no exit node is forced.
	// Exit node ID takes precedence over exit node IP.
	// To find the node ID, go to /api.md#device.
	ExitNodeID Key = "ExitNodeID"
	ExitNodeIP Key = "ExitNodeIP" // default ""; if blank, no exit node is forced. Value is exit node IP.

	// AllowExitNodeOverride is a boolean key that allows the user to override exit node policy settings
	// and manually select an exit node. It does not allow disabling exit node usage entirely.
	// It is typically used in conjunction with [ExitNodeID] set to "auto:any".
	//
	// Warning: This policy setting is experimental and may change, be renamed or removed in the future.
	// It may also not be fully supported by all Tailscale clients until it is out of experimental status.
	// See tailscale/corp#29969.
	AllowExitNodeOverride Key = "ExitNode.AllowOverride"

	// Keys with a string value that specifies an option: "always", "never", "user-decides".
	// The default is "user-decides" unless otherwise stated. Enforcement of
	// these policies is typically performed in ipnlocal.applySysPolicy(). GUIs
	// typically hide menu items related to policies that are enforced.
	EnableIncomingConnections Key = "AllowIncomingConnections"
	EnableServerMode          Key = "UnattendedMode"
	ExitNodeAllowLANAccess    Key = "ExitNodeAllowLANAccess"
	EnableTailscaleDNS        Key = "UseTailscaleDNSSettings"
	EnableTailscaleSubnets    Key = "UseTailscaleSubnets"

	// EnableDNSRegistration is a string value that can be set to "always", "never"
	// or "user-decides". It controls whether DNS registration and dynamic DNS
	// updates are enabled for the Tailscale interface. For historical reasons
	// and to maintain compatibility with existing setups, the default is "never".
	// It is only used on Windows.
	EnableDNSRegistration Key = "EnableDNSRegistration"

	// CheckUpdates is the key to signal if the updater should periodically
	// check for updates.
	CheckUpdates Key = "CheckUpdates"
	// ApplyUpdates is the key to signal if updates should be automatically
	// installed. Its value is "InstallUpdates" because of an awkwardly-named
	// visibility option "ApplyUpdates" on MacOS.
	ApplyUpdates Key = "InstallUpdates"
	// EnableRunExitNode controls if the device acts as an exit node. Even when
	// running as an exit node, the device must be approved by a tailnet
	// administrator. Its name is slightly awkward because RunExitNodeVisibility
	// predates this option but is preserved for backwards compatibility.
	EnableRunExitNode Key = "AdvertiseExitNode"

	// Keys with a string value that controls visibility: "show", "hide".
	// The default is "show" unless otherwise stated. Enforcement of these
	// policies is typically performed by the UI code for the relevant operating
	// system.
	AdminConsoleVisibility    Key = "AdminConsole"
	NetworkDevicesVisibility  Key = "NetworkDevices"
	TestMenuVisibility        Key = "TestMenu"
	UpdateMenuVisibility      Key = "UpdateMenu"
	ResetToDefaultsVisibility Key = "ResetToDefaults"
	// RunExitNodeVisibility controls if the "run as exit node" menu item is
	// visible, without controlling the setting itself. This is preserved for
	// backwards compatibility but prefer EnableRunExitNode in new deployments.
	RunExitNodeVisibility     Key = "RunExitNode"
	PreferencesMenuVisibility Key = "PreferencesMenu"
	ExitNodeMenuVisibility    Key = "ExitNodesPicker"
	// AutoUpdateVisibility is the key to signal if the menu item for automatic
	// installation of updates should be visible. It is only used by macsys
	// installations and uses the Sparkle naming convention, even though it does
	// not actually control updates, merely the UI for that setting.
	AutoUpdateVisibility Key = "ApplyUpdates"
	// SuggestedExitNodeVisibility controls the visibility of suggested exit nodes in the client GUI.
	// When this system policy is set to 'hide', an exit node suggestion won't be presented to the user as part of the exit nodes picker.
	SuggestedExitNodeVisibility Key = "SuggestedExitNode"
	// OnboardingFlowVisibility controls the visibility of the onboarding flow in the client GUI.
	// When this system policy is set to 'hide', the onboarding flow is never shown to the user.
	OnboardingFlowVisibility Key = "OnboardingFlow"

	// Keys with a string value formatted for use with time.ParseDuration().
	KeyExpirationNoticeTime Key = "KeyExpirationNotice" // default 24 hours

	// Boolean Keys that are only applicable on Windows. Booleans are stored in the registry as
	// DWORD or QWORD (either is acceptable). 0 means false, and anything else means true.
	// The default is 0 unless otherwise stated.
	LogSCMInteractions      Key = "LogSCMInteractions"
	FlushDNSOnSessionUnlock Key = "FlushDNSOnSessionUnlock"

	// EncryptState is a boolean setting that specifies whether to encrypt the
	// tailscaled state file.
	// Windows and Linux use a TPM device, Apple uses the Keychain.
	// It's a noop on other platforms.
	EncryptState Key = "EncryptState"

	// HardwareAttestation is a boolean key that controls whether to use a
	// hardware-backed key to bind the node identity to this device.
	HardwareAttestation Key = "HardwareAttestation"

	// PostureChecking indicates if posture checking is enabled and the client shall gather
	// posture data.
	// Key is a string value that specifies an option: "always", "never", "user-decides".
	// The default is "user-decides" unless otherwise stated.
	PostureChecking Key = "PostureChecking"
	// DeviceSerialNumber is the serial number of the device that is running Tailscale.
	// This is used on Android, iOS and tvOS to allow IT administrators to manually give us a serial number via MDM.
	// We are unable to programmatically get the serial number on mobile due to sandboxing restrictions.
	DeviceSerialNumber Key = "DeviceSerialNumber"

	// ManagedByOrganizationName indicates the name of the organization managing the Tailscale
	// install. It is displayed inside the client UI in a prominent location.
	ManagedByOrganizationName Key = "ManagedByOrganizationName"
	// ManagedByCaption is an info message displayed inside the client UI as a caption when
	// ManagedByOrganizationName is set. It can be used to provide a pointer to support resources
	// for Tailscale within the organization.
	ManagedByCaption Key = "ManagedByCaption"
	// ManagedByURL is a valid URL pointing to a support help desk for Tailscale within the
	// organization. A button in the client UI provides easy access to this URL.
	ManagedByURL Key = "ManagedByURL"

	// AuthKey is an auth key that will be used to login whenever the backend starts. This can be used to
	// automatically authenticate managed devices, without requiring user interaction.
	AuthKey Key = "AuthKey"

	// MachineCertificateSubject is the exact name of a Subject that needs
	// to be present in an identity's certificate chain to sign a RegisterRequest,
	// formatted as per pkix.Name.String(). The Subject may be that of the identity
	// itself, an intermediate CA or the root CA.
	//
	// Example: "CN=Tailscale Inc Test Root CA,OU=Tailscale Inc Test Certificate Authority,O=Tailscale Inc,ST=ON,C=CA"
	MachineCertificateSubject Key = "MachineCertificateSubject"

	// Hostname is the hostname of the device that is running Tailscale.
	// When this policy is set, it overrides the hostname that the client
	// would otherwise obtain from the OS, e.g. by calling os.Hostname().
	Hostname Key = "Hostname"

	// Keys with a string array value.

	// AllowedSuggestedExitNodes's string array value is a list of exit node IDs that restricts which exit nodes are considered when generating suggestions for exit nodes.
	AllowedSuggestedExitNodes Key = "AllowedSuggestedExitNodes"
)
