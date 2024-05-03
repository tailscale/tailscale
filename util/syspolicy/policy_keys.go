// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package syspolicy

type Key string

const (
	// Keys with a string value
	ControlURL Key = "LoginURL"  // default ""; if blank, ipn uses ipn.DefaultControlURL.
	LogTarget  Key = "LogTarget" // default ""; if blank logging uses logtail.DefaultHost.
	Tailnet    Key = "Tailnet"   // default ""; if blank, no tailnet name is sent to the server.
	// ExitNodeID is the exit node's node id. default ""; if blank, no exit node is forced.
	// Exit node ID takes precedence over exit node IP.
	// To find the node ID, go to /api.md#device.
	ExitNodeID Key = "ExitNodeID"
	ExitNodeIP Key = "ExitNodeIP" // default ""; if blank, no exit node is forced. Value is exit node IP.

	// Keys with a string value that specifies an option: "always", "never", "user-decides".
	// The default is "user-decides" unless otherwise stated. Enforcement of
	// these policies is typically performed in ipnlocal.applySysPolicy(). GUIs
	// typically hide menu items related to policies that are enforced.
	EnableIncomingConnections Key = "AllowIncomingConnections"
	EnableServerMode          Key = "UnattendedMode"
	ExitNodeAllowLANAccess    Key = "ExitNodeAllowLANAccess"
	EnableTailscaleDNS        Key = "UseTailscaleDNSSettings"
	EnableTailscaleSubnets    Key = "UseTailscaleSubnets"
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

	// Keys with a string value formatted for use with time.ParseDuration().
	KeyExpirationNoticeTime Key = "KeyExpirationNotice" // default 24 hours

	// Boolean Keys that are only applicable on Windows. Booleans are stored in the registry as
	// DWORD or QWORD (either is acceptable). 0 means false, and anything else means true.
	// The default is 0 unless otherwise stated.
	LogSCMInteractions      Key = "LogSCMInteractions"
	FlushDNSOnSessionUnlock Key = "FlushDNSOnSessionUnlock"

	// PostureChecking indicates if posture checking is enabled and the client shall gather
	// posture data.
	// Key is a string value that specifies an option: "always", "never", "user-decides".
	// The default is "user-decides" unless otherwise stated.
	PostureChecking Key = "PostureChecking"

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

	// Keys with a string array value.
	// AllowedSuggestedExitNodes's string array value is a list of exit node IDs that restricts which exit nodes are considered when generating suggestions for exit nodes.
	AllowedSuggestedExitNodes Key = "AllowedSuggestedExitNodes"
)
