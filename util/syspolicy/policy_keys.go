// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package syspolicy

import (
	"tailscale.com/types/lazy"
	"tailscale.com/util/syspolicy/internal"
	"tailscale.com/util/syspolicy/setting"
	"tailscale.com/util/testenv"
)

// Key is a string that uniquely identifies a policy and must remain unchanged
// once established and documented for a given policy setting. It may contain
// alphanumeric characters and zero or more [KeyPathSeparator]s to group
// individual policy settings into categories.
type Key = setting.Key

// The const block below lists known policy keys.
// When adding a key to this list, remember to add a corresponding
// [setting.Definition] to [implicitDefinitions] below.
// Otherwise, the [TestKnownKeysRegistered] test will fail as a reminder.

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

	// PostureChecking indicates if posture checking is enabled and the client shall gather
	// posture data.
	// Key is a string value that specifies an option: "always", "never", "user-decides".
	// The default is "user-decides" unless otherwise stated.
	PostureChecking Key = "PostureChecking"
	// DeviceSerialNumber is the serial number of the device that is running Tailscale.
	// This is used on iOS/tvOS to allow IT administrators to manually give us a serial number via MDM.
	// We are unable to programmatically get the serial number from IOKit due to sandboxing restrictions.
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

	// Keys with a string array value.
	// AllowedSuggestedExitNodes's string array value is a list of exit node IDs that restricts which exit nodes are considered when generating suggestions for exit nodes.
	AllowedSuggestedExitNodes Key = "AllowedSuggestedExitNodes"
)

// implicitDefinitions is a list of [setting.Definition] that will be registered
// automatically when the policy setting definitions are first used by the syspolicy package hierarchy.
// This includes the first time a policy needs to be read from any source.
var implicitDefinitions = []*setting.Definition{
	// Device policy settings (can only be configured on a per-device basis):
	setting.NewDefinition(AllowedSuggestedExitNodes, setting.DeviceSetting, setting.StringListValue),
	setting.NewDefinition(ApplyUpdates, setting.DeviceSetting, setting.PreferenceOptionValue),
	setting.NewDefinition(AuthKey, setting.DeviceSetting, setting.StringValue),
	setting.NewDefinition(CheckUpdates, setting.DeviceSetting, setting.PreferenceOptionValue),
	setting.NewDefinition(ControlURL, setting.DeviceSetting, setting.StringValue),
	setting.NewDefinition(DeviceSerialNumber, setting.DeviceSetting, setting.StringValue),
	setting.NewDefinition(EnableIncomingConnections, setting.DeviceSetting, setting.PreferenceOptionValue),
	setting.NewDefinition(EnableRunExitNode, setting.DeviceSetting, setting.PreferenceOptionValue),
	setting.NewDefinition(EnableServerMode, setting.DeviceSetting, setting.PreferenceOptionValue),
	setting.NewDefinition(EnableTailscaleDNS, setting.DeviceSetting, setting.PreferenceOptionValue),
	setting.NewDefinition(EnableTailscaleSubnets, setting.DeviceSetting, setting.PreferenceOptionValue),
	setting.NewDefinition(ExitNodeAllowLANAccess, setting.DeviceSetting, setting.PreferenceOptionValue),
	setting.NewDefinition(ExitNodeID, setting.DeviceSetting, setting.StringValue),
	setting.NewDefinition(ExitNodeIP, setting.DeviceSetting, setting.StringValue),
	setting.NewDefinition(FlushDNSOnSessionUnlock, setting.DeviceSetting, setting.BooleanValue),
	setting.NewDefinition(LogSCMInteractions, setting.DeviceSetting, setting.BooleanValue),
	setting.NewDefinition(LogTarget, setting.DeviceSetting, setting.StringValue),
	setting.NewDefinition(MachineCertificateSubject, setting.DeviceSetting, setting.StringValue),
	setting.NewDefinition(PostureChecking, setting.DeviceSetting, setting.PreferenceOptionValue),
	setting.NewDefinition(Tailnet, setting.DeviceSetting, setting.StringValue),

	// User policy settings (can be configured on a user- or device-basis):
	setting.NewDefinition(AdminConsoleVisibility, setting.UserSetting, setting.VisibilityValue),
	setting.NewDefinition(AutoUpdateVisibility, setting.UserSetting, setting.VisibilityValue),
	setting.NewDefinition(ExitNodeMenuVisibility, setting.UserSetting, setting.VisibilityValue),
	setting.NewDefinition(KeyExpirationNoticeTime, setting.UserSetting, setting.DurationValue),
	setting.NewDefinition(ManagedByCaption, setting.UserSetting, setting.StringValue),
	setting.NewDefinition(ManagedByOrganizationName, setting.UserSetting, setting.StringValue),
	setting.NewDefinition(ManagedByURL, setting.UserSetting, setting.StringValue),
	setting.NewDefinition(NetworkDevicesVisibility, setting.UserSetting, setting.VisibilityValue),
	setting.NewDefinition(PreferencesMenuVisibility, setting.UserSetting, setting.VisibilityValue),
	setting.NewDefinition(ResetToDefaultsVisibility, setting.UserSetting, setting.VisibilityValue),
	setting.NewDefinition(RunExitNodeVisibility, setting.UserSetting, setting.VisibilityValue),
	setting.NewDefinition(SuggestedExitNodeVisibility, setting.UserSetting, setting.VisibilityValue),
	setting.NewDefinition(TestMenuVisibility, setting.UserSetting, setting.VisibilityValue),
	setting.NewDefinition(UpdateMenuVisibility, setting.UserSetting, setting.VisibilityValue),
	setting.NewDefinition(OnboardingFlowVisibility, setting.UserSetting, setting.VisibilityValue),
}

func init() {
	internal.Init.MustDefer(func() error {
		// Avoid implicit [setting.Definition] registration during tests.
		// Each test should control which policy settings to register.
		// Use [setting.SetDefinitionsForTest] to specify necessary definitions,
		// or [setWellKnownSettingsForTest] to set implicit definitions for the test duration.
		if testenv.InTest() {
			return nil
		}
		for _, d := range implicitDefinitions {
			setting.RegisterDefinition(d)
		}
		return nil
	})
}

var implicitDefinitionMap lazy.SyncValue[setting.DefinitionMap]

// WellKnownSettingDefinition returns a well-known, implicit setting definition by its key,
// or an [ErrNoSuchKey] if a policy setting with the specified key does not exist
// among implicit policy definitions.
func WellKnownSettingDefinition(k Key) (*setting.Definition, error) {
	m, err := implicitDefinitionMap.GetErr(func() (setting.DefinitionMap, error) {
		return setting.DefinitionMapOf(implicitDefinitions)
	})
	if err != nil {
		return nil, err
	}
	if d, ok := m[k]; ok {
		return d, nil
	}
	return nil, ErrNoSuchKey
}

// RegisterWellKnownSettingsForTest registers all implicit setting definitions
// for the duration of the test.
func RegisterWellKnownSettingsForTest(tb TB) {
	tb.Helper()
	err := setting.SetDefinitionsForTest(tb, implicitDefinitions...)
	if err != nil {
		tb.Fatalf("Failed to register well-known settings: %v", err)
	}
}
