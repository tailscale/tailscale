// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package syspolicy

import (
	"tailscale.com/util/syspolicy/internal"
	"tailscale.com/util/syspolicy/pkey"
	"tailscale.com/util/syspolicy/setting"
	"tailscale.com/util/testenv"
)

// implicitDefinitions is a list of [setting.Definition] that will be registered
// automatically when the policy setting definitions are first used by the syspolicy package hierarchy.
// This includes the first time a policy needs to be read from any source.
var implicitDefinitions = []*setting.Definition{
	// Device policy settings (can only be configured on a per-device basis):
	setting.NewDefinition(pkey.AllowedSuggestedExitNodes, setting.DeviceSetting, setting.StringListValue),
	setting.NewDefinition(pkey.AllowExitNodeOverride, setting.DeviceSetting, setting.BooleanValue),
	setting.NewDefinition(pkey.AllowTailscaledRestart, setting.DeviceSetting, setting.BooleanValue),
	setting.NewDefinition(pkey.AlwaysOn, setting.DeviceSetting, setting.BooleanValue),
	setting.NewDefinition(pkey.AlwaysOnOverrideWithReason, setting.DeviceSetting, setting.BooleanValue),
	setting.NewDefinition(pkey.ApplyUpdates, setting.DeviceSetting, setting.PreferenceOptionValue),
	setting.NewDefinition(pkey.AuthKey, setting.DeviceSetting, setting.StringValue),
	setting.NewDefinition(pkey.CheckUpdates, setting.DeviceSetting, setting.PreferenceOptionValue),
	setting.NewDefinition(pkey.ControlURL, setting.DeviceSetting, setting.StringValue),
	setting.NewDefinition(pkey.DeviceSerialNumber, setting.DeviceSetting, setting.StringValue),
	setting.NewDefinition(pkey.EnableDNSRegistration, setting.DeviceSetting, setting.PreferenceOptionValue),
	setting.NewDefinition(pkey.EnableIncomingConnections, setting.DeviceSetting, setting.PreferenceOptionValue),
	setting.NewDefinition(pkey.EnableRunExitNode, setting.DeviceSetting, setting.PreferenceOptionValue),
	setting.NewDefinition(pkey.EnableServerMode, setting.DeviceSetting, setting.PreferenceOptionValue),
	setting.NewDefinition(pkey.EnableTailscaleDNS, setting.DeviceSetting, setting.PreferenceOptionValue),
	setting.NewDefinition(pkey.EnableTailscaleSubnets, setting.DeviceSetting, setting.PreferenceOptionValue),
	setting.NewDefinition(pkey.ExitNodeAllowLANAccess, setting.DeviceSetting, setting.PreferenceOptionValue),
	setting.NewDefinition(pkey.ExitNodeID, setting.DeviceSetting, setting.StringValue),
	setting.NewDefinition(pkey.ExitNodeIP, setting.DeviceSetting, setting.StringValue),
	setting.NewDefinition(pkey.FlushDNSOnSessionUnlock, setting.DeviceSetting, setting.BooleanValue),
	setting.NewDefinition(pkey.EncryptState, setting.DeviceSetting, setting.BooleanValue),
	setting.NewDefinition(pkey.Hostname, setting.DeviceSetting, setting.StringValue),
	setting.NewDefinition(pkey.LogSCMInteractions, setting.DeviceSetting, setting.BooleanValue),
	setting.NewDefinition(pkey.LogTarget, setting.DeviceSetting, setting.StringValue),
	setting.NewDefinition(pkey.MachineCertificateSubject, setting.DeviceSetting, setting.StringValue),
	setting.NewDefinition(pkey.PostureChecking, setting.DeviceSetting, setting.PreferenceOptionValue),
	setting.NewDefinition(pkey.ReconnectAfter, setting.DeviceSetting, setting.DurationValue),
	setting.NewDefinition(pkey.Tailnet, setting.DeviceSetting, setting.StringValue),
	setting.NewDefinition(pkey.HardwareAttestation, setting.DeviceSetting, setting.BooleanValue),

	// User policy settings (can be configured on a user- or device-basis):
	setting.NewDefinition(pkey.AdminConsoleVisibility, setting.UserSetting, setting.VisibilityValue),
	setting.NewDefinition(pkey.AutoUpdateVisibility, setting.UserSetting, setting.VisibilityValue),
	setting.NewDefinition(pkey.ExitNodeMenuVisibility, setting.UserSetting, setting.VisibilityValue),
	setting.NewDefinition(pkey.KeyExpirationNoticeTime, setting.UserSetting, setting.DurationValue),
	setting.NewDefinition(pkey.ManagedByCaption, setting.UserSetting, setting.StringValue),
	setting.NewDefinition(pkey.ManagedByOrganizationName, setting.UserSetting, setting.StringValue),
	setting.NewDefinition(pkey.ManagedByURL, setting.UserSetting, setting.StringValue),
	setting.NewDefinition(pkey.NetworkDevicesVisibility, setting.UserSetting, setting.VisibilityValue),
	setting.NewDefinition(pkey.PreferencesMenuVisibility, setting.UserSetting, setting.VisibilityValue),
	setting.NewDefinition(pkey.ResetToDefaultsVisibility, setting.UserSetting, setting.VisibilityValue),
	setting.NewDefinition(pkey.RunExitNodeVisibility, setting.UserSetting, setting.VisibilityValue),
	setting.NewDefinition(pkey.SuggestedExitNodeVisibility, setting.UserSetting, setting.VisibilityValue),
	setting.NewDefinition(pkey.TestMenuVisibility, setting.UserSetting, setting.VisibilityValue),
	setting.NewDefinition(pkey.UpdateMenuVisibility, setting.UserSetting, setting.VisibilityValue),
	setting.NewDefinition(pkey.OnboardingFlowVisibility, setting.UserSetting, setting.VisibilityValue),
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
