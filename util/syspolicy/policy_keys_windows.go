// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package syspolicy

var stringKeys = []Key{
	ControlURL,
	LogTarget,
	Tailnet,
	ExitNodeID,
	ExitNodeIP,
	EnableIncomingConnections,
	EnableServerMode,
	ExitNodeAllowLANAccess,
	EnableTailscaleDNS,
	EnableTailscaleSubnets,
	AdminConsoleVisibility,
	NetworkDevicesVisibility,
	TestMenuVisibility,
	UpdateMenuVisibility,
	RunExitNodeVisibility,
	PreferencesMenuVisibility,
	ExitNodeMenuVisibility,
	AutoUpdateVisibility,
	ResetToDefaultsVisibility,
	KeyExpirationNoticeTime,
	PostureChecking,
	ManagedByOrganizationName,
	ManagedByCaption,
	ManagedByURL,
}

var boolKeys = []Key{
	LogSCMInteractions,
	FlushDNSOnSessionUnlock,
}

var uint64Keys = []Key{}
