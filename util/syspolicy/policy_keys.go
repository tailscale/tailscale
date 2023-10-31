// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package syspolicy

type Key string

const (
	// Keys with a string value
	ControlURL Key = "LoginURL"  // default ""; if blank, ipn uses ipn.DefaultControlURL.
	LogTarget  Key = "LogTarget" // default ""; if blank logging uses logtail.DefaultHost.
	Tailnet    Key = "Tailnet"   // default ""; if blank, no tailnet name is sent to the server.

	// Keys with a string value that specifies an option: "always", "never", "user-decides".
	// The default is "user-decides" unless otherwise stated.
	EnableIncomingConnections Key = "AllowIncomingConnections"
	EnableServerMode          Key = "UnattendedMode"

	// Keys with a string value that controls visibility: "show", "hide".
	// The default is "show" unless otherwise stated.
	AdminConsoleVisibility    Key = "AdminConsole"
	NetworkDevicesVisibility  Key = "NetworkDevices"
	TestMenuVisibility        Key = "TestMenu"
	UpdateMenuVisibility      Key = "UpdateMenu"
	RunExitNodeVisibility     Key = "RunExitNode"
	PreferencesMenuVisibility Key = "PreferencesMenu"

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
)
