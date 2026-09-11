// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package health

// Arg is a type for the key to be used in the Args of a Warnable.
type Arg string

const (
	// ArgAvailableVersion provides an update notification Warnable with the available version of the Tailscale client.
	ArgAvailableVersion Arg = "available-version"

	// ArgCurrentVersion provides an update notification Warnable with the current version of the Tailscale client.
	ArgCurrentVersion Arg = "current-version"

	// ArgDuration provides a Warnable with how long the Warnable has been in an unhealthy state.
	ArgDuration Arg = "duration"

	// ArgError provides a Warnable with the underlying error behind an unhealthy state.
	ArgError Arg = "error"

	// ArgMagicsockFunctionName provides a Warnable with the name of the Magicsock function that caused the unhealthy state.
	ArgMagicsockFunctionName Arg = "magicsock-function-name"

	// ArgDERPRegionID provides a Warnable with the ID of a DERP server involved in the unhealthy state.
	ArgDERPRegionID Arg = "derp-region-id"

	// ArgDERPRegionName provides a Warnable with the name of a DERP server involved in the unhealthy state.
	// It is used to show a more friendly message like "the Seattle relay server failed to connect" versus
	// "relay server 10 failed to connect".
	ArgDERPRegionName Arg = "derp-region-name"

	// ArgServerName provides a Warnable with the hostname of a server involved in the unhealthy state.
	ArgServerName Arg = "server-name"

	// ArgServerName provides a Warnable with comma delimited list of the hostname of the servers involved in the unhealthy state.
	// If no nameservers were available to query, this will be an empty string.
	ArgDNSServers Arg = "dns-servers"

	// ArgDomains provides a Warnable with a comma-delimited list of domain
	// names involved in the unhealthy state.
	ArgDomains Arg = "domains"

	// ArgURL provides a Warnable with a URL the user should open to resolve the
	// unhealthy state, such as the login page of a captive portal.
	ArgURL Arg = "url"

	// ArgExitNodeBlocksPortal is set on a captive portal Warnable when an exit
	// node is routing LAN traffic over the tunnel, so the login page named by
	// ArgURL cannot be reached until LAN access is allowed. It exists so that
	// GUIs can offer to allow it without parsing the rendered message.
	ArgExitNodeBlocksPortal Arg = "exit-node-blocks-portal"

	// ArgExitNodeSuspect is set on a captive portal Warnable when the exit node
	// in use is what stands between the user and the login page named by
	// ArgURL: the page is out on the Internet, so it sits behind the default
	// route that the exit node holds.
	//
	// It is the signal for badging the exit node in a GUI as the thing to look
	// at, and is set whether or not we are able to do anything about it
	// ourselves. ArgExitNodeSuspended says which of those two it is.
	ArgExitNodeSuspect Arg = "exit-node-suspect"

	// ArgExitNodeSuspended is set on a captive portal Warnable when the client
	// has temporarily taken the exit node out of the network configuration so
	// that the login page can be reached, which it does only if the user opted
	// in. The exit node comes back on its own, so a GUI should present this as
	// a state the node is passing through rather than a setting that changed.
	ArgExitNodeSuspended Arg = "exit-node-suspended"
)
