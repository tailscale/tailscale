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

	// ArgExitNodeName provides a Warnable with a human-readable identifier for
	// the selected exit node: its display name if it is (or recently was) a
	// known peer, otherwise its stable node ID or IP address. It is empty if
	// no particular exit node has been selected.
	ArgExitNodeName Arg = "exit-node-name"

	// ArgExitNodeReason provides a Warnable with the reason the selected exit
	// node cannot carry internet traffic: "not-in-tailnet", "no-exit-routes",
	// or "not-yet-selected". It lets GUIs distinguish the cases without
	// parsing the rendered message.
	ArgExitNodeReason Arg = "exit-node-reason"

	// ArgExitNodePolicyForced is "true" when the selected exit node is
	// mandated by the ExitNodeID or ExitNodeIP policy settings, meaning the
	// user cannot resolve the problem themselves and should contact their
	// network administrator.
	ArgExitNodePolicyForced Arg = "exit-node-policy-forced"
)
