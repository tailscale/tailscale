// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package appctype

import "go4.org/netipx"

const AppConnectorsExperimentalAttrName = "tailscale.com/app-connectors-experimental"

type Conn25Attr struct {
	// Name is the name of this collection of domains.
	Name string `json:"name,omitempty"`
	// Domains enumerates the domains serviced by the specified app connectors.
	// Domains can be of the form: example.com, or *.example.com.
	Domains []string `json:"domains,omitempty"`
	// Connectors enumerates the app connectors which service these domains.
	// These can either be "*" to match any advertising connector, or a
	// tag of the form tag:<tag-name>.
	Connectors    []string         `json:"connectors,omitempty"`
	MagicIPPool   []netipx.IPRange `json:"magicIPPool,omitempty"`
	TransitIPPool []netipx.IPRange `json:"transitIPPool,omitempty"`
}
