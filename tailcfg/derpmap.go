// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tailcfg

// DERPMap describes the set of DERP packet relay servers that are available.
type DERPMap struct {
	// Regions is the set of geographic regions running DERP node(s).
	//
	// It's keyed by the DERPRegion.RegionID.
	//
	// The numbers are not necessarily contiguous.
	Regions map[int]*DERPRegion
}

// DERPRegion is a geographic region running DERP relay node(s).
//
// Client nodes discover which region they're closest to, advertise
// that "home" DERP region (previously called "home node", when there
// was only 1 node per region) and maintain a persistent connection
// that region as long as it's the closest. Client nodes will further
// connect to other regions as necessary to communicate with peers
// advertising other regions as their homes.
type DERPRegion struct {
	// RegionID is a unique integer for a geographic region.
	//
	// It corresponds to the legacy derpN.tailscale.com hostnames
	// used by older clients. (Older clients will continue to resolve
	// derpN.tailscale.com when contacting peers, rather than use
	// the server-provided DERPMap)
	//
	// RegionIDs must be non-zero, positive, and guaranteed to fit
	// in a JavaScript number.
	RegionID int

	// RegionCode is a short name for the region. It's usually a popular
	// city or airport code in the region: "nyc", "sf", "sin",
	// "fra", etc.
	RegionCode string

	// Nodes are the DERP nodes running in this region, in
	// priority order for the current client. Client TLS
	// connections should ideally only go to the first entry
	// (falling back to the second if necessary). STUN packets
	// should go to the first 1 or 2.
	//
	// If nodes within a region route packets amongst themselves,
	// but not to other regions. That said, each user/domain
	// should get a the same preferred node order, so if all nodes
	// for a user/network pick the first one (as they should, when
	// things are healthy), the inter-cluster routing is minimal
	// to zero.
	Nodes []*DERPNode
}

// DERPNode describes a DERP packet relay node running within a DERPRegion.
type DERPNode struct {
	// Name is a unique node name (across all regions).
	// It is not a host name.
	// It's typically of the form "1b", "2a", "3b", etc. (region
	// ID + suffix within that region)
	Name string

	// RegionID is the RegionID of the DERPRegion that this node
	// is running in.
	RegionID int

	// HostName is the DERP node's hostname.
	//
	// It is required but need not be unique; multiple nodes may
	// have the same HostName but vary in configuration otherwise.
	HostName string

	// CertName optionally specifies the expected TLS cert common
	// name. If empty, HostName is used. If CertName is non-empty,
	// HostName is only used for the TCP dial (if IPv4/IPv6 are
	// not present) + TLS ClientHello.
	CertName string `json:",omitempty"`

	// CertFingerprint, if non-empty, specifies the expected
	// lowercase hex of the SHA-256 of the TLS server's offered
	// certificate. If empty, the system default RootCAs are used.
	CertFingerprint []string `json:",omitempty"`

	// IPv4 optionally forces an IPv4 address to use, instead of using DNS.
	// If empty, A record(s) from DNS lookups of HostName are used.
	IPv4 string `json:",omitempty"`

	// IPv6 optionally forces an IPv6 address to use, instead of using DNS.
	// If empty, AAAA record(s) from DNS lookups of HostName are used.
	IPv6 string `json:",omitempty"`
}
