// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tailcfg

import "sort"

// DERPMap describes the set of DERP packet relay servers that are available.
type DERPMap struct {
	// Regions is the set of geographic regions running DERP node(s).
	//
	// It's keyed by the DERPRegion.RegionID.
	//
	// The numbers are not necessarily contiguous.
	Regions map[int]*DERPRegion

	// OmitDefaultRegions specifies to not use Tailscale's DERP servers, and only use those
	// specified in this DERPMap. If there are none set outside of the defaults, this is a noop.
	OmitDefaultRegions bool `json:"omitDefaultRegions,omitempty"`
}

// / RegionIDs returns the sorted region IDs.
func (m *DERPMap) RegionIDs() []int {
	ret := make([]int, 0, len(m.Regions))
	for rid := range m.Regions {
		ret = append(ret, rid)
	}
	sort.Ints(ret)
	return ret
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
	//
	// RegionIDs in range 900-999 are reserved for end users to run their
	// own DERP nodes.
	RegionID int

	// RegionCode is a short name for the region. It's usually a popular
	// city or airport code in the region: "nyc", "sf", "sin",
	// "fra", etc.
	RegionCode string

	// RegionName is a long English name for the region: "New York City",
	// "San Francisco", "Singapore", "Frankfurt", etc.
	RegionName string

	// Avoid is whether the client should avoid picking this as its home
	// region. The region should only be used if a peer is there.
	// Clients already using this region as their home should migrate
	// away to a new region without Avoid set.
	Avoid bool `json:",omitempty"`

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

	// IPv4 optionally forces an IPv4 address to use, instead of using DNS.
	// If empty, A record(s) from DNS lookups of HostName are used.
	// If the string is not an IPv4 address, IPv4 is not used; the
	// conventional string to disable IPv4 (and not use DNS) is
	// "none".
	IPv4 string `json:",omitempty"`

	// IPv6 optionally forces an IPv6 address to use, instead of using DNS.
	// If empty, AAAA record(s) from DNS lookups of HostName are used.
	// If the string is not an IPv6 address, IPv6 is not used; the
	// conventional string to disable IPv6 (and not use DNS) is
	// "none".
	IPv6 string `json:",omitempty"`

	// Port optionally specifies a STUN port to use.
	// Zero means 3478.
	// To disable STUN on this node, use -1.
	STUNPort int `json:",omitempty"`

	// STUNOnly marks a node as only a STUN server and not a DERP
	// server.
	STUNOnly bool `json:",omitempty"`

	// DERPPort optionally provides an alternate TLS port number
	// for the DERP HTTPS server.
	//
	// If zero, 443 is used.
	DERPPort int `json:",omitempty"`

	// InsecureForTests is used by unit tests to disable TLS verification.
	// It should not be set by users.
	InsecureForTests bool `json:",omitempty"`

	// STUNTestIP is used in tests to override the STUN server's IP.
	// If empty, it's assumed to be the same as the DERP server.
	STUNTestIP string `json:",omitempty"`
}
