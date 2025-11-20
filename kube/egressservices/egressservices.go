// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package egressservices contains shared types for exposing tailnet services to
// cluster workloads.
// These are split into a separate package for consumption of
// non-Kubernetes shared libraries and binaries. Be mindful of not increasing
// dependency size for those consumers when adding anything new here.
package egressservices

import (
	"encoding/json"
	"net/netip"
)

const (
	// KeyEgressServices is name of the proxy state Secret field that contains the
	// currently applied egress proxy config.
	KeyEgressServices = "egress-services"

	// KeyHEPPings is the number of times an egress service health check endpoint needs to be pinged to ensure that
	// each currently configured backend is hit. In practice, it depends on the number of ProxyGroup replicas.
	KeyHEPPings = "hep-pings"
)

// Configs contains the desired configuration for egress services keyed by
// service name.
type Configs map[string]Config

// Config is an egress service configuration.
// TODO(irbekrm): version this?
type Config struct {
	HealthCheckEndpoint string `json:"healthCheckEndpoint"`
	// TailnetTarget is the target to which cluster traffic for this service
	// should be proxied.
	TailnetTarget TailnetTarget `json:"tailnetTarget"`
	// Ports contains mappings for ports that can be accessed on the tailnet target.
	Ports PortMaps `json:"ports"`
}

// TailnetTarget is the tailnet target to which traffic for the egress service
// should be proxied. Exactly one of IP or FQDN should be set.
type TailnetTarget struct {
	// IP is the tailnet IP of the target.
	IP string `json:"ip"`
	// FQDN is the full tailnet FQDN of the target.
	FQDN string `json:"fqdn"`
}

// PorMap is a mapping between match port on which proxy receives cluster
// traffic and target port where traffic received on match port should be
// fowardded to.
type PortMap struct {
	Protocol   string `json:"protocol"`
	MatchPort  uint16 `json:"matchPort"`
	TargetPort uint16 `json:"targetPort"`
}

type PortMaps map[PortMap]struct{}

// PortMaps is a list of PortMap structs, however, we want to use it as a set
// with efficient lookups in code. It implements custom JSON marshalling
// methods to convert between being a list in JSON and a set (map with empty
// values) in code.
var _ json.Marshaler = &PortMaps{}
var _ json.Marshaler = PortMaps{}
var _ json.Unmarshaler = &PortMaps{}

func (p *PortMaps) UnmarshalJSON(data []byte) error {
	*p = make(map[PortMap]struct{})

	var v []PortMap
	if err := json.Unmarshal(data, &v); err != nil {
		return err
	}

	for _, pm := range v {
		(*p)[pm] = struct{}{}
	}

	return nil
}

func (p PortMaps) MarshalJSON() ([]byte, error) {
	v := make([]PortMap, 0, len(p))
	for pm := range p {
		v = append(v, pm)
	}

	return json.Marshal(v)
}

// Status represents the currently configured firewall rules for all egress
// services for a proxy identified by the PodIP.
type Status struct {
	PodIPv4 string `json:"podIPv4"`
	// All egress service status keyed by service name.
	Services map[string]*ServiceStatus `json:"services"`
}

// ServiceStatus is the currently configured firewall rules for an egress
// service.
type ServiceStatus struct {
	Ports PortMaps `json:"ports"`
	// TailnetTargetIPs are the tailnet target IPs that were used to
	// configure these firewall rules. For a TailnetTarget with IP set, this
	// is the same as IP.
	TailnetTargetIPs []netip.Addr  `json:"tailnetTargetIPs"`
	TailnetTarget    TailnetTarget `json:"tailnetTarget"`
}
