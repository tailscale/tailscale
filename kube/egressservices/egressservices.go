// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package egressservices contains shared types for exposing tailnet services to
// cluster workloads.
// These are split into a separate package for consumption of
// non-Kubernetes shared libraries and binaries. Be mindful of not increasing
// dependency size for those consumers when adding anything new here.
package egressservices

import (
	"encoding"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
)

// KeyEgressServices is name of the proxy state Secret field that contains the
// currently applied egress proxy config.
const KeyEgressServices = "egress-services"

// Configs contains the desired configuration for egress services keyed by
// service name.
type Configs map[string]Config

// Config is an egress service configuration.
// TODO(irbekrm): version this?
type Config struct {
	// TailnetTarget is the target to which cluster traffic for this service
	// should be proxied.
	TailnetTarget TailnetTarget `json:"tailnetTarget"`
	// Ports contains mappings for ports that can be accessed on the tailnet target.
	Ports map[PortMap]struct{} `json:"ports"`
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

// PortMap is used as a Config.Ports map key. Config needs to be serialized/deserialized to/from JSON. JSON only
// supports string map keys, so we need to implement TextMarshaler/TextUnmarshaler to convert PortMap to string and
// back.
var _ encoding.TextMarshaler = PortMap{}
var _ encoding.TextUnmarshaler = &PortMap{}

func (pm *PortMap) UnmarshalText(t []byte) error {
	tt := string(t)
	ss := strings.Split(tt, ":")
	if len(ss) != 3 {
		return fmt.Errorf("error unmarshalling portmap from JSON, wants a portmap in form <protocol>:<matchPort>:<targetPor>, got %q", tt)
	}
	(*pm).Protocol = ss[0]
	matchPort, err := strconv.ParseUint(ss[1], 10, 16)
	if err != nil {
		return fmt.Errorf("error converting match port %q to uint16: %w", ss[1], err)
	}
	(*pm).MatchPort = uint16(matchPort)
	targetPort, err := strconv.ParseUint(ss[2], 10, 16)
	if err != nil {
		return fmt.Errorf("error converting target port %q to uint16: %w", ss[2], err)
	}
	(*pm).TargetPort = uint16(targetPort)
	return nil
}

func (pm PortMap) MarshalText() ([]byte, error) {
	s := fmt.Sprintf("%s:%d:%d", pm.Protocol, pm.MatchPort, pm.TargetPort)
	return []byte(s), nil
}

// Status represents the currently configured firewall rules for all egress
// services for a proxy identified by the PodIP.
type Status struct {
	PodIP string `json:"podIP"`
	// All egress service status keyed by service name.
	Services map[string]*ServiceStatus `json:"services"`
}

// ServiceStatus is the currently configured firewall rules for an egress
// service.
type ServiceStatus struct {
	Ports map[PortMap]struct{} `json:"ports"`
	// TailnetTargetIPs are the tailnet target IPs that were used to
	// configure these firewall rules. For a TailnetTarget with IP set, this
	// is the same as IP.
	TailnetTargetIPs []netip.Addr  `json:"tailnetTargetIPs"`
	TailnetTarget    TailnetTarget `json:"tailnetTarget"`
}
