// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package nmcfg converts a controlclient.NetMap into a wgcfg config.
package nmcfg

import (
	"bytes"
	"fmt"
	"net/netip"
	"strings"

	"golang.org/x/exp/slices"
	"tailscale.com/logtail"
	"tailscale.com/net/tsaddr"
	"tailscale.com/tailcfg"
	"tailscale.com/types/logger"
	"tailscale.com/types/netmap"
	"tailscale.com/wgengine/wgcfg"
)

func nodeDebugName(n *tailcfg.Node) string {
	name := n.Name
	if name == "" {
		name = n.Hostinfo.Hostname()
	}
	if i := strings.Index(name, "."); i != -1 {
		name = name[:i]
	}
	if name == "" && len(n.Addresses) != 0 {
		return n.Addresses[0].String()
	}
	return name
}

// cidrIsSubnet reports whether cidr is a non-default-route subnet
// exported by node that is not one of its own self addresses.
func cidrIsSubnet(node *tailcfg.Node, cidr netip.Prefix) bool {
	if cidr.Bits() == 0 {
		return false
	}
	if !cidr.IsSingleIP() {
		return true
	}
	for _, selfCIDR := range node.Addresses {
		if cidr == selfCIDR {
			return false
		}
	}
	return true
}

// WGCfg returns the NetworkMaps's WireGuard configuration.
func WGCfg(nm *netmap.NetworkMap, logf logger.Logf, flags netmap.WGConfigFlags, exitNode tailcfg.StableNodeID) (*wgcfg.Config, error) {
	cfg := &wgcfg.Config{
		Name:       "tailscale",
		PrivateKey: nm.PrivateKey,
		Addresses:  nm.Addresses,
		Peers:      make([]wgcfg.Peer, 0, len(nm.Peers)),
	}

	// Setup log IDs for data plane audit logging.
	if nm.SelfNode != nil {
		canNetworkLog := slices.Contains(nm.SelfNode.Capabilities, tailcfg.CapabilityDataPlaneAuditLogs)
		if canNetworkLog && nm.SelfNode.DataPlaneAuditLogID != "" && nm.DomainAuditLogID != "" {
			nodeID, errNode := logtail.ParsePrivateID(nm.SelfNode.DataPlaneAuditLogID)
			if errNode != nil {
				logf("[v1] wgcfg: unable to parse node audit log ID: %v", errNode)
			}
			domainID, errDomain := logtail.ParsePrivateID(nm.DomainAuditLogID)
			if errDomain != nil {
				logf("[v1] wgcfg: unable to parse domain audit log ID: %v", errDomain)
			}
			if errNode == nil && errDomain == nil {
				cfg.NetworkLogging.NodeID = nodeID
				cfg.NetworkLogging.DomainID = domainID
			}
		}
	}

	// Logging buffers
	skippedUnselected := new(bytes.Buffer)
	skippedIPs := new(bytes.Buffer)
	skippedSubnets := new(bytes.Buffer)

	for _, peer := range nm.Peers {
		if peer.DiscoKey.IsZero() && peer.DERP == "" {
			// Peer predates both DERP and active discovery, we cannot
			// communicate with it.
			logf("[v1] wgcfg: skipped peer %s, doesn't offer DERP or disco", peer.Key.ShortString())
			continue
		}
		cfg.Peers = append(cfg.Peers, wgcfg.Peer{
			PublicKey: peer.Key,
			DiscoKey:  peer.DiscoKey,
		})
		cpeer := &cfg.Peers[len(cfg.Peers)-1]
		if peer.KeepAlive {
			cpeer.PersistentKeepalive = 25 // seconds
		}

		didExitNodeWarn := false
		for _, allowedIP := range peer.AllowedIPs {
			if allowedIP.Bits() == 0 && peer.StableID != exitNode {
				if didExitNodeWarn {
					// Don't log about both the IPv4 /0 and IPv6 /0.
					continue
				}
				didExitNodeWarn = true
				if skippedUnselected.Len() > 0 {
					skippedUnselected.WriteString(", ")
				}
				fmt.Fprintf(skippedUnselected, "%q (%v)", nodeDebugName(peer), peer.Key.ShortString())
				continue
			} else if allowedIP.IsSingleIP() && tsaddr.IsTailscaleIP(allowedIP.Addr()) && (flags&netmap.AllowSingleHosts) == 0 {
				if skippedIPs.Len() > 0 {
					skippedIPs.WriteString(", ")
				}
				fmt.Fprintf(skippedIPs, "%v from %q (%v)", allowedIP.Addr(), nodeDebugName(peer), peer.Key.ShortString())
				continue
			} else if cidrIsSubnet(peer, allowedIP) {
				if (flags & netmap.AllowSubnetRoutes) == 0 {
					if skippedSubnets.Len() > 0 {
						skippedSubnets.WriteString(", ")
					}
					fmt.Fprintf(skippedSubnets, "%v from %q (%v)", allowedIP, nodeDebugName(peer), peer.Key.ShortString())
					continue
				}
			}
			cpeer.AllowedIPs = append(cpeer.AllowedIPs, allowedIP)
		}
	}

	if skippedUnselected.Len() > 0 {
		logf("[v1] wgcfg: skipped unselected default routes from: %s", skippedUnselected.Bytes())
	}
	if skippedIPs.Len() > 0 {
		logf("[v1] wgcfg: skipped node IPs: %s", skippedIPs)
	}
	if skippedSubnets.Len() > 0 {
		logf("[v1] wgcfg: did not accept subnet routes: %s", skippedSubnets)
	}

	return cfg, nil
}
