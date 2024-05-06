// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package nmcfg converts a controlclient.NetMap into a wgcfg config.
package nmcfg

import (
	"bytes"
	"fmt"
	"net/netip"
	"strings"

	"tailscale.com/net/tsaddr"
	"tailscale.com/tailcfg"
	"tailscale.com/types/logger"
	"tailscale.com/types/logid"
	"tailscale.com/types/netmap"
	"tailscale.com/wgengine/wgcfg"
)

func nodeDebugName(n tailcfg.NodeView) string {
	name := n.Name()
	if name == "" {
		name = n.Hostinfo().Hostname()
	}
	if i := strings.Index(name, "."); i != -1 {
		name = name[:i]
	}
	if name == "" && n.Addresses().Len() != 0 {
		return n.Addresses().At(0).String()
	}
	return name
}

// cidrIsSubnet reports whether cidr is a non-default-route subnet
// exported by node that is not one of its own self addresses.
func cidrIsSubnet(node tailcfg.NodeView, cidr netip.Prefix) bool {
	if cidr.Bits() == 0 {
		return false
	}
	if !cidr.IsSingleIP() {
		return true
	}
	for i := range node.Addresses().Len() {
		selfCIDR := node.Addresses().At(i)
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
		Addresses:  nm.GetAddresses().AsSlice(),
		Peers:      make([]wgcfg.Peer, 0, len(nm.Peers)),
	}

	// Setup log IDs for data plane audit logging.
	if nm.SelfNode.Valid() {
		cfg.NodeID = nm.SelfNode.StableID()
		canNetworkLog := nm.SelfNode.HasCap(tailcfg.CapabilityDataPlaneAuditLogs)
		logExitFlowEnabled := nm.SelfNode.HasCap(tailcfg.NodeAttrLogExitFlows)
		if canNetworkLog && nm.SelfNode.DataPlaneAuditLogID() != "" && nm.DomainAuditLogID != "" {
			nodeID, errNode := logid.ParsePrivateID(nm.SelfNode.DataPlaneAuditLogID())
			if errNode != nil {
				logf("[v1] wgcfg: unable to parse node audit log ID: %v", errNode)
			}
			domainID, errDomain := logid.ParsePrivateID(nm.DomainAuditLogID)
			if errDomain != nil {
				logf("[v1] wgcfg: unable to parse domain audit log ID: %v", errDomain)
			}
			if errNode == nil && errDomain == nil {
				cfg.NetworkLogging.NodeID = nodeID
				cfg.NetworkLogging.DomainID = domainID
				cfg.NetworkLogging.LogExitFlowEnabled = logExitFlowEnabled
			}
		}
	}

	// Logging buffers
	skippedUnselected := new(bytes.Buffer)
	skippedIPs := new(bytes.Buffer)
	skippedSubnets := new(bytes.Buffer)

	for _, peer := range nm.Peers {
		if peer.DiscoKey().IsZero() && peer.DERP() == "" && !peer.IsWireGuardOnly() {
			// Peer predates both DERP and active discovery, we cannot
			// communicate with it.
			logf("[v1] wgcfg: skipped peer %s, doesn't offer DERP or disco", peer.Key().ShortString())
			continue
		}
		// Skip expired peers; we'll end up failing to connect to them
		// anyway, since control intentionally breaks node keys for
		// expired peers so that we can't discover endpoints via DERP.
		if peer.Expired() {
			logf("[v1] wgcfg: skipped expired peer %s", peer.Key().ShortString())
			continue
		}

		cfg.Peers = append(cfg.Peers, wgcfg.Peer{
			PublicKey: peer.Key(),
			DiscoKey:  peer.DiscoKey(),
		})
		cpeer := &cfg.Peers[len(cfg.Peers)-1]

		didExitNodeWarn := false
		cpeer.V4MasqAddr = peer.SelfNodeV4MasqAddrForThisPeer()
		cpeer.V6MasqAddr = peer.SelfNodeV6MasqAddrForThisPeer()
		cpeer.IsJailed = peer.IsJailed()
		for i := range peer.AllowedIPs().Len() {
			allowedIP := peer.AllowedIPs().At(i)
			if allowedIP.Bits() == 0 && peer.StableID() != exitNode {
				if didExitNodeWarn {
					// Don't log about both the IPv4 /0 and IPv6 /0.
					continue
				}
				didExitNodeWarn = true
				if skippedUnselected.Len() > 0 {
					skippedUnselected.WriteString(", ")
				}
				fmt.Fprintf(skippedUnselected, "%q (%v)", nodeDebugName(peer), peer.Key().ShortString())
				continue
			} else if allowedIP.IsSingleIP() && tsaddr.IsTailscaleIP(allowedIP.Addr()) && (flags&netmap.AllowSingleHosts) == 0 {
				if skippedIPs.Len() > 0 {
					skippedIPs.WriteString(", ")
				}
				fmt.Fprintf(skippedIPs, "%v from %q (%v)", allowedIP.Addr(), nodeDebugName(peer), peer.Key().ShortString())
				continue
			} else if cidrIsSubnet(peer, allowedIP) {
				if (flags & netmap.AllowSubnetRoutes) == 0 {
					if skippedSubnets.Len() > 0 {
						skippedSubnets.WriteString(", ")
					}
					fmt.Fprintf(skippedSubnets, "%v from %q (%v)", allowedIP, nodeDebugName(peer), peer.Key().ShortString())
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
