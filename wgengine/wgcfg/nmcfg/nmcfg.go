// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package nmcfg converts a controlclient.NetMap into a wgcfg config.
package nmcfg

import (
	"bufio"
	"cmp"
	"fmt"
	"net/netip"
	"strings"

	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
	"tailscale.com/types/logid"
	"tailscale.com/types/netmap"
	"tailscale.com/wgengine/wgcfg"
)

func nodeDebugName(n tailcfg.NodeView) string {
	name, _, _ := strings.Cut(cmp.Or(n.Name(), n.Hostinfo().Hostname()), ".")
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
	for _, selfCIDR := range node.Addresses().All() {
		if cidr == selfCIDR {
			return false
		}
	}
	return true
}

// WGCfg returns the NetworkMaps's WireGuard configuration.
func WGCfg(pk key.NodePrivate, nm *netmap.NetworkMap, logf logger.Logf, flags netmap.WGConfigFlags, exitNode tailcfg.StableNodeID) (*wgcfg.Config, error) {
	cfg := &wgcfg.Config{
		PrivateKey: pk,
		Addresses:  nm.GetAddresses().AsSlice(),
		Peers:      make([]wgcfg.Peer, 0, len(nm.Peers)),
	}

	// Setup log IDs for data plane audit logging.
	if nm.SelfNode.Valid() {
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

	var skippedExitNode, skippedSubnetRouter, skippedExpired []tailcfg.NodeView

	for _, peer := range nm.Peers {
		if peer.DiscoKey().IsZero() && peer.HomeDERP() == 0 && !peer.IsWireGuardOnly() {
			// Peer predates both DERP and active discovery, we cannot
			// communicate with it.
			logf("[v1] wgcfg: skipped peer %s, doesn't offer DERP or disco", peer.Key().ShortString())
			continue
		}
		// Skip expired peers; we'll end up failing to connect to them
		// anyway, since control intentionally breaks node keys for
		// expired peers so that we can't discover endpoints via DERP.
		if peer.Expired() {
			skippedExpired = append(skippedExpired, peer)
			continue
		}

		cfg.Peers = append(cfg.Peers, wgcfg.Peer{
			PublicKey: peer.Key(),
			DiscoKey:  peer.DiscoKey(),
		})
		cpeer := &cfg.Peers[len(cfg.Peers)-1]

		didExitNodeLog := false
		cpeer.V4MasqAddr = peer.SelfNodeV4MasqAddrForThisPeer().Clone()
		cpeer.V6MasqAddr = peer.SelfNodeV6MasqAddrForThisPeer().Clone()
		cpeer.IsJailed = peer.IsJailed()
		for _, allowedIP := range peer.AllowedIPs().All() {
			if allowedIP.Bits() == 0 && peer.StableID() != exitNode {
				if didExitNodeLog {
					// Don't log about both the IPv4 /0 and IPv6 /0.
					continue
				}
				didExitNodeLog = true
				skippedExitNode = append(skippedExitNode, peer)
				continue
			} else if cidrIsSubnet(peer, allowedIP) {
				if (flags & netmap.AllowSubnetRoutes) == 0 {
					skippedSubnetRouter = append(skippedSubnetRouter, peer)
					continue
				}
			}
			cpeer.AllowedIPs = append(cpeer.AllowedIPs, allowedIP)
		}
	}

	logList := func(title string, nodes []tailcfg.NodeView) {
		if len(nodes) == 0 {
			return
		}
		logf("[v1] wgcfg: %s from %d nodes: %s", title, len(nodes), logger.ArgWriter(func(bw *bufio.Writer) {
			const max = 5
			for i, n := range nodes {
				if i == max {
					fmt.Fprintf(bw, "... +%d", len(nodes)-max)
					return
				}
				if i > 0 {
					bw.WriteString(", ")
				}
				fmt.Fprintf(bw, "%s (%s)", nodeDebugName(n), n.StableID())
			}
		}))
	}
	logList("skipped unselected exit nodes", skippedExitNode)
	logList("did not accept subnet routes", skippedSubnetRouter)
	logList("skipped expired peers", skippedExpired)

	return cfg, nil
}
