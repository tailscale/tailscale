// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package nmcfg converts a controlclient.NetMap into a wgcfg config.
package nmcfg

import (
	"fmt"
	"net"
	"strconv"
	"strings"

	"inet.af/netaddr"
	"tailscale.com/control/controlclient"
	"tailscale.com/net/tsaddr"
	"tailscale.com/tailcfg"
	"tailscale.com/types/logger"
	"tailscale.com/wgengine/wgcfg"
)

func nodeDebugName(n *tailcfg.Node) string {
	name := n.Name
	if name == "" {
		name = n.Hostinfo.Hostname
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
func cidrIsSubnet(node *tailcfg.Node, cidr netaddr.IPPrefix) bool {
	if cidr.Bits == 0 {
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

// WGCfg returns the NetworkMaps's Wireguard configuration.
func WGCfg(nm *controlclient.NetworkMap, logf logger.Logf, flags controlclient.WGConfigFlags) (*wgcfg.Config, error) {
	cfg := &wgcfg.Config{
		Name:       "tailscale",
		PrivateKey: wgcfg.PrivateKey(nm.PrivateKey),
		Addresses:  nm.Addresses,
		ListenPort: nm.LocalPort,
		Peers:      make([]wgcfg.Peer, 0, len(nm.Peers)),
	}

	for _, peer := range nm.Peers {
		if controlclient.Debug.OnlyDisco && peer.DiscoKey.IsZero() {
			continue
		}
		cfg.Peers = append(cfg.Peers, wgcfg.Peer{
			PublicKey: wgcfg.Key(peer.Key),
		})
		cpeer := &cfg.Peers[len(cfg.Peers)-1]
		if peer.KeepAlive {
			cpeer.PersistentKeepalive = 25 // seconds
		}

		if !peer.DiscoKey.IsZero() {
			if err := appendEndpoint(cpeer, fmt.Sprintf("%x%s", peer.DiscoKey[:], wgcfg.EndpointDiscoSuffix)); err != nil {
				return nil, err
			}
			cpeer.Endpoints = fmt.Sprintf("%x.disco.tailscale:12345", peer.DiscoKey[:])
		} else {
			if err := appendEndpoint(cpeer, peer.DERP); err != nil {
				return nil, err
			}
			for _, ep := range peer.Endpoints {
				if err := appendEndpoint(cpeer, ep); err != nil {
					return nil, err
				}
			}
		}
		for _, allowedIP := range peer.AllowedIPs {
			if allowedIP.IsSingleIP() && tsaddr.IsTailscaleIP(allowedIP.IP) && (flags&controlclient.AllowSingleHosts) == 0 {
				logf("[v1] wgcfg: skipping node IP %v from %q (%v)",
					allowedIP.IP, nodeDebugName(peer), peer.Key.ShortString())
				continue
			} else if cidrIsSubnet(peer, allowedIP) {
				if (flags & controlclient.AllowSubnetRoutes) == 0 {
					logf("[v1] wgcfg: not accepting subnet route %v from %q (%v)",
						allowedIP, nodeDebugName(peer), peer.Key.ShortString())
					continue
				}
			}
			cpeer.AllowedIPs = append(cpeer.AllowedIPs, allowedIP)
		}
	}

	return cfg, nil
}

func appendEndpoint(peer *wgcfg.Peer, epStr string) error {
	if epStr == "" {
		return nil
	}
	_, port, err := net.SplitHostPort(epStr)
	if err != nil {
		return fmt.Errorf("malformed endpoint %q for peer %v", epStr, peer.PublicKey.ShortString())
	}
	_, err = strconv.ParseUint(port, 10, 16)
	if err != nil {
		return fmt.Errorf("invalid port in endpoint %q for peer %v", epStr, peer.PublicKey.ShortString())
	}
	if peer.Endpoints != "" {
		peer.Endpoints += ","
	}
	peer.Endpoints += epStr
	return nil
}
