// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package wgcfg

import (
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"

	"inet.af/netaddr"
)

// ToUAPI writes cfg in UAPI format to w.
// Prev is the previous device Config.
// Prev is required so that we can remove now-defunct peers
// without having to remove and re-add all peers.
func (cfg *Config) ToUAPI(w io.Writer, prev *Config) error {
	var stickyErr error
	set := func(key, value string) {
		if stickyErr != nil {
			return
		}
		_, err := fmt.Fprintf(w, "%s=%s\n", key, value)
		if err != nil {
			stickyErr = err
		}
	}
	setUint16 := func(key string, value uint16) {
		set(key, strconv.FormatUint(uint64(value), 10))
	}
	setPeer := func(peer Peer) {
		set("public_key", peer.PublicKey.HexString())
	}

	// Device config.
	if prev.PrivateKey != cfg.PrivateKey {
		set("private_key", cfg.PrivateKey.HexString())
	}
	if prev.ListenPort != cfg.ListenPort {
		setUint16("listen_port", cfg.ListenPort)
	}

	old := make(map[Key]Peer)
	for _, p := range prev.Peers {
		old[p.PublicKey] = p
	}

	// Add/configure all new peers.
	for _, p := range cfg.Peers {
		oldPeer := old[p.PublicKey]
		setPeer(p)
		set("protocol_version", "1")

		if !endpointsEqual(oldPeer.Endpoints, p.Endpoints) {
			set("endpoint", p.Endpoints)
		}

		// TODO: replace_allowed_ips is expensive.
		// If p.AllowedIPs is a strict superset of oldPeer.AllowedIPs,
		// then skip replace_allowed_ips and instead add only
		// the new ipps with allowed_ip.
		if !cidrsEqual(oldPeer.AllowedIPs, p.AllowedIPs) {
			set("replace_allowed_ips", "true")
			for _, ipp := range p.AllowedIPs {
				set("allowed_ip", ipp.String())
			}
		}

		// Set PersistentKeepalive after the peer is otherwise configured,
		// because it can trigger handshake packets.
		if oldPeer.PersistentKeepalive != p.PersistentKeepalive {
			setUint16("persistent_keepalive_interval", p.PersistentKeepalive)
		}
	}

	// Remove peers that were present but should no longer be.
	for _, p := range cfg.Peers {
		delete(old, p.PublicKey)
	}
	for _, p := range old {
		setPeer(p)
		set("remove", "true")
	}

	if stickyErr != nil {
		stickyErr = fmt.Errorf("ToUAPI: %w", stickyErr)
	}
	return stickyErr
}

func endpointsEqual(x, y string) bool {
	// Cheap comparisons.
	if x == y {
		return true
	}
	xs := strings.Split(x, ",")
	ys := strings.Split(y, ",")
	if len(xs) != len(ys) {
		return false
	}
	// Otherwise, see if they're the same, but out of order.
	sort.Strings(xs)
	sort.Strings(ys)
	x = strings.Join(xs, ",")
	y = strings.Join(ys, ",")
	return x == y
}

func cidrsEqual(x, y []netaddr.IPPrefix) bool {
	// TODO: re-implement using netaddr.IPSet.Equal.
	if len(x) != len(y) {
		return false
	}
	// First see if they're equal in order, without allocating.
	exact := true
	for i := range x {
		if x[i] != y[i] {
			exact = false
			break
		}
	}
	if exact {
		return true
	}

	// Otherwise, see if they're the same, but out of order.
	m := make(map[netaddr.IPPrefix]bool)
	for _, v := range x {
		m[v] = true
	}
	for _, v := range y {
		if !m[v] {
			return false
		}
	}
	return true
}
