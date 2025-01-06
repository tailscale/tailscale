// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"strings"
	"time"

	"tailscale.com/derp"
	"tailscale.com/derp/derphttp"
	"tailscale.com/net/netmon"
	"tailscale.com/types/logger"
)

func startMesh(s *derp.Server) error {
	if *meshWith == "" {
		return nil
	}
	if !s.HasMeshKey() {
		return errors.New("--mesh-with requires --mesh-psk-file")
	}
	for _, host := range strings.Split(*meshWith, ",") {
		if err := startMeshWithHost(s, host); err != nil {
			return err
		}
	}
	return nil
}

func startMeshWithHost(s *derp.Server, host string) error {
	logf := logger.WithPrefix(log.Printf, fmt.Sprintf("mesh(%q): ", host))
	netMon := netmon.NewStatic() // good enough for cmd/derper; no need for netns fanciness
	c, err := derphttp.NewClient(s.PrivateKey(), "https://"+host+"/derp", logf, netMon)
	if err != nil {
		return err
	}
	c.MeshKey = s.MeshKey()
	c.WatchConnectionChanges = true

	// For meshed peers within a region, connect via VPC addresses.
	c.SetURLDialer(func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			logf("failed to split %q: %v", addr, err)
			return nil, err
		}
		var d net.Dialer
		var r net.Resolver
		if base, ok := strings.CutSuffix(host, ".tailscale.com"); ok && port == "443" {
			subCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
			defer cancel()
			vpcHost := base + "-vpc.tailscale.com"
			ips, err := r.LookupIP(subCtx, "ip", vpcHost)
			if err != nil {
				logf("failed to resolve %v: %v", vpcHost, err)
			}
			if len(ips) > 0 {
				vpcAddr := net.JoinHostPort(ips[0].String(), port)
				c, err := d.DialContext(subCtx, network, vpcAddr)
				if err == nil {
					logf("connected to %v (%v) instead of %v", vpcHost, ips[0], base)
					return c, nil
				}
				logf("failed to connect to %v (%v): %v; trying non-VPC route", vpcHost, ips[0], err)
			}
		}
		return d.DialContext(ctx, network, addr)
	})

	add := func(m derp.PeerPresentMessage) { s.AddPacketForwarder(m.Key, c) }
	remove := func(m derp.PeerGoneMessage) { s.RemovePacketForwarder(m.Peer, c) }
	go c.RunWatchConnectionLoop(context.Background(), s.PublicKey(), logf, add, remove)
	return nil
}
