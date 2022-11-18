// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

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
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
	"tailscale.com/util/strs"
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
	c, err := derphttp.NewClient(s.PrivateKey(), "https://"+host+"/derp", logf)
	if err != nil {
		return err
	}
	c.MeshKey = s.MeshKey()

	// For meshed peers within a region, connect via VPC addresses.
	c.SetURLDialer(func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}
		var d net.Dialer
		var r net.Resolver
		if base, ok := strs.CutSuffix(host, ".tailscale.com"); ok && port == "443" {
			subCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
			defer cancel()
			vpcHost := base + "-vpc.tailscale.com"
			ips, _ := r.LookupIP(subCtx, "ip", vpcHost)
			if len(ips) > 0 {
				vpcAddr := net.JoinHostPort(ips[0].String(), port)
				c, err := d.DialContext(subCtx, network, vpcAddr)
				if err == nil {
					log.Printf("connected to %v (%v) instead of %v", vpcHost, ips[0], base)
					return c, nil
				}
				log.Printf("failed to connect to %v (%v): %v; trying non-VPC route", vpcHost, ips[0], err)
			}
		}
		return d.DialContext(ctx, network, addr)
	})

	add := func(k key.NodePublic) { s.AddPacketForwarder(k, c) }
	remove := func(k key.NodePublic) { s.RemovePacketForwarder(k, c) }
	go c.RunWatchConnectionLoop(context.Background(), s.PublicKey(), logf, add, remove)
	return nil
}
