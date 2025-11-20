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

	"tailscale.com/derp"
	"tailscale.com/derp/derphttp"
	"tailscale.com/derp/derpserver"
	"tailscale.com/net/netmon"
	"tailscale.com/types/logger"
)

func startMesh(s *derpserver.Server) error {
	if *meshWith == "" {
		return nil
	}
	if !s.HasMeshKey() {
		return errors.New("--mesh-with requires --mesh-psk-file")
	}
	for _, hostTuple := range strings.Split(*meshWith, ",") {
		if err := startMeshWithHost(s, hostTuple); err != nil {
			return err
		}
	}
	return nil
}

func startMeshWithHost(s *derpserver.Server, hostTuple string) error {
	var host string
	var dialHost string
	hostParts := strings.Split(hostTuple, "/")
	if len(hostParts) > 2 {
		return fmt.Errorf("too many components in host tuple %q", hostTuple)
	}
	host = hostParts[0]
	if len(hostParts) == 2 {
		dialHost = hostParts[1]
	} else {
		dialHost = hostParts[0]
	}

	logf := logger.WithPrefix(log.Printf, fmt.Sprintf("mesh(%q): ", host))
	netMon := netmon.NewStatic() // good enough for cmd/derper; no need for netns fanciness
	c, err := derphttp.NewClient(s.PrivateKey(), "https://"+host+"/derp", logf, netMon)
	if err != nil {
		return err
	}
	c.MeshKey = s.MeshKey()
	c.WatchConnectionChanges = true

	logf("will dial %q for %q", dialHost, host)
	if dialHost != host {
		var d net.Dialer
		c.SetURLDialer(func(ctx context.Context, network, addr string) (net.Conn, error) {
			_, port, err := net.SplitHostPort(addr)
			if err != nil {
				logf("failed to split %q: %v", addr, err)
				return nil, err
			}
			dialAddr := net.JoinHostPort(dialHost, port)
			logf("dialing %q instead of %q", dialAddr, addr)
			return d.DialContext(ctx, network, dialAddr)
		})
	}

	add := func(m derp.PeerPresentMessage) { s.AddPacketForwarder(m.Key, c) }
	remove := func(m derp.PeerGoneMessage) { s.RemovePacketForwarder(m.Peer, c) }
	notifyError := func(err error) {}
	go c.RunWatchConnectionLoop(context.Background(), s.PublicKey(), logf, add, remove, notifyError)
	return nil
}
