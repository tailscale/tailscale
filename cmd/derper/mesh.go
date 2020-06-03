// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"errors"
	"fmt"
	"log"
	"strings"
	"time"

	"tailscale.com/derp"
	"tailscale.com/derp/derphttp"
	"tailscale.com/types/key"
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
	c, err := derphttp.NewClient(s.PrivateKey(), "https://"+host+"/derp", logf)
	if err != nil {
		return err
	}
	c.MeshKey = s.MeshKey()
	go runMeshClient(s, host, c, logf)
	return nil
}

func runMeshClient(s *derp.Server, host string, c *derphttp.Client, logf logger.Logf) {
	const retryInterval = 5 * time.Second
	const statusInterval = 10 * time.Second
	lastGen := 0
	present := map[key.Public]bool{}
	clear := func() {
		if len(present) == 0 {
			return
		}
		logf("reconnected; clearing %d forwarding mappings", len(present))
		for k := range present {
			s.RemovePacketForwarder(k, c)
		}
		present = map[key.Public]bool{}
	}
	lastStatus := time.Now()

	for {
		err := c.WatchConnectionChanges()
		if err != nil {
			clear()
			logf("WatchConnectionChanges: %v", err)
			time.Sleep(retryInterval)
			continue
		}
		if c.ServerPublicKey() == s.PublicKey() {
			logf("detected self-connect; ignoring host")
			return
		}
		for {
			var buf [64 << 10]byte
			m, connGen, err := c.RecvDetail(buf[:])
			if err != nil {
				clear()
				logf("Recv: %v", err)
				time.Sleep(retryInterval)
				break
			}
			if connGen != lastGen {
				lastGen = connGen
				clear()
			}
			switch m := m.(type) {
			case derp.PeerPresentMessage:
				k := key.Public(m)
				present[k] = true
				s.AddPacketForwarder(k, c)
			case derp.PeerGoneMessage:
				k := key.Public(m)
				delete(present, k)
				s.RemovePacketForwarder(k, c)
			default:
				continue
			}
			if now := time.Now(); now.Sub(lastStatus) > statusInterval {
				lastStatus = now
				logf("%d connections", len(present))
			}
		}
	}
}
