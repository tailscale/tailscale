// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"errors"
	"fmt"
	"log"
	"strings"
	"sync"
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
	var (
		mu              sync.Mutex
		present         = map[key.Public]bool{}
		loggedConnected = false
	)
	clear := func() {
		mu.Lock()
		defer mu.Unlock()
		if len(present) == 0 {
			return
		}
		logf("reconnected; clearing %d forwarding mappings", len(present))
		for k := range present {
			s.RemovePacketForwarder(k, c)
		}
		present = map[key.Public]bool{}
	}
	lastConnGen := 0
	lastStatus := time.Now()
	logConnectedLocked := func() {
		if loggedConnected {
			return
		}
		logf("connected; %d peers", len(present))
		loggedConnected = true
	}

	const logConnectedDelay = 200 * time.Millisecond
	timer := time.AfterFunc(2*time.Second, func() {
		mu.Lock()
		defer mu.Unlock()
		logConnectedLocked()
	})
	defer timer.Stop()

	updatePeer := func(k key.Public, isPresent bool) {
		if isPresent {
			s.AddPacketForwarder(k, c)
		} else {
			s.RemovePacketForwarder(k, c)
		}

		mu.Lock()
		defer mu.Unlock()
		if isPresent {
			present[k] = true
			if !loggedConnected {
				timer.Reset(logConnectedDelay)
			}
		} else {
			// If we got a peerGone message, that means the initial connection's
			// flood of peerPresent messages is done, so we can log already:
			logConnectedLocked()
			delete(present, k)
		}
	}

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
			m, connGen, err := c.RecvDetail()
			if err != nil {
				clear()
				logf("Recv: %v", err)
				time.Sleep(retryInterval)
				break
			}
			if connGen != lastConnGen {
				lastConnGen = connGen
				clear()
			}
			switch m := m.(type) {
			case derp.PeerPresentMessage:
				updatePeer(key.Public(m), true)
			case derp.PeerGoneMessage:
				updatePeer(key.Public(m), false)
			default:
				continue
			}
			if now := time.Now(); now.Sub(lastStatus) > statusInterval {
				lastStatus = now
				logf("%d peers", len(present))
			}
		}
	}
}
