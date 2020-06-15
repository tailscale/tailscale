// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"errors"
	"fmt"
	"log"
	"strings"

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
	add := func(k key.Public) { s.AddPacketForwarder(k, c) }
	remove := func(k key.Public) { s.AddPacketForwarder(k, c) }
	go c.RunWatchConnectionLoop(s.PublicKey(), add, remove)
	return nil
}
