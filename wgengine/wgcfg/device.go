// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package wgcfg

import (
	"io"
	"sort"

	"github.com/tailscale/wireguard-go/device"
	"tailscale.com/types/logger"
)

func DeviceConfig(d *device.Device) (*Config, error) {
	r, w := io.Pipe()
	errc := make(chan error, 1)
	go func() {
		errc <- d.IpcGetOperation(w)
		w.Close()
	}()
	cfg, err := FromUAPI(r)
	if err != nil {
		return nil, err
	}
	if err := <-errc; err != nil {
		return nil, err
	}

	sort.Slice(cfg.Peers, func(i, j int) bool {
		return cfg.Peers[i].PublicKey.LessThan(&cfg.Peers[j].PublicKey)
	})
	return cfg, nil
}

// ReconfigDevice replaces the existing device configuration with cfg.
func ReconfigDevice(d *device.Device, cfg *Config, logf logger.Logf) (err error) {
	defer func() {
		if err != nil {
			logf("wgcfg.Reconfig failed: %v", err)
		}
	}()

	prev, err := DeviceConfig(d)
	if err != nil {
		return err
	}

	r, w := io.Pipe()
	errc := make(chan error, 1)
	go func() {
		errc <- d.IpcSetOperation(r)
		w.Close()
	}()

	err = cfg.ToUAPI(w, prev)
	if err != nil {
		return err
	}
	w.Close()
	return <-errc
}
