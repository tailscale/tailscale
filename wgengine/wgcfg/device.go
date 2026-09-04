// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package wgcfg

import (
	"fmt"

	"github.com/tailscale/wireguard-go/conn"
	"github.com/tailscale/wireguard-go/device"
	"github.com/tailscale/wireguard-go/tun"
	"tailscale.com/types/logger"
)

// NewDevice returns a wireguard-go Device configured for Tailscale use.
func NewDevice(tunDev tun.Device, bind conn.Bind, logger *device.Logger) *device.Device {
	return device.NewDevice(tunDev, bind, logger, getDeviceOptions()...)
}

// NewPeerLookupFunc returns a [device.PeerLookupFunc] that lazily
// creates peers using peerConfig as the source of each peer's allowed IPs and
// optional pre-shared key. The peer's endpoint is derived from its public key
// via bind.
func NewPeerLookupFunc(bind conn.Bind, logf logger.Logf, peerConfig func(device.NoisePublicKey) (PeerConfig, bool)) device.PeerLookupFunc {
	return func(pubk device.NoisePublicKey) (_ *device.NewPeerConfig, ok bool) {
		conf, ok := peerConfig(pubk)
		if !ok {
			return nil, false
		}
		ep, err := bind.ParseEndpoint(fmt.Sprintf("%x", pubk[:]))
		if err != nil {
			logf("wgcfg: failed to parse endpoint for peer %x: %v", pubk[:8], err)
			return nil, false
		}
		return &device.NewPeerConfig{
			AllowedIPs:   conf.AllowedIPs,
			PresharedKey: conf.PresharedKey,
			Endpoint:     ep,
		}, true
	}
}
