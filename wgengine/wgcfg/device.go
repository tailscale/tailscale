// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package wgcfg

import (
	"log"
	"net/netip"

	"github.com/tailscale/wireguard-go/conn"
	"github.com/tailscale/wireguard-go/device"
	"github.com/tailscale/wireguard-go/tun"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
)

// NewDevice returns a wireguard-go Device configured for Tailscale use.
func NewDevice(tunDev tun.Device, bind conn.Bind, logger *device.Logger) *device.Device {
	ret := device.NewDevice(tunDev, bind, logger)
	ret.DisableSomeRoamingForBrokenMobileSemantics()
	return ret
}

// ReconfigDevice replaces the existing device configuration with cfg.
func ReconfigDevice(d *device.Device, cfg *Config, logf logger.Logf) (err error) {
	defer func() {
		if err != nil {
			logf("wgcfg.Reconfig failed: %v", err)
		}
	}()

	d.SetPrivateKey(key.NodePrivateAs[device.NoisePrivateKey](cfg.PrivateKey))

	peers := map[device.NoisePublicKey][]netip.Prefix{} // public key → allowed IPs
	for _, p := range cfg.Peers {
		peers[p.PublicKey.Raw32()] = p.AllowedIPs
	}
	d.RemoveMatchingPeers(func(pk device.NoisePublicKey) bool {
		_, exists := peers[pk]
		return !exists
	})

	d.SetPeerLookupFunc(func(pubk device.NoisePublicKey) []netip.Prefix {
		allowedIPs, ok := peers[pubk]
		log.Printf("XXX wgcfg.ReconfigDevice: lookup for peer %v, found=%v => %v", pubk, ok, allowedIPs)
		return allowedIPs
	})

	return nil
}
