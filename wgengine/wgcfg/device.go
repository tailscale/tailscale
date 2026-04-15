// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package wgcfg

import (
	"fmt"
	"net/netip"

	"github.com/tailscale/wireguard-go/conn"
	"github.com/tailscale/wireguard-go/device"
	"github.com/tailscale/wireguard-go/tun"
	"tailscale.com/types/logger"
)

// NewDevice returns a wireguard-go Device configured for Tailscale use.
func NewDevice(tunDev tun.Device, bind conn.Bind, logger *device.Logger) *device.Device {
	ret := device.NewDevice(tunDev, bind, logger)
	ret.DisableSomeRoamingForBrokenMobileSemantics()
	return ret
}

// ReconfigDevice replaces the existing device configuration with cfg.
//
// Instead of using the UAPI text protocol, it uses the wireguard-go direct API
// to install a [device.PeerLookupFunc] callback that creates peers on demand.
//
// The caller is responsible for:
//   - calling [device.Device.SetPrivateKey] when the key changes
//   - installing a [device.PeerByIPPacketFunc] on the device for outbound
//     packet routing (e.g. via [tailscale.com/wgengine.Engine.SetPeerByIPPacketFunc])
func ReconfigDevice(d *device.Device, cfg *Config, logf logger.Logf) (err error) {
	defer func() {
		if err != nil {
			logf("wgcfg.Reconfig failed: %v", err)
		}
	}()

	// Build peer map: public key → allowed IPs.
	peers := make(map[device.NoisePublicKey][]netip.Prefix, len(cfg.Peers))
	for _, p := range cfg.Peers {
		peers[p.PublicKey.Raw32()] = p.AllowedIPs
	}

	// Remove peers not in the new config.
	d.RemoveMatchingPeers(func(pk device.NoisePublicKey) bool {
		_, exists := peers[pk]
		return !exists
	})

	// Update AllowedIPs on any already-active peers whose config may have
	// changed. Peers that don't exist yet will get the correct AllowedIPs
	// from PeerLookupFunc when they are lazily created.
	for pk, allowedIPs := range peers {
		if peer, ok := d.LookupActivePeer(pk); ok {
			peer.SetAllowedIPs(allowedIPs)
		}
	}

	// Install callback for lazy peer creation (incoming packets).
	bind := d.Bind()
	d.SetPeerLookupFunc(func(pubk device.NoisePublicKey) (_ *device.NewPeerConfig, ok bool) {
		allowedIPs, ok := peers[pubk]
		if !ok {
			return nil, false
		}
		ep, err := bind.ParseEndpoint(fmt.Sprintf("%x", pubk[:]))
		if err != nil {
			logf("wgcfg: failed to parse endpoint for peer %x: %v", pubk[:8], err)
			return nil, false
		}
		return &device.NewPeerConfig{
			AllowedIPs: allowedIPs,
			Endpoint:   ep,
		}, true
	})

	// RemoveMatchingPeers _again_, now that SetPeerLookupFunc is installed,
	// lest any removed peers got re-created before the new SetPeerLookupFunc
	// func was installed.
	d.RemoveMatchingPeers(func(pk device.NoisePublicKey) bool {
		_, exists := peers[pk]
		return !exists
	})

	return nil
}
