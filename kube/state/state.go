// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

// Package state updates state keys for tailnet client devices managed by the
// operator. These keys are used to signal readiness, metadata, and current
// configuration state to the operator. Client packages deployed by the operator
// include containerboot, tsrecorder, and k8s-proxy, but currently containerboot
// has its own implementation to manage the same keys.
package state

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"slices"

	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/kube/kubetypes"
	klc "tailscale.com/kube/localclient"
	"tailscale.com/tailcfg"
)

const (
	keyPodUID     = ipn.StateKey(kubetypes.KeyPodUID)
	keyCapVer     = ipn.StateKey(kubetypes.KeyCapVer)
	keyDeviceID   = ipn.StateKey(kubetypes.KeyDeviceID)
	keyDeviceIPs  = ipn.StateKey(kubetypes.KeyDeviceIPs)
	keyDeviceFQDN = ipn.StateKey(kubetypes.KeyDeviceFQDN)
)

// SetInitialKeys sets Pod UID and cap ver.
func SetInitialKeys(store ipn.StateStore, podUID string) error {
	if err := store.WriteState(keyPodUID, []byte(podUID)); err != nil {
		return fmt.Errorf("error writing pod UID to state store: %w", err)
	}
	if err := store.WriteState(keyCapVer, fmt.Appendf(nil, "%d", tailcfg.CurrentCapabilityVersion)); err != nil {
		return fmt.Errorf("error writing capability version to state store: %w", err)
	}

	return nil
}

// KeepKeysUpdated sets state store keys consistent with containerboot to
// signal proxy readiness to the operator. It runs until its context is
// cancelled or it hits an error. It seeds the self node from the initial
// status and then watches the IPN bus for SelfChange notifications, which
// fire whenever the self node changes.
func KeepKeysUpdated(ctx context.Context, store ipn.StateStore, lc klc.LocalClient) error {
	w, err := lc.WatchIPNBus(ctx, ipn.NotifyInitialStatus)
	if err != nil {
		return fmt.Errorf("error watching IPN bus: %w", err)
	}
	defer w.Close()

	var prevDeviceID tailcfg.StableNodeID
	var prevFQDN string
	var prevAddrs []netip.Prefix

	// storeSelf writes the device ID, FQDN, and IP state keys derived
	// from the given self node, skipping any whose value is unchanged
	// since the last write.
	storeSelf := func(self tailcfg.NodeView) error {
		if deviceID := self.StableID(); deviceID != prevDeviceID {
			if err := store.WriteState(keyDeviceID, []byte(deviceID)); err != nil {
				return fmt.Errorf("failed to store device ID in state: %w", err)
			}
			prevDeviceID = deviceID
		}

		if fqdn := self.Name(); fqdn != prevFQDN {
			if err := store.WriteState(keyDeviceFQDN, []byte(fqdn)); err != nil {
				return fmt.Errorf("failed to store device FQDN in state: %w", err)
			}
			prevFQDN = fqdn
		}

		if addrs := self.Addresses().AsSlice(); !slices.Equal(addrs, prevAddrs) {
			var deviceIPs []string
			for _, addr := range addrs {
				deviceIPs = append(deviceIPs, addr.Addr().String())
			}
			deviceIPsValue, err := json.Marshal(deviceIPs)
			if err != nil {
				return err
			}
			if err := store.WriteState(keyDeviceIPs, deviceIPsValue); err != nil {
				return fmt.Errorf("failed to store device IPs in state: %w", err)
			}
			prevAddrs = addrs
		}
		return nil
	}

	for {
		n, err := w.Next() // Blocks on a streaming LocalAPI HTTP call.
		if err != nil {
			if err == ctx.Err() {
				return nil
			}
			return err
		}

		var self tailcfg.NodeView
		switch {
		case n.SelfChange != nil:
			self = n.SelfChange.View()
		case n.InitialStatus != nil && n.InitialStatus.Self != nil:
			self = selfNodeFromPeerStatus(n.InitialStatus.Self)
		default:
			continue
		}
		if err := storeSelf(self); err != nil {
			return err
		}
	}
}

// selfNodeFromPeerStatus converts the subset of ps that KeepKeysUpdated
// reads into a [tailcfg.NodeView], so the initial status seed and
// subsequent [ipn.Notify.SelfChange] updates can share one code path.
func selfNodeFromPeerStatus(ps *ipnstate.PeerStatus) tailcfg.NodeView {
	n := &tailcfg.Node{
		StableID: ps.ID,
		Name:     ps.DNSName,
	}
	for _, ip := range ps.TailscaleIPs {
		n.Addresses = append(n.Addresses, netip.PrefixFrom(ip, ip.BitLen()))
	}
	return n.View()
}
