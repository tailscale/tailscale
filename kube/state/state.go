// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

// Package state updates state keys for tailnet client devices managed by the
// operator. These keys are used to signal readiness, metadata, and current
// configuration state to the operator. Client packages deployed by the operator
// include containerboot, tsrecorder, and k8s-proxy, but currently containerboot
// has its own implementation to manage the same keys.
package state

import (
	"encoding/json"
	"fmt"

	"tailscale.com/ipn"
	"tailscale.com/kube/kubetypes"
	"tailscale.com/tailcfg"
	"tailscale.com/util/deephash"
)

const (
	keyPodUID     = ipn.StateKey(kubetypes.KeyPodUID)
	keyCapVer     = ipn.StateKey(kubetypes.KeyCapVer)
	keyDeviceID   = ipn.StateKey(kubetypes.KeyDeviceID)
	keyDeviceIPs  = ipn.StateKey(kubetypes.KeyDeviceIPs)
	keyDeviceFQDN = ipn.StateKey(kubetypes.KeyDeviceFQDN)
)

// SetInitialKeys sets Pod UID and cap ver and clears tailnet device state
// keys to help stop the operator using stale tailnet device state.
func SetInitialKeys(store ipn.StateStore, podUID string) error {
	// Clear device state keys first so the operator knows if the pod UID
	// matches, the other values are definitely not stale.
	for _, key := range []ipn.StateKey{keyDeviceID, keyDeviceFQDN, keyDeviceIPs} {
		if _, err := store.ReadState(key); err == nil {
			if err := store.WriteState(key, nil); err != nil {
				return fmt.Errorf("error writing %q to state store: %w", key, err)
			}
		}
	}

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
// cancelled or it hits an error. The passed in next function is expected to be
// from a local.IPNBusWatcher that is at least subscribed to
// ipn.NotifyInitialNetMap.
func KeepKeysUpdated(store ipn.StateStore, next func() (ipn.Notify, error)) error {
	var currentDeviceID, currentDeviceIPs, currentDeviceFQDN deephash.Sum

	for {
		n, err := next() // Blocks on a streaming LocalAPI HTTP call.
		if err != nil {
			return err
		}
		if n.NetMap == nil {
			continue
		}

		if deviceID := n.NetMap.SelfNode.StableID(); deephash.Update(&currentDeviceID, &deviceID) {
			if err := store.WriteState(keyDeviceID, []byte(deviceID)); err != nil {
				return fmt.Errorf("failed to store device ID in state: %w", err)
			}
		}

		if fqdn := n.NetMap.SelfNode.Name(); deephash.Update(&currentDeviceFQDN, &fqdn) {
			if err := store.WriteState(keyDeviceFQDN, []byte(fqdn)); err != nil {
				return fmt.Errorf("failed to store device FQDN in state: %w", err)
			}
		}

		if addrs := n.NetMap.SelfNode.Addresses(); deephash.Update(&currentDeviceIPs, &addrs) {
			var deviceIPs []string
			for _, addr := range addrs.AsSlice() {
				deviceIPs = append(deviceIPs, addr.Addr().String())
			}
			deviceIPsValue, err := json.Marshal(deviceIPs)
			if err != nil {
				return err
			}
			if err := store.WriteState(keyDeviceIPs, deviceIPsValue); err != nil {
				return fmt.Errorf("failed to store device IPs in state: %w", err)
			}
		}
	}
}
