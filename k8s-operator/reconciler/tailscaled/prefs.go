// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

package tailscaled

import (
	"encoding/json"
	"fmt"

	corev1 "k8s.io/api/core/v1"

	"tailscale.com/ipn"
	"tailscale.com/tailcfg"
)

// Prefs is the subset of ipn.Prefs that operator reconcilers need to read back out of a tailscaled state Secret.
// tailscaled writes the full prefs for the current profile; only the fields declared here are unmarshalled.
type Prefs struct {
	Config struct {
		NodeID      tailcfg.StableNodeID `json:"NodeID"`
		UserProfile struct {
			// LoginName is the MagicDNS name of the device, e.g. foo.tail-scale.ts.net.
			LoginName string `json:"LoginName"`
		} `json:"UserProfile"`
	} `json:"Config"`

	AdvertiseServices []string `json:"AdvertiseServices"`
}

// PrefsFromStateSecret returns the prefs tailscaled recorded for its current profile in secret. ok reports whether
// a node ID was found; it is false when the device hasn't finished authenticating yet, in which case prefs is not
// meaningful. LoginName is expected to be set whenever the node ID is, but that is not required.
//
// TODO(tomhjp): Should maybe use ipn to parse the following info instead.
func PrefsFromStateSecret(secret *corev1.Secret) (prefs Prefs, ok bool, err error) {
	currentProfile, ok := secret.Data[string(ipn.CurrentProfileStateKey)]
	if !ok {
		return prefs, false, nil
	}
	profileBytes, ok := secret.Data[string(currentProfile)]
	if !ok {
		return prefs, false, nil
	}
	if err := json.Unmarshal(profileBytes, &prefs); err != nil {
		return prefs, false, fmt.Errorf("failed to extract node profile info from state Secret %s: %w", secret.Name, err)
	}

	ok = prefs.Config.NodeID != ""
	return prefs, ok, nil
}
