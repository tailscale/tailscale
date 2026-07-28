// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

package tailscaled

import (
	"context"
	"encoding/json"
	"fmt"

	corev1 "k8s.io/api/core/v1"

	tailscaleclient "tailscale.com/client/tailscale/v2"

	"tailscale.com/ipn"
	"tailscale.com/k8s-operator/tsclient"
)

// ClientProvider returns a Tailscale API client for the given tailnet name. A blank name should return the
// operator's default client.
type ClientProvider interface {
	For(tailnet string) (tsclient.Client, error)
}

// NewAuthKey mints a single-use, preauthorized tailnet auth key with the given tags. The key is intended for one
// tailscaled pod to consume on first startup; callers should not persist or share it.
func NewAuthKey(ctx context.Context, client tsclient.Client, tags []string) (string, error) {
	var caps tailscaleclient.KeyCapabilities
	caps.Devices.Create.Reusable = false
	caps.Devices.Create.Preauthorized = true
	caps.Devices.Create.Tags = tags

	key, err := client.Keys().CreateAuthKey(ctx, tailscaleclient.CreateKeyRequest{Capabilities: caps})
	if err != nil {
		return "", fmt.Errorf("failed to create auth key: %w", err)
	}
	return key.Key, nil
}

// AuthKeyFromConfigSecret returns the auth key embedded in the tailscaled config file stored in secret, or nil if
// none is set. secret is expected to be a Secret produced by NewConfigSecret. The Data map may contain multiple
// versioned config files (cap-<n>.hujson); the first one to parse successfully and yield a non-empty AuthKey wins.
func AuthKeyFromConfigSecret(secret *corev1.Secret) *string {
	for _, body := range secret.Data {
		var conf ipn.ConfigVAlpha
		if err := json.Unmarshal(body, &conf); err != nil {
			continue
		}
		if conf.AuthKey != nil && *conf.AuthKey != "" {
			return conf.AuthKey
		}
	}
	return nil
}
