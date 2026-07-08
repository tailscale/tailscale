// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

package peerrelay

import (
	"context"
	"encoding/json"
	"fmt"

	corev1 "k8s.io/api/core/v1"

	tailscaleclient "tailscale.com/client/tailscale/v2"

	"tailscale.com/ipn"
	tsapi "tailscale.com/k8s-operator/apis/v1alpha1"
	"tailscale.com/k8s-operator/tsclient"
)

// ClientProvider returns a Tailscale API client for the given tailnet name. A blank name should return the
// operator's default client. This mirrors the subset of *tsclient.Provider the reconciler needs and is broken out
// as an interface so tests can supply a fake.
type ClientProvider interface {
	For(tailnet string) (tsclient.Client, error)
}

func newAuthKey(ctx context.Context, client tsclient.Client, tags []string) (string, error) {
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

func authKeyFromConfigSecret(secret *corev1.Secret) *string {
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

func (r *Reconciler) peerRelayTags(pr *tsapi.PeerRelay) []string {
	tags := pr.Spec.Tags.Stringify()
	if len(tags) == 0 {
		return r.defaultTags
	}
	return tags
}
