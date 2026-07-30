// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

package peerrelay

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"

	tsapi "tailscale.com/k8s-operator/apis/v1alpha1"
	"tailscale.com/k8s-operator/reconciler/tailscaled"
	"tailscale.com/kube/kubetypes"
)

func (r *Reconciler) peerRelayTags(pr *tsapi.PeerRelay) []string {
	tags := pr.Spec.Tags.Stringify()
	if len(tags) == 0 {
		return r.defaultTags
	}
	return tags
}

// getAuthKey returns the auth key to embed in a replica's config Secret, or nil if none is
// needed. A new key is minted if the config Secret doesn't exist yet, or if the replica has
// requested a reissue via its state Secret. An existing key is retained while the device hasn't
// authed or a reissue is in progress.
func (r *Reconciler) getAuthKey(ctx context.Context, pr *tsapi.PeerRelay, idx int32) (*string, error) {
	tsClient, err := r.tsClients.For(pr.Spec.Tailnet)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve Tailscale API client for tailnet %q: %w", pr.Spec.Tailnet, err)
	}

	var existingCfgSecret *corev1.Secret
	cfgSecret := &corev1.Secret{}
	err = r.Get(ctx, types.NamespacedName{Namespace: r.tailscaleNamespace, Name: configSecretName(pr.Name, idx)}, cfgSecret)
	switch {
	case apierrors.IsNotFound(err):
	case err != nil:
		return nil, fmt.Errorf("failed to get config Secret: %w", err)
	default:
		existingCfgSecret = cfgSecret
	}

	stateSecret := &corev1.Secret{}
	if err = r.Get(ctx, types.NamespacedName{Namespace: r.tailscaleNamespace, Name: replicaName(pr.Name, idx)}, stateSecret); err != nil && !apierrors.IsNotFound(err) {
		return nil, err
	}

	var createAuthKey bool
	var cfgAuthKey *string
	if existingCfgSecret == nil {
		createAuthKey = true
	} else {
		cfgAuthKey = tailscaled.AuthKeyFromConfigSecret(existingCfgSecret)
	}

	if !createAuthKey {
		createAuthKey, err = r.reissuer.ShouldReissue(ctx, tsClient, r.logger, tailscaled.ReissueInput{
			ParentName:  pr.Name,
			ReplicaName: replicaName(pr.Name, idx),
			Kind:        tailscaled.KindPeerRelay,
			StateSecret: stateSecret,
			CfgAuthKey:  cfgAuthKey,
		})
		if err != nil {
			return nil, err
		}
	}

	var authKey *string
	if createAuthKey {
		key, err := tailscaled.NewAuthKey(ctx, tsClient, r.peerRelayTags(pr))
		if err != nil {
			return nil, err
		}
		authKey = &key
	} else {
		// Retain auth key if the device hasn't authed yet, or if a reissue is
		// in progress (device_id is stale during reissue).
		_, reissueRequested := stateSecret.Data[kubetypes.KeyReissueAuthkey]
		if tailscaled.DeviceIDFromStateSecret(stateSecret) == "" || reissueRequested {
			authKey = cfgAuthKey
		}
	}

	return authKey, nil
}
