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

	tailscaleclient "tailscale.com/client/tailscale/v2"

	tsapi "tailscale.com/k8s-operator/apis/v1alpha1"
	"tailscale.com/k8s-operator/reconciler/tailscaled"
	"tailscale.com/k8s-operator/tsclient"
	"tailscale.com/kube/kubetypes"
	"tailscale.com/tailcfg"
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
func (r *Reconciler) getAuthKey(ctx context.Context, tsClient tsclient.Client, pr *tsapi.PeerRelay, idx int32) (*string, error) {
	var existingCfgSecret *corev1.Secret
	cfgSecret := &corev1.Secret{}
	err := r.Get(ctx, types.NamespacedName{Namespace: r.tailscaleNamespace, Name: configSecretName(pr.Name, idx)}, cfgSecret)
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
		createAuthKey, err = r.shouldReissueAuthKey(ctx, tsClient, pr, idx, stateSecret, cfgAuthKey)
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

// shouldReissueAuthKey returns true if the replica needs a new auth key. It tracks in-flight
// reissues via authKeyReissuing to avoid duplicate API calls across reconciles.
func (r *Reconciler) shouldReissueAuthKey(ctx context.Context, tsClient tsclient.Client, pr *tsapi.PeerRelay, idx int32, stateSecret *corev1.Secret, cfgAuthKey *string) (shouldReissue bool, err error) {
	name := replicaName(pr.Name, idx)

	r.mu.Lock()
	reissuing := r.authKeyReissuing[name]
	r.mu.Unlock()

	if reissuing {
		_, requestStillPresent := stateSecret.Data[kubetypes.KeyReissueAuthkey]
		if !requestStillPresent {
			r.mu.Lock()
			r.authKeyReissuing[name] = false
			r.mu.Unlock()
			r.logger.Debugf("auth key reissue completed for %q", name)
			return false, nil
		}
		r.logger.Debugf("auth key already in process of re-issuance for %q, waiting", name)
		return false, nil
	}

	defer func() {
		r.mu.Lock()
		r.authKeyReissuing[name] = shouldReissue
		r.mu.Unlock()
	}()

	brokenAuthkey, ok := stateSecret.Data[kubetypes.KeyReissueAuthkey]
	if !ok {
		return false, nil
	}

	empty := cfgAuthKey == nil || *cfgAuthKey == ""
	broken := cfgAuthKey != nil && *cfgAuthKey == string(brokenAuthkey)

	// A new key has been written but the replica hasn't picked it up yet.
	if !empty && !broken {
		return false, nil
	}

	lim := r.authKeyRateLimits[pr.Name]
	if !lim.Allow() {
		r.logger.Debugf("auth key re-issuance rate limit exceeded, limit: %.2f, burst: %d, tokens: %.2f",
			lim.Limit(), lim.Burst(), lim.Tokens())
		return false, fmt.Errorf("auth key re-issuance rate limit exceeded for PeerRelay %q, will retry with backoff", pr.Name)
	}

	r.logger.Infof("PeerRelay replica %s failing to auth; attempting cleanup and new key", name)
	if tsID := stateSecret.Data[kubetypes.KeyDeviceID]; len(tsID) > 0 {
		if err = r.ensureDeviceDeleted(ctx, tsClient, tailcfg.StableNodeID(tsID)); err != nil {
			return false, err
		}
	}

	return true, nil
}

func (r *Reconciler) ensureDeviceDeleted(ctx context.Context, tsClient tsclient.Client, id tailcfg.StableNodeID) error {
	r.logger.Debugf("deleting device %s from control", string(id))
	err := tsClient.Devices().Delete(ctx, string(id))
	switch {
	case tailscaleclient.IsNotFound(err):
		r.logger.Debugf("device %s not found, likely because it has already been deleted from control", string(id))
	case err != nil:
		return fmt.Errorf("error deleting device: %w", err)
	default:
		r.logger.Debugf("device %s deleted from control", string(id))
	}
	return nil
}
