// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

package peerrelay

import (
	"context"
	"errors"
	"fmt"

	"go.uber.org/zap"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"sigs.k8s.io/controller-runtime/pkg/client"

	tailscaleclient "tailscale.com/client/tailscale/v2"

	tsapi "tailscale.com/k8s-operator/apis/v1alpha1"
	"tailscale.com/k8s-operator/reconciler/tailscaled"
	"tailscale.com/kube/kubetypes"
)

func (r *Reconciler) deleteDevicesFrom(ctx context.Context, logger *zap.SugaredLogger, pr *tsapi.PeerRelay, fromIdx int32) error {
	if r.tsClients == nil {
		return nil
	}

	tsc, err := r.tsClients.For(pr.Spec.Tailnet)
	if err != nil {
		return fmt.Errorf("failed to resolve Tailscale API client for tailnet %q: %w", pr.Spec.Tailnet, err)
	}

	labels := peerRelayLabels(pr.Name)
	labels[kubetypes.LabelSecretType] = kubetypes.LabelSecretTypeState

	var list corev1.SecretList
	if err = r.List(ctx, &list, client.InNamespace(r.tailscaleNamespace), client.MatchingLabels(labels)); err != nil {
		return fmt.Errorf("failed to list state Secrets: %w", err)
	}

	var errs []error
	for i := range list.Items {
		s := &list.Items[i]
		idx, ok := replicaIndexFromLabels(s.Labels)
		if !ok || idx < fromIdx {
			continue
		}

		if deviceID := tailscaled.DeviceIDFromStateSecret(s); deviceID != "" {
			logger.Debugf("deleting tailnet device %q", deviceID)
			if err = tsc.Devices().Delete(ctx, deviceID); err != nil && !tailscaleclient.IsNotFound(err) {
				errs = append(errs, fmt.Errorf("failed to delete tailnet device %q: %w", deviceID, err))
				continue
			}
		}

		logger.Debugf("deleting state Secret %q", s.Name)
		if err = r.Delete(ctx, s); err != nil && !apierrors.IsNotFound(err) {
			errs = append(errs, fmt.Errorf("failed to delete state Secret %q: %w", s.Name, err))
		}
	}

	return errors.Join(errs...)
}
