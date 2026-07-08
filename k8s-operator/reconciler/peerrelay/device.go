// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

package peerrelay

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"sigs.k8s.io/controller-runtime/pkg/client"

	tailscaleclient "tailscale.com/client/tailscale/v2"

	tsapi "tailscale.com/k8s-operator/apis/v1alpha1"
	"tailscale.com/kube/kubetypes"
)

func (r *Reconciler) deleteDevicesFrom(ctx context.Context, pr *tsapi.PeerRelay, fromIdx int32) error {
	if r.tsClients == nil {
		return nil
	}

	tsc, err := r.tsClients.For(pr.Spec.Tailnet)
	if err != nil {
		return fmt.Errorf("failed to resolve Tailscale API client for tailnet %q: %w", pr.Spec.Tailnet, err)
	}

	var list corev1.SecretList
	if err = r.List(ctx, &list, client.InNamespace(r.tailscaleNamespace)); err != nil {
		return fmt.Errorf("failed to list Secrets: %w", err)
	}

	prefix := pr.Name + "-"
	var errs []error
	for i := range list.Items {
		s := &list.Items[i]

		if s.Labels[kubetypes.LabelSecretType] == kubetypes.LabelSecretTypeConfig {
			continue
		}
		if !strings.HasPrefix(s.Name, prefix) {
			continue
		}

		ordinal, err := strconv.ParseInt(s.Name[len(prefix):], 10, 32)
		if err != nil {
			continue
		}
		if int32(ordinal) < fromIdx {
			continue
		}

		if deviceID := string(s.Data[kubetypes.KeyDeviceID]); deviceID != "" {
			if err = tsc.Devices().Delete(ctx, deviceID); err != nil && !tailscaleclient.IsNotFound(err) {
				errs = append(errs, fmt.Errorf("failed to delete tailnet device %q: %w", deviceID, err))
				continue
			}
		}

		if err = r.Delete(ctx, s); err != nil && !apierrors.IsNotFound(err) {
			errs = append(errs, fmt.Errorf("failed to delete state Secret %q: %w", s.Name, err))
		}
	}

	return errors.Join(errs...)
}
