// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package services manages graceful shutdown of Tailscale Services advertised
// by Kubernetes clients.
package services

import (
	"context"
	"fmt"

	"tailscale.com/client/local"
	"tailscale.com/ipn"
	"tailscale.com/types/logger"
)

// EnsureServicesNotAdvertised is a function that gets called on containerboot
// or k8s-proxy termination and ensures that any currently advertised Services
// get unadvertised to give clients time to switch to another node before this
// one is shut down.
func EnsureServicesNotAdvertised(ctx context.Context, lc *local.Client, logf logger.Logf) error {
	prefs, err := lc.GetPrefs(ctx)
	if err != nil {
		return fmt.Errorf("error getting prefs: %w", err)
	}

	if len(prefs.AdvertiseServices) == 0 {
		return nil
	}

	logf("unadvertising services: %v", prefs.AdvertiseServices)
	_, err = lc.EditPrefs(ctx, &ipn.MaskedPrefs{
		AdvertiseServicesSet: true,
		Prefs: ipn.Prefs{
			AdvertiseServices: nil,
		}})
	if err != nil {
		// EditPrefs only returns an error if it fails to _set_ its local prefs.
		return fmt.Errorf("error setting prefs AdvertiseServices: %w", err)
	}

	return nil
}
