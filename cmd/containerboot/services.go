// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux

package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"tailscale.com/client/local"
	"tailscale.com/ipn"
)

// ensureServicesNotAdvertised is a function that gets called on containerboot
// termination and ensures that any currently advertised VIPServices get
// unadvertised to give clients time to switch to another node before this one
// is shut down.
func ensureServicesNotAdvertised(ctx context.Context, lc *local.Client) error {
	prefs, err := lc.GetPrefs(ctx)
	if err != nil {
		return fmt.Errorf("error getting prefs: %w", err)
	}
	if len(prefs.AdvertiseServices) == 0 {
		return nil
	}

	log.Printf("unadvertising services: %v", prefs.AdvertiseServices)
	if _, err := lc.EditPrefs(ctx, &ipn.MaskedPrefs{
		AdvertiseServicesSet: true,
		Prefs: ipn.Prefs{
			AdvertiseServices: nil,
		},
	}); err != nil {
		// EditPrefs only returns an error if it fails _set_ its local prefs.
		// If it fails to _persist_ the prefs in state, we don't get an error
		// and we continue waiting below, as control will failover as usual.
		return fmt.Errorf("error setting prefs AdvertiseServices: %w", err)
	}

	// Services use the same (failover XOR regional routing) mechanism that
	// HA subnet routers use. Unfortunately we don't yet get a reliable signal
	// from control that it's responded to our unadvertisement, so the best we
	// can do is wait for 20 seconds, where 15s is the approximate maximum time
	// it should take for control to choose a new primary, and 5s is for buffer.
	//
	// Note: There is no guarantee that clients have been _informed_ of the new
	// primary no matter how long we wait. We would need a mechanism to await
	// netmap updates for peers to know for sure.
	//
	// See https://tailscale.com/kb/1115/high-availability for more details.
	// TODO(tomhjp): Wait for a netmap update instead of sleeping when control
	// supports that.
	select {
	case <-ctx.Done():
		return nil
	case <-time.After(20 * time.Second):
		return nil
	}
}
