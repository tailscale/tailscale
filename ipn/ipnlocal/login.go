// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package ipnlocal

import (
	"context"
	"errors"

	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnauth"
)

// beginLoginOpts describes the optional configuration for an interactive login.
// prefs contains edits to the current profile.
type beginLoginOpts struct {
	prefs   *ipn.MaskedPrefs
	authKey string
}

// beginLoginAs initiates interactive login, reusing the existing control client
// when its configuration is already suitable. In particular, it does not set
// WantRunning through EditPrefs before calling Start, since doing this could start a
// login on a control client that Start would immediately replace.
//
// Profile creation and selection are the caller's responsibility. The OS VPN
// tunnel must also be started separately by platform clients.
func (b *LocalBackend) beginLoginAs(ctx context.Context, actor ipnauth.Actor, opts beginLoginOpts) error {
	b.beginLoginMu.Lock()
	defer b.beginLoginMu.Unlock()

	if err := ctx.Err(); err != nil {
		return err
	}
	if b.health.IsUnhealthy(ipn.StateStoreHealth) {
		return errors.New("cannot log in when state store is unhealthy")
	}

	b.mu.Lock()
	current := b.pm.CurrentPrefs()
	prefs := current.AsStruct()
	if opts.prefs != nil {
		prefs.ApplyEdits(opts.prefs)
	}
	prefs.WantRunning = true
	if opts.authKey != "" {
		prefs.LoggedOut = false
	}
	// Start recreates the control client and clears any pending auth URL.
	// Keep the current client (and pending auth flow) when no changes are needed.
	needsStart := b.cc == nil || opts.authKey != "" || !prefs.View().Equals(current)
	b.mu.Unlock()

	if needsStart {
		if err := b.Start(ipn.Options{UpdatePrefs: prefs, AuthKey: opts.authKey}); err != nil {
			return err
		}
	}
	return b.StartLoginInteractiveAs(ctx, actor)
}
