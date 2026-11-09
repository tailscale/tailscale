// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package ipnlocal

import (
	"context"

	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnauth"
)

// beginLoginOpts describes the optional configuration for an interactive login.
// prefs contains edits to the current profile.
type beginLoginOpts struct {
	prefs      *ipn.MaskedPrefs
	authKey    string
	controlURL string
}

// beginLoginAs initiates interactive login, reusing the existing control client
// when its configuration is already suitable. In particular, it does not set
// WantRunning through EditPrefs before calling Start, since doing this could start a
// login on a control client that Start would immediately replace.
//
// This method blocks until login has been initiated, but does not wait for authentication
// to complete. The Caller must not hold b.mu or b.beginLoginMu.
//
// Profile creation and selection are the caller's responsibility. The OS VPN
// tunnel must also be started separately by platform clients.
func (b *LocalBackend) beginLoginAs(ctx context.Context, actor ipnauth.Actor, opts beginLoginOpts) error {
	b.beginLoginMu.Lock()
	defer b.beginLoginMu.Unlock()

	if err := ctx.Err(); err != nil {
		return err
	}

	b.mu.Lock()
	current := b.pm.CurrentPrefs()
	prefs := current.AsStruct()
	if opts.prefs != nil {
		prefs.ApplyEdits(opts.prefs)
	}
	if opts.controlURL != "" {
		prefs.ControlURL = opts.controlURL
	}
	prefs.WantRunning = true
	if opts.authKey != "" {
		prefs.LoggedOut = false
	}
	// Start recreates the control client and clears any pending auth URL.
	// Keep the current client (and pending auth flow) when no changes are needed.,
	// unless an explicit auth key or control URL was provided.
	needsStart := b.cc == nil || opts.authKey != "" || opts.controlURL != "" || !prefs.View().Equals(current)
	b.mu.Unlock()

	if needsStart {
		if err := b.Start(ipn.Options{UpdatePrefs: prefs, AuthKey: opts.authKey}); err != nil {
			return err
		}
	}
	return b.StartLoginInteractiveAs(ctx, actor)
}
