// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build ts_omit_serve

// These are temporary (2025-09-13) stubs for when tailscaled is built with the
// ts_omit_serve build tag, disabling serve.
//
// TODO: move serve to a separate package, out of ipnlocal, and delete this
// file. One step at a time.

package ipnlocal

import (
	"tailscale.com/ipn"
	"tailscale.com/tailcfg"
)

const serveEnabled = false

type localListener = struct{}

func (b *LocalBackend) DeleteForegroundSession(sessionID string) error {
	return nil
}

type funnelFlow = struct{}

func (*LocalBackend) hasIngressEnabledLocked() bool         { return false }
func (*LocalBackend) shouldWireInactiveIngressLocked() bool { return false }

func (b *LocalBackend) vipServicesFromPrefsLocked(prefs ipn.PrefsView) []*tailcfg.VIPService {
	return nil
}
