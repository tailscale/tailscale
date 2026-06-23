// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build ts_omit_tailnetlock

package ipnlocal

import (
	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/tka"
	"tailscale.com/types/netmap"
)

type tkaState struct {
	authority *tka.Authority
}

func (b *LocalBackend) initTKALocked() error {
	return nil
}

func (b *LocalBackend) tkaSyncIfNeeded(nm *netmap.NetworkMap, prefs ipn.PrefsView) error {
	return nil
}

func (b *LocalBackend) tkaFilterNetmapLocked(nm *netmap.NetworkMap) {}

func (b *LocalBackend) tkaFilterDeltaMutsLocked(muts []netmap.NodeMutation) []netmap.NodeMutation {
	return muts
}

func (b *LocalBackend) TailnetLockStatus() *ipnstate.TailnetLockStatus {
	return &ipnstate.TailnetLockStatus{Enabled: false}
}

// Deprecated: use [LocalBackend.TailnetLockStatus] instead.
func (b *LocalBackend) NetworkLockStatus() *ipnstate.TailnetLockStatus {
	return b.TailnetLockStatus()
}
