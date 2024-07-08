// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux || windows

package ipnlocal

import (
	"context"
	"time"

	"tailscale.com/clientupdate"
	"tailscale.com/ipn"
	"tailscale.com/version"
)

func (b *LocalBackend) stopOfflineAutoUpdate() {
	if b.offlineAutoUpdateCancel != nil {
		b.logf("offline auto-update: stopping update checks")
		b.offlineAutoUpdateCancel()
		b.offlineAutoUpdateCancel = nil
	}
}

func (b *LocalBackend) maybeStartOfflineAutoUpdate(prefs ipn.PrefsView) {
	if !prefs.AutoUpdate().Apply.EqualBool(true) {
		return
	}
	// AutoUpdate.Apply field in prefs can only be true for platforms that
	// support auto-updates. But check it here again, just in case.
	if !clientupdate.CanAutoUpdate() {
		return
	}
	// On macsys, auto-updates are managed by Sparkle.
	if version.IsMacSysExt() {
		return
	}

	if b.offlineAutoUpdateCancel != nil {
		// Already running.
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	b.offlineAutoUpdateCancel = cancel

	b.logf("offline auto-update: starting update checks")
	go b.offlineAutoUpdate(ctx)
}

const offlineAutoUpdateCheckPeriod = time.Hour

func (b *LocalBackend) offlineAutoUpdate(ctx context.Context) {
	t := time.NewTicker(offlineAutoUpdateCheckPeriod)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		if err := b.startAutoUpdate("offline auto-update"); err != nil {
			b.logf("offline auto-update: failed: %v", err)
		}
	}
}
