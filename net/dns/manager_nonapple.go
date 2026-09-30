// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !darwin && !ios

package dns

import "tailscale.com/feature/buildfeatures"

// managerCacheFlush has no state on platforms without NXDOMAIN tracking.
type managerCacheFlush struct{}

// SetCacheFlushHook is a no-op on this platform.
func (*Manager) SetCacheFlushHook(func()) {}

// CheckCachedDNS is a no-op on this platform.
func (*Manager) CheckCachedDNS() {}

// FlushCaches flushes the platform DNS cache using the native implementation.
func (*Manager) FlushCaches() error {
	if !buildfeatures.HasDNS {
		return nil
	}
	return flushCaches()
}
