// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !darwin && !ios

package dns

import "tailscale.com/feature/buildfeatures"

// managerCacheFlush provides no-op cache-flush hooks on platforms without NXDOMAIN tracking.
type managerCacheFlush struct{}

// SetCacheFlushHook is a no-op on this platform.
func (*managerCacheFlush) SetCacheFlushHook(func()) {}

// CheckCachedDNS is a no-op on this platform.
func (*managerCacheFlush) CheckCachedDNS() {}

// FlushCaches flushes the platform DNS cache using the native implementation.
func (*Manager) FlushCaches() error {
	if !buildfeatures.HasDNS {
		return nil
	}
	return flushCaches()
}
