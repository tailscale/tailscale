// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build darwin || ios

package dns

import "tailscale.com/feature/buildfeatures"

// managerCacheFlush holds the Apple-specific cache-flush hook, guarded by Manager.mu.
type managerCacheFlush struct {
	cacheFlushHook func()
}

// SetCacheFlushHook installs a callback that flushes the DNS cache by reapplying
// VPN settings. Passing nil removes the callback. The callback must be
// concurrency-safe, return promptly, must not call LocalBackend.  Typically, it should
// be set as early as possible during backend initialization and never thereafter.  The hook
// is not called immediately when set.
//
// Must be called without the manager lock held.
func (m *Manager) SetCacheFlushHook(hook func()) {
	if !buildfeatures.HasDNS {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.cacheFlushHook = hook
}

// MaybeCheckCachedDNS checks previously issued negative answers against the current
// in-memory host records after a peer update. It does not issue DNS queries.
func (m *Manager) MaybeCheckCachedDNS() {
	if !buildfeatures.HasDNS || !m.resolver.CheckCachedDNS() {
		return
	}
	m.mu.Lock()
	hook := m.cacheFlushHook
	m.mu.Unlock()
	if hook != nil {
		m.logf("MagicDNS record became resolvable after issuing NXDOMAIN; requesting DNS cache flush")
		hook()
	} else {
		m.logf("MagicDNS record became resolvable after issuing NXDOMAIN; no cache flush hook is set")
	}
}

// FlushCaches forgets negative answers covered by link-change handling.
// The caller already reapplies VPN settings on macOS and iOS, so this must not
// invoke the cache-flush hook and request another VPN reconfiguration.
func (m *Manager) FlushCaches() error {
	if buildfeatures.HasDNS {
		m.resolver.ClearNegativeCache()
	}
	return nil
}
