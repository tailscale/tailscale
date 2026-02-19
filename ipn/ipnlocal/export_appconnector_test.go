// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ts_omit_appconnectors

package ipnlocal

import (
	"context"
	"net/http"
	"net/netip"

	"tailscale.com/health"
	"tailscale.com/ipn/store/mem"
	"tailscale.com/tailcfg"
	"tailscale.com/tsd"
	"tailscale.com/types/logger"
	"tailscale.com/types/netmap"
	"tailscale.com/wgengine/filter"
)

// Exported wrappers for use by appconnector_test.go (package ipnlocal_test).

var (
	ExportNewTestBackend             = newTestBackend
	ExportNewTestLocalBackendWithSys = newTestLocalBackendWithSys
)

// ExportNewProfileManager wraps newProfileManager for testing.
func ExportNewProfileManager(store *mem.Store, logf logger.Logf, ht *health.Tracker) (*profileManager, error) {
	return newProfileManager(store, logf, ht)
}

// InitExtensionsForTest initializes all registered extensions on the backend.
// In production, this happens during the first call to Start().
func (b *LocalBackend) InitExtensionsForTest() {
	b.extHost.Init()
}

// TriggerOnAuthReconfigForTest synchronously invokes the OnAuthReconfig hooks,
// which in production are called asynchronously by authReconfigLocked.
func (b *LocalBackend) TriggerOnAuthReconfigForTest() {
	nm := b.NetMap()
	var selfNode tailcfg.NodeView
	if nm != nil {
		selfNode = nm.SelfNodeOrZero()
	}
	prefs := b.Prefs()
	for _, f := range b.extHost.Hooks().OnAuthReconfig {
		f(selfNode, prefs)
	}
}

// SetNetMapForTest sets the netmap on the backend's current node.
func (b *LocalBackend) SetNetMapForTest(nm *netmap.NetworkMap) {
	b.currentNode().SetNetMap(nm)
}

// SysForTest returns the backend's system dependencies for testing.
func (b *LocalBackend) SysForTest() *tsd.System {
	return b.sys
}

// SetFilterForTest sets the packet filter on the backend.
func (b *LocalBackend) SetFilterForTest(f *filter.Filter) {
	b.setFilter(f)
}

// SetProfileManagerForTest overrides the backend's profile manager.
func (b *LocalBackend) SetProfileManagerForTest(pm *profileManager) {
	b.pm = pm
}

// PeerAPIServerForTest wraps an unexported peerAPIServer for external test access.
type PeerAPIServerForTest struct {
	ps *peerAPIServer
}

// NewPeerAPIServerForTest creates a peerAPIServer for testing.
func NewPeerAPIServerForTest(b *LocalBackend) *PeerAPIServerForTest {
	return &PeerAPIServerForTest{ps: &peerAPIServer{b: b}}
}

// PeerDNSQueryHandlerForTest is an exported alias for the unexported
// peerDNSQueryHandler interface, for use in external test packages.
type PeerDNSQueryHandlerForTest = peerDNSQueryHandler

// SetResolver sets the DNS resolver for the peerAPI server.
func (s *PeerAPIServerForTest) SetResolver(r PeerDNSQueryHandlerForTest) {
	s.ps.resolver = r
}

// PeerAPIHandlerForTest wraps an unexported peerAPIHandler for external test access.
type PeerAPIHandlerForTest struct {
	h peerAPIHandler
}

// NewPeerAPIHandlerForTest creates a peerAPIHandler for testing.
func NewPeerAPIHandlerForTest(ps *PeerAPIServerForTest, remoteAddr netip.AddrPort) *PeerAPIHandlerForTest {
	return &PeerAPIHandlerForTest{h: peerAPIHandler{
		ps:         ps.ps,
		remoteAddr: remoteAddr,
	}}
}

// ReplyToDNSQueries reports whether the handler will serve DNS queries.
func (h *PeerAPIHandlerForTest) ReplyToDNSQueries() bool {
	return h.h.replyToDNSQueries()
}

// HandleDNSQuery serves a DNS query.
func (h *PeerAPIHandlerForTest) HandleDNSQuery(w http.ResponseWriter, r *http.Request) {
	h.h.handleDNSQuery(w, r)
}

// WaitAppConnectorForTest waits for the app connector extension's internal
// queue to finish processing. This is needed because domain and route updates
// are processed asynchronously.
func (b *LocalBackend) WaitAppConnectorForTest(ctx context.Context) {
	ext := b.extHost.FindExtensionByName("appconnectors")
	if ext == nil {
		return
	}
	type waiter interface {
		Wait(context.Context)
	}
	if w, ok := ext.(waiter); ok {
		w.Wait(ctx)
	}
}
