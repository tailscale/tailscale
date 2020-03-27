// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ipn

import (
	"sync"
	"time"

	"github.com/tailscale/wireguard-go/wgcfg"
	"tailscale.com/types/logger"
)

type Handle struct {
	frontendLogID string
	b             Backend
	xnotify       func(Notify)
	logf          logger.Logf

	// Mutex protects everything below
	mu                sync.Mutex
	netmapCache       *NetworkMap
	engineStatusCache EngineStatus
	stateCache        State
	prefsCache        *Prefs
}

func NewHandle(b Backend, logf logger.Logf, opts Options) (*Handle, error) {
	h := &Handle{
		b:    b,
		logf: logf,
	}

	err := h.Start(opts)
	if err != nil {
		return nil, err
	}

	return h, nil
}

func (h *Handle) Start(opts Options) error {
	h.frontendLogID = opts.FrontendLogID
	h.xnotify = opts.Notify
	h.netmapCache = nil
	h.engineStatusCache = EngineStatus{}
	h.stateCache = NoState
	if opts.Prefs != nil {
		h.prefsCache = opts.Prefs.Clone()
	}
	xopts := opts
	xopts.Notify = h.notify
	return h.b.Start(xopts)
}

func (h *Handle) Reset() {
	st := NoState
	h.notify(Notify{State: &st})
}

func (h *Handle) notify(n Notify) {
	h.mu.Lock()
	if n.BackendLogID != nil {
		h.logf("Handle: logs: be:%v fe:%v\n",
			*n.BackendLogID, h.frontendLogID)
	}
	if n.State != nil {
		h.stateCache = *n.State
	}
	if n.Prefs != nil {
		h.prefsCache = n.Prefs.Clone()
	}
	if n.NetMap != nil {
		h.netmapCache = n.NetMap
	}
	if n.Engine != nil {
		h.engineStatusCache = *n.Engine
	}
	h.mu.Unlock()

	if h.xnotify != nil {
		// Forward onward to our parent's notifier
		h.xnotify(n)
	}
}

func (h *Handle) Prefs() *Prefs {
	h.mu.Lock()
	defer h.mu.Unlock()

	return h.prefsCache.Clone()
}

func (h *Handle) UpdatePrefs(updateFn func(p *Prefs)) {
	h.mu.Lock()
	defer h.mu.Unlock()

	new := h.prefsCache.Clone()
	updateFn(new)
	h.prefsCache = new
	h.b.SetPrefs(new)
}

func (h *Handle) State() State {
	h.mu.Lock()
	defer h.mu.Unlock()

	return h.stateCache
}

func (h *Handle) EngineStatus() EngineStatus {
	h.mu.Lock()
	defer h.mu.Unlock()

	return h.engineStatusCache
}

func (h *Handle) LocalAddrs() []wgcfg.CIDR {
	h.mu.Lock()
	defer h.mu.Unlock()

	nm := h.netmapCache
	if nm != nil {
		return nm.Addresses
	}
	return []wgcfg.CIDR{}
}

func (h *Handle) NetMap() *NetworkMap {
	h.mu.Lock()
	defer h.mu.Unlock()

	return h.netmapCache
}

func (h *Handle) Expiry() time.Time {
	h.mu.Lock()
	defer h.mu.Unlock()

	nm := h.netmapCache
	if nm != nil {
		return nm.Expiry
	}
	return time.Time{}
}

func (h *Handle) AdminPageURL() string {
	return h.prefsCache.ControlURL + "/admin/machines"
}

func (h *Handle) StartLoginInteractive() {
	h.b.StartLoginInteractive()
}

func (h *Handle) Logout() {
	h.b.Logout()
}

func (h *Handle) RequestEngineStatus() {
	h.b.RequestEngineStatus()
}

func (h *Handle) RequestStatus() {
	h.b.RequestStatus()
}

func (h *Handle) FakeExpireAfter(x time.Duration) {
	h.b.FakeExpireAfter(x)
}
