// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package router

import (
	"sync"
)

// CallbackRouter is an implementation of both Router and dns.OSConfigurator.
// When either network or DNS settings are changed, SetBoth is called with both configs.
// Mainly used as a shim for OSes that want to set both network and
// DNS configuration simultaneously (Mac, iOS, Android).
type CallbackRouter struct {
	SetBoth  func(rcfg *Config) error
	SplitDNS bool

	// InitialMTU is the MTU the tun should be initialized with.
	// Zero means don't change the MTU from the default. This MTU
	// is applied only once, shortly after the TUN is created, and
	// ignored thereafter.
	InitialMTU uint32

	mu        sync.Mutex // protects all the following
	didSetMTU bool       // if we set the MTU already
	rcfg      *Config    // last applied router config
}

// Up implements Router.
func (r *CallbackRouter) Up() error {
	return nil // TODO: check that all callers have no need for initialization
}

// Set implements Router.
func (r *CallbackRouter) Set(rcfg *Config) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.rcfg.Equal(rcfg) {
		return nil
	}
	if r.didSetMTU == false {
		r.didSetMTU = true
		rcfg.NewMTU = int(r.InitialMTU)
	}
	r.rcfg = rcfg
	return r.SetBoth(r.rcfg)
}

// UpdateMagicsockPort implements the Router interface. This implementation
// does nothing and returns nil because this router does not currently need
// to know what the magicsock UDP port is.
func (r *CallbackRouter) UpdateMagicsockPort(_ uint16, _ string) error {
	return nil
}

// SupportsSplitDNS implements dns.OSConfigurator.
func (r *CallbackRouter) SupportsSplitDNS() bool {
	return r.SplitDNS
}

func (r *CallbackRouter) Close() error {
	return r.SetBoth(nil) // TODO: check if makes sense
}
