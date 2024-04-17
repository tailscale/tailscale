// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package router

import (
	"sync"

	"tailscale.com/net/dns"
)

// CallbackRouter is an implementation of both Router and dns.OSConfigurator.
// When either network or DNS settings are changed, SetBoth is called with both configs.
// Mainly used as a shim for OSes that want to set both network and
// DNS configuration simultaneously (Mac, iOS, Android).
type CallbackRouter struct {
	SetBoth  func(rcfg *Config, dcfg *dns.OSConfig) error
	SplitDNS bool

	// GetBaseConfigFunc optionally specifies a function to return the current DNS
	// config in response to GetBaseConfig.
	//
	// If nil, reading the current config isn't supported and GetBaseConfig()
	// will return ErrGetBaseConfigNotSupported.
	GetBaseConfigFunc func() (dns.OSConfig, error)

	// InitialMTU is the MTU the tun should be initialized with.
	// Zero means don't change the MTU from the default. This MTU
	// is applied only once, shortly after the TUN is created, and
	// ignored thereafter.
	InitialMTU uint32

	mu        sync.Mutex    // protects all the following
	didSetMTU bool          // if we set the MTU already
	rcfg      *Config       // last applied router config
	dcfg      *dns.OSConfig // last applied DNS config
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
	return r.SetBoth(r.rcfg, r.dcfg)
}

// UpdateMagicsockPort implements the Router interface. This implementation
// does nothing and returns nil because this router does not currently need
// to know what the magicsock UDP port is.
func (r *CallbackRouter) UpdateMagicsockPort(_ uint16, _ string) error {
	return nil
}

// SetDNS implements dns.OSConfigurator.
func (r *CallbackRouter) SetDNS(dcfg dns.OSConfig) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.dcfg != nil && r.dcfg.Equal(dcfg) {
		return nil
	}
	r.dcfg = &dcfg
	return r.SetBoth(r.rcfg, r.dcfg)
}

// SupportsSplitDNS implements dns.OSConfigurator.
func (r *CallbackRouter) SupportsSplitDNS() bool {
	return r.SplitDNS
}

func (r *CallbackRouter) GetBaseConfig() (dns.OSConfig, error) {
	if r.GetBaseConfigFunc == nil {
		return dns.OSConfig{}, dns.ErrGetBaseConfigNotSupported
	}
	return r.GetBaseConfigFunc()
}

func (r *CallbackRouter) Close() error {
	return r.SetBoth(nil, nil) // TODO: check if makes sense
}
