// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package router

import (
	"sync"

	"tailscale.com/net/dns"
)

// CallbackRouter is an implementation of both Router and dns.OSConfigurator.
// When either network or DNS settings are changed, SetBoth is called with both configs.
// Mainly used as a shim for OSes that want to set both network and
// DNS configuration simultaneously (iOS, android).
type CallbackRouter struct {
	SetBoth  func(rcfg *Config, dcfg *dns.OSConfig) error
	SplitDNS bool

	mu   sync.Mutex    // protects all the following
	rcfg *Config       // last applied router config
	dcfg *dns.OSConfig // last applied DNS config
}

// Up implements Router.
func (r *CallbackRouter) Up() error {
	return nil // TODO: check that all callers have no need for initialization
}

// Set implements Router.
func (r *CallbackRouter) Set(rcfg *Config) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.rcfg = rcfg
	return r.SetBoth(r.rcfg, r.dcfg)
}

// SetDNS implements dns.OSConfigurator.
func (r *CallbackRouter) SetDNS(dcfg dns.OSConfig) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.dcfg = &dcfg
	return r.SetBoth(r.rcfg, r.dcfg)
}

// SupportsSplitDNS implements dns.OSConfigurator.
func (r *CallbackRouter) SupportsSplitDNS() bool {
	return r.SplitDNS
}

func (r *CallbackRouter) GetBaseConfig() (dns.OSConfig, error) {
	return dns.OSConfig{}, dns.ErrGetBaseConfigNotSupported
}

func (r *CallbackRouter) Close() error {
	return r.SetBoth(nil, nil) // TODO: check if makes sense
}
