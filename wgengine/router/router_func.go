// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package router

import (
	"tailscale.com/types/logger"
)

// RoutingFuncs are functions implementing a routing configuration interface.
type RoutingFuncs struct {
	// Up brings the routes up.
	Up func() error
	// Down brings the routes down.
	Down func() error
	// Set applies the supplied config.
	Set func(*Config) error
}

// funcRouter delegates to the RoutingFuncs it embeds.
// It is useful, for example, to pass configs into ipn-go-bridge on macOS/iOS.
type funcRouter struct {
	funcs RoutingFuncs
}

// NewFuncRouter returns a Router which delegates to the supplied RoutingFuncs.
func NewFuncRouter(logf logger.Logf, funcs RoutingFuncs) (Router, error) {
	return funcRouter{funcs: funcs}, nil
}

func (r funcRouter) Up() error {
	if r.funcs.Up == nil {
		return nil
	}
	return r.funcs.Up()
}

func (r funcRouter) Set(cfg *Config) error {
	if r.funcs.Set == nil {
		return nil
	}
	if cfg == nil {
		cfg = &shutdownConfig
	}
	return r.funcs.Set(cfg)
}

func (r funcRouter) Close() error {
	if r.funcs.Set != nil {
		if err := r.funcs.Set(&shutdownConfig); err != nil {
			return err
		}
	}

	if r.funcs.Down == nil {
		return nil
	}
	return r.funcs.Down()
}
