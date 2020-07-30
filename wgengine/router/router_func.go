// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package router

import (
	"tailscale.com/types/logger"
)

// setRoutesFunc applies the given router settings to the OS network stack.
type setRoutesFunc func(cfg *Config) error

// funcRouter passes the configs it receives to setRoutesFunc.
// It is useful, for example, to pass configs into ipn-go-bridge on macOS/iOS.
type funcRouter struct {
	setRoutesFunc setRoutesFunc
}

// NewFuncRouter returns a Router which passes the configs it receives to setRoutesFunc.
func NewFuncRouter(logf logger.Logf, setRoutesFunc setRoutesFunc) (Router, error) {
	return funcRouter{
		setRoutesFunc: setRoutesFunc,
	}, nil
}

func (funcRouter) Up() error {
	// Bringing up the routes is handled externally.
	return nil
}

func (r funcRouter) Set(cfg *Config) error {
	if cfg == nil {
		cfg = &shutdownConfig
	}
	return r.setRoutesFunc(cfg)
}

func (r funcRouter) Close() error {
	return r.setRoutesFunc(&shutdownConfig)
}
