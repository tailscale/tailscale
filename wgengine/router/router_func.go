// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package router

// FuncRouter is a Router to the functions it embeds.
// It is useful, for example, to pass configs into ipn-go-bridge on macOS/iOS.
type FuncRouter struct {
	// UpFunc, if specified, brings the routes up.
	// If nil, Up successfully does nothing.
	UpFunc func() error
	// DownFunc, if specified, brings the routes down.
	// If nil, Down successfully does nothing.
	DownFunc func() error
	// SetFunc, if specified, applies the given configuration.
	// If nil, Set successfully does nothing.
	SetFunc func(*Config) error
}

func (r FuncRouter) Up() error {
	if r.UpFunc == nil {
		return nil
	}
	return r.UpFunc()
}

func (r FuncRouter) Set(cfg *Config) error {
	if r.SetFunc == nil {
		return nil
	}
	if cfg == nil {
		cfg = &shutdownConfig
	}
	return r.SetFunc(cfg)
}

func (r FuncRouter) Close() error {
	if r.SetFunc != nil {
		if err := r.SetFunc(&shutdownConfig); err != nil {
			return err
		}
	}

	if r.DownFunc == nil {
		return nil
	}
	return r.DownFunc()
}
