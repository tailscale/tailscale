// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build js

package wgengine

import "tailscale.com/net/dns/resolver"

type watchdogEngine struct {
	Engine
	wrap Engine
}

func (e *watchdogEngine) GetResolver() (r *resolver.Resolver, ok bool) {
	return nil, false
}
