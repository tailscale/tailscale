// Copyright (c) 2022 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

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
