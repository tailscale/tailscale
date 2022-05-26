// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build !ios && !js
// +build !ios,!js

package netns

import "golang.org/x/net/proxy"

func init() {
	wrapDialer = wrapSocks
}

func wrapSocks(d Dialer) Dialer {
	if cd, ok := proxy.FromEnvironmentUsing(d).(Dialer); ok {
		return cd
	}
	return d
}
