// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build !ios

package derphttp

import "golang.org/x/net/proxy"

func init() {
	wrapDialer = wrapSocks
}

func wrapSocks(d dialer) dialer {
	if cd, ok := proxy.FromEnvironmentUsing(d).(dialer); ok {
		return cd
	}
	return d
}
