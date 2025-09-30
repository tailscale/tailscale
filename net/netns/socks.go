// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ios && !js && !android && !ts_omit_useproxy

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
