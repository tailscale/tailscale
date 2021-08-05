// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build linux || windows
// +build linux windows

package router

import "inet.af/netaddr"

func mustCIDRs(ss ...string) []netaddr.IPPrefix {
	var ret []netaddr.IPPrefix
	for _, s := range ss {
		ret = append(ret, netaddr.MustParseIPPrefix(s))
	}
	return ret
}
