// Copyright (c) 2022 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build linux
// +build linux

package tshttpproxy

import (
	"net/http"
	"net/url"

	"tailscale.com/version/distro"
)

func init() {
	sysProxyFromEnv = linuxSysProxyFromEnv
}

func linuxSysProxyFromEnv(req *http.Request) (*url.URL, error) {
	if distro.Get() == distro.Synology {
		return synologyProxyFromConfigCached(req)
	}
	return nil, nil
}
