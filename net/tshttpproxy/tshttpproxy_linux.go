// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux

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
