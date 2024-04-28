// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !linux && !windows && !darwin && !freebsd && !android

package netmon

import "errors"

var errTODO = errors.New("TODO")

func defaultRoute() (DefaultRouteDetails, error) {
	return DefaultRouteDetails{}, errTODO
}
