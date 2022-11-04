// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build !linux && !windows && !darwin && !freebsd

package interfaces

import "errors"

var errTODO = errors.New("TODO")

func defaultRoute() (DefaultRouteDetails, error) {
	return DefaultRouteDetails{}, errTODO
}
