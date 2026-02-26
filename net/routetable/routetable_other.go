// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build android || (!linux && !darwin && !freebsd && !openbsd)

package routetable

import (
	"errors"
	"runtime"
)

var errUnsupported = errors.New("cannot get route table on platform " + runtime.GOOS)

func Get(max int) ([]RouteEntry, error) {
	return nil, errUnsupported
}
