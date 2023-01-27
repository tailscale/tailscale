// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !linux && !darwin && !freebsd

package routetable

import (
	"errors"
	"runtime"
)

var errUnsupported = errors.New("cannot get route table on platform " + runtime.GOOS)

func Get(max int) ([]RouteEntry, error) {
	return nil, errUnsupported
}
