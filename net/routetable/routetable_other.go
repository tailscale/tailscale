// Copyright (c) 2022 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

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
