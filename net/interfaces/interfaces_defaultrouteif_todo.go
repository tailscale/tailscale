// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build !linux

package interfaces

import "errors"

var errTODO = errors.New("TODO")

func DefaultRouteInterface() (string, error) {
	return "TODO", errTODO
}
