// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package groupmemeber verifies group membership of the provided user on the
// local system.
package groupmember

import (
	"errors"
	"runtime"
)

var ErrNotImplemented = errors.New("not implemented for GOOS=" + runtime.GOOS)

// IsMemberOfGroup verifies if the provided user is member of the provided
// system group.
// If verfication fails, an error is returned.
func IsMemberOfGroup(group, userName string) (bool, error) {
	return isMemberOfGroup(group, userName)
}
