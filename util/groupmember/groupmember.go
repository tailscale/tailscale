// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package groupmember verifies group membership of the provided user on the
// local system.
package groupmember

import (
	"errors"
	"runtime"
)

var ErrNotImplemented = errors.New("not implemented for GOOS=" + runtime.GOOS)

// IsMemberOfGroup reports whether the provided user is a member of
// the provided system group.
func IsMemberOfGroup(group, userName string) (bool, error) {
	return isMemberOfGroup(group, userName)
}
