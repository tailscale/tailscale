// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package resolver

import (
	"errors"
	"syscall"
)

// Avoid allocation when calling errors.Is below
// by converting syscall.Errno to error here.
var (
	networkDown        error = syscall.ENETDOWN
	networkUnreachable error = syscall.ENETUNREACH
)

func networkIsDown(err error) bool {
	return errors.Is(err, networkDown)
}

func networkIsUnreachable(err error) bool {
	return errors.Is(err, networkUnreachable)
}
