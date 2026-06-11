// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !windows

package ipnlocal

import (
	"errors"

	"tailscale.com/util/syspolicy/source"
)

func newUserPolicyStore(uid string) (source.Store, error) {
	return nil, errors.New("per-user policy stores are not supported on this platform")
}
