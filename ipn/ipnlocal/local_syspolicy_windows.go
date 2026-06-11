// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build windows

package ipnlocal

import "tailscale.com/util/syspolicy/source"

func newUserPolicyStore(uid string) (source.Store, error) {
	return source.NewUserPlatformPolicyStoreForSID(uid)
}
