// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build windows

package syspolicy

import "tailscale.com/util/syspolicy/source"

func init() {
	newUserStore = func(uid string) (source.Store, error) {
		return source.NewUserPlatformPolicyStoreForSID(uid)
	}
}
