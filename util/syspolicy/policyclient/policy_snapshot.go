// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ts_omit_syspolicy

package policyclient

import "tailscale.com/util/syspolicy/setting"

// PolicySnapshot is an alias for [settings.Snapshot] unless syspolicy is omitted
// from the build.
type policySnapshot = setting.Snapshot
