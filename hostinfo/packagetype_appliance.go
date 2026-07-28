// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux && ts_appliance

package hostinfo

func init() {
	linuxBuildTagPackageType = "tsapp"
}
