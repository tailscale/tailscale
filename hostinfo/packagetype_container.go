// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux && ts_package_container

package hostinfo

func init() {
	linuxBuildTagPackageType = "container"
}
