// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build gokrazy

package dns

const (
	resolvConf = "/tmp/resolv.conf"
	backupConf = "/tmp/resolv.pre-tailscale-backup.conf"
)
