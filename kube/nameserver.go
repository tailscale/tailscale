// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package kube

type DNSConfig struct {
	Hosts map[string]string `json:"hosts"`
}
