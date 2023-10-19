// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:generate go run tailscale.com/cmd/cloner  -clonefunc=true -type SliceContainer

package clonerex

type SliceContainer struct {
	Slice []*int
}
