// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build ios || ts_omit_gro

package gro

import (
	"runtime"

	"tailscale.com/net/packet"
)

type GRO struct{}

func NewGRO() *GRO {
	if runtime.GOOS == "ios" {
		panic("unsupported on iOS")
	}
	panic("GRO disabled in build")

}

func (g *GRO) SetDispatcher(any) {}

func (g *GRO) Enqueue(_ *packet.Parsed) {}

func (g *GRO) Flush() {}
