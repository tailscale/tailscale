// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !linux

package xdp

import "net/netip"

type noopFIB struct{}

func (noopFIB) Delete(vni uint32) error                                 { return nil }
func (noopFIB) Upsert(vni uint32, participants [2]netip.AddrPort) error { return nil }
func (noopFIB) Close(vni uint32, participants [2]netip.AddrPort) error  { return nil }

func NewFIB(config FIBConfig, opts ...FIBOption) (FIB, error) {
	return noopFIB{}
}
