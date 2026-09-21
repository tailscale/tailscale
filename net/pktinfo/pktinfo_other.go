// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !linux

package pktinfo

import (
	"errors"
	"net"
	"net/netip"
)

func enable(pc *net.UDPConn) error { return errors.ErrUnsupported }

func dst(oob []byte) netip.Addr { return netip.Addr{} }

func appendSrc(b []byte, src netip.Addr) []byte { return b }
