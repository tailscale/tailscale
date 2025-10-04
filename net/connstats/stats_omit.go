// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build ts_omit_connstats

package connstats

import (
	"context"
	"net/netip"
	"time"
)

type Statistics struct{}

func NewStatistics(maxPeriod time.Duration, maxConns int, dump func(start, end time.Time, virtual, physical any)) *Statistics {
	return &Statistics{}
}

func (s *Statistics) UpdateTxVirtual(b []byte)                                                {}
func (s *Statistics) UpdateRxVirtual(b []byte)                                                {}
func (s *Statistics) UpdateTxPhysical(src netip.Addr, dst netip.AddrPort, packets, bytes int) {}
func (s *Statistics) UpdateRxPhysical(src netip.Addr, dst netip.AddrPort, packets, bytes int) {}
func (s *Statistics) Shutdown(context.Context) error                                          { return nil }
