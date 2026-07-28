// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// Package ipnlocaltest provides test helpers for constructing a
// [*ipnlocal.LocalBackend] from external test packages that cannot
// access ipnlocal's internal test helpers.
package ipnlocaltest

import (
	"testing"

	"tailscale.com/ipn/ipnlocal"
	"tailscale.com/ipn/store/mem"
	"tailscale.com/net/netmon"
	"tailscale.com/net/tsdial"
	"tailscale.com/tsd"
	"tailscale.com/types/logger"
	"tailscale.com/types/logid"
	"tailscale.com/util/eventbus/eventbustest"
	"tailscale.com/util/testenv"
	"tailscale.com/wgengine"
)

// NewBackend creates a new [*ipnlocal.LocalBackend] suitable for tests,
// using an in-memory state store, a fake userspace engine, and a static
// network monitor. Shutdown is registered as a t.Cleanup.
func NewBackend(t testing.TB) *ipnlocal.LocalBackend {
	testenv.AssertInTest()
	bus := eventbustest.NewBus(t)
	return NewBackendWithSys(t, tsd.NewSystemWithBus(bus))
}

// NewBackendWithSys creates a new [*ipnlocal.LocalBackend] with the
// given [*tsd.System]. Missing components in sys (state store, engine,
// dialer) are filled in with test fakes.
func NewBackendWithSys(t testing.TB, sys *tsd.System) *ipnlocal.LocalBackend {
	testenv.AssertInTest()
	var logf logger.Logf = logger.Discard
	if _, ok := sys.StateStore.GetOK(); !ok {
		sys.Set(new(mem.Store))
		t.Log("Added memory store for testing")
	}
	if _, ok := sys.Engine.GetOK(); !ok {
		eng, err := wgengine.NewFakeUserspaceEngine(logf, sys.Set, sys.HealthTracker.Get(), sys.UserMetricsRegistry(), sys.Bus.Get())
		if err != nil {
			t.Fatalf("NewFakeUserspaceEngine: %v", err)
		}
		t.Cleanup(eng.Close)
		sys.Set(eng)
		t.Log("Added fake userspace engine for testing")
	}
	if _, ok := sys.Dialer.GetOK(); !ok {
		dialer := tsdial.NewDialer(netmon.NewStatic())
		dialer.SetBus(sys.Bus.Get())
		sys.Set(dialer)
		t.Log("Added static dialer for testing")
	}
	lb, err := ipnlocal.NewLocalBackend(logf, logid.PublicID{}, sys, 0)
	if err != nil {
		t.Fatalf("NewLocalBackend: %v", err)
	}
	t.Cleanup(lb.Shutdown)
	return lb
}
