// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package lapitest

import (
	"testing"

	"tailscale.com/control/controlclient"
	"tailscale.com/ipn/ipnlocal"
	"tailscale.com/ipn/store/mem"
	"tailscale.com/types/logid"
	"tailscale.com/wgengine"
)

// NewBackend returns a new [ipnlocal.LocalBackend] for testing purposes.
// It fails the test if the specified options are invalid or if the backend cannot be created.
func NewBackend(tb testing.TB, opts ...Option) *ipnlocal.LocalBackend {
	tb.Helper()
	options, err := newOptions(tb, opts...)
	if err != nil {
		tb.Fatalf("NewBackend: %v", err)
	}
	return newBackend(options)
}

func newBackend(opts *options) *ipnlocal.LocalBackend {
	tb := opts.TB()
	tb.Helper()

	sys := opts.Sys()
	if _, ok := sys.StateStore.GetOK(); !ok {
		sys.Set(&mem.Store{})
	}

	e, err := wgengine.NewFakeUserspaceEngine(opts.Logf(), sys.Set, sys.HealthTracker.Get(), sys.UserMetricsRegistry(), sys.Bus.Get())
	if err != nil {
		opts.tb.Fatalf("NewFakeUserspaceEngine: %v", err)
	}
	tb.Cleanup(e.Close)
	sys.Set(e)

	b, err := ipnlocal.NewLocalBackend(opts.Logf(), logid.PublicID{}, sys, 0)
	if err != nil {
		tb.Fatalf("NewLocalBackend: %v", err)
	}
	tb.Cleanup(b.Shutdown)
	b.SetControlClientGetterForTesting(opts.MakeControlClient)
	return b
}

// NewUnreachableControlClient is a [NewControlFn] that creates
// a new [controlclient.Client] for an unreachable control server.
func NewUnreachableControlClient(tb testing.TB, opts controlclient.Options) (controlclient.Client, error) {
	tb.Helper()
	opts.ServerURL = "https://127.0.0.1:1"
	cc, err := controlclient.New(opts)
	if err != nil {
		tb.Fatal(err)
	}
	return cc, nil
}
