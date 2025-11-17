// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package localclient provides an interface for all the local.Client methods
// kube needs to use, so that we can easily mock it in tests.
package localclient

import (
	"context"
	"io"

	"tailscale.com/client/local"
	"tailscale.com/ipn"
)

// LocalClient is roughly a subset of the local.Client struct's methods, used
// for easier testing.
type LocalClient interface {
	WatchIPNBus(ctx context.Context, mask ipn.NotifyWatchOpt) (IPNBusWatcher, error)
	CertIssuer
}

// IPNBusWatcher is local.IPNBusWatcher's methods restated in an interface to
// allow for easier mocking in tests.
type IPNBusWatcher interface {
	io.Closer
	Next() (ipn.Notify, error)
}

type CertIssuer interface {
	CertPair(context.Context, string) ([]byte, []byte, error)
}

// New returns a LocalClient that wraps the provided local.Client.
func New(lc *local.Client) LocalClient {
	return &localClient{lc: lc}
}

type localClient struct {
	lc *local.Client
}

func (lc *localClient) WatchIPNBus(ctx context.Context, mask ipn.NotifyWatchOpt) (IPNBusWatcher, error) {
	return lc.lc.WatchIPNBus(ctx, mask)
}

func (lc *localClient) CertPair(ctx context.Context, domain string) ([]byte, []byte, error) {
	return lc.lc.CertPair(ctx, domain)
}
