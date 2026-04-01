// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ts_omit_routecheck

package routecheck

import (
	"tailscale.com/ipn/ipnext"
	"tailscale.com/ipn/ipnlocal"
	"tailscale.com/ipn/routecheck"
)

// DefaultTimeout is the default time allowed for a response before a peer is considered unreachable.
const DefaultTimeout = routecheck.DefaultTimeout

// Client generates Reports describing the result of both passive and active
// reachability probing.
type Client = routecheck.Client

// ClientFor returns the [routecheck.Client] for a given backend,
// or nil if route checking is not available for that backend.
func ClientFor(b *ipnlocal.LocalBackend) *Client {
	e, ok := ipnlocal.GetExt[*Extension](b)
	if e == nil || !ok {
		return nil
	}
	return e.Client
}

// Report contains the result of a single routecheck.
type Report = routecheck.Report

// NodeBackender is a shim between [ipnext.Host] and [routecheck.NodeBackender].
type nodeBackender struct{ ipnext.Host }

var _ routecheck.NodeBackender = nodeBackender{}

func (nb nodeBackender) NodeBackend() routecheck.NodeBackend {
	return nb.Host.NodeBackend()
}
