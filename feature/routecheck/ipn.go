// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package routecheck

import (
	"tailscale.com/ipn/ipnext"
	"tailscale.com/net/routecheck"
)

// NodeBackender is a shim between [ipnext.Host] and [routecheck.NodeBackender].
type nodeBackender struct{ ipnext.Host }

var _ routecheck.NodeBackender = nodeBackender{}

func (nb nodeBackender) NodeBackend() routecheck.NodeBackend {
	return nb.Host.NodeBackend()
}
