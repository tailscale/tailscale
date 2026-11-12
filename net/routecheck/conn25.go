// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package routecheck

import (
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/tailcfg"
	"tailscale.com/tailcfg/nodecap"
)

// connectorApps returns the conn25 app names that nv serves as a connector.
// It returns a nil slice if nv is not a conn25 connector.
func connectorApps(nv tailcfg.NodeView) ([]string, error) {
	return tailcfg.UnmarshalNodeCapViewJSON[string](nv.CapMap(), nodecap.Conn25Connector)
}

// IsConn25Connector reports whether nv advertises itself as a conn25 connector.
func IsConn25Connector(nv tailcfg.NodeView) bool {
	return nv.HasCap(nodecap.Conn25Connector)
}

// PeerStatusIsConn25Connector reports whether ps describes a conn25 connector.
// It is the [ipnstate.PeerStatus] analogue of [IsConn25Connector].
func PeerStatusIsConn25Connector(ps *ipnstate.PeerStatus) bool {
	return ps != nil && ps.HasCap(nodecap.Conn25Connector)
}
