// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package tsnet2

import (
	"tailscale.com/client/local"
)

// LocalClient returns a [*local.Client] that speaks to the daemon's
// LocalAPI handler over the Unix socket.
//
// It will start the server if it has not been started yet.
//
// Every existing [local.Client] method (WhoIs, Status, EditPrefs,
// GetServeConfig, SetServeConfig, WatchIPNBus, GetCertificate, …)
// works against the proxied LocalAPI for free, because the client
// speaks plain HTTP over the connection returned by its Dial hook.
func (s *Server) LocalClient() (*local.Client, error) {
	return nil, errNotImplemented
}
