// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package tsnet2

import (
	"context"
	"net"

	"tailscale.com/client/local"
	"tailscale.com/tsnet2/internal/clientsock"
	"tailscale.com/tsnet2/proto"
)

// LocalClient returns a [*local.Client] that speaks to the daemon's
// LocalAPI handler over the Unix socket.
//
// Every existing [local.Client] method (WhoIs, Status, EditPrefs,
// GetServeConfig, SetServeConfig, WatchIPNBus, GetCertificate, …)
// works against the proxied LocalAPI for free, because the client
// speaks plain HTTP over the connection returned by its Dial hook.
//
// Each Dial opens a fresh daemon connection in "localapi" channel mode;
// the daemon then serves a single-conn http.Server.Serve session on
// it. This preserves http.Hijacker and http.Flusher semantics so
// streaming endpoints (watch-ipn-bus, logtap, hijacked /dial) work.
func (s *Server) LocalClient() (*local.Client, error) {
	if err := s.Start(); err != nil {
		return nil, err
	}
	return &local.Client{
		Dial: s.dialLocalAPI,
		// We omit basic-auth (the daemon trusts the unix socket
		// peer; v1 TODO is to add peercred-based auth).
		OmitAuth: true,
	}, nil
}

func (s *Server) dialLocalAPI(ctx context.Context, _, _ string) (net.Conn, error) {
	return clientsock.Dial(ctx, s.SocketPath, proto.ChannelLocalAPI)
}
