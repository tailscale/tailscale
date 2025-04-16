// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package ipnserver

import (
	"context"
	"net/http"

	"tailscale.com/ipn/ipnauth"
)

// BlockWhileInUseByOtherForTest blocks while the actor can't connect to the server because
// the server is in use by a different actor. It is used in tests only.
func (s *Server) BlockWhileInUseByOtherForTest(ctx context.Context, actor ipnauth.Actor) error {
	return s.blockWhileIdentityInUse(ctx, actor)
}

// BlockWhileInUseForTest blocks until the server becomes idle (no active requests),
// or the specified context is done. It returns the context's error if it is done.
// It is used in tests only.
func (s *Server) BlockWhileInUseForTest(ctx context.Context) error {
	ready, cleanup := s.zeroReqWaiter.add(&s.mu, ctx)

	s.mu.Lock()
	busy := len(s.activeReqs) != 0
	s.mu.Unlock()

	if busy {
		<-ready
	}
	cleanup()
	return ctx.Err()
}

// ServeHTTPForTest responds to a single LocalAPI HTTP request.
// The request's context carries the actor that made the request
// and can be created with [NewContextWithActorForTest].
// It is used in tests only.
func (s *Server) ServeHTTPForTest(w http.ResponseWriter, r *http.Request) {
	s.serveHTTP(w, r)
}
