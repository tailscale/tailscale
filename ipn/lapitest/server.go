// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package lapitest provides utilities for black-box testing of LocalAPI ([ipnserver]).
package lapitest

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"tailscale.com/client/local"
	"tailscale.com/client/tailscale/apitype"
	"tailscale.com/envknob"
	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnauth"
	"tailscale.com/ipn/ipnlocal"
	"tailscale.com/ipn/ipnserver"
	"tailscale.com/types/logger"
	"tailscale.com/types/logid"
	"tailscale.com/types/ptr"
	"tailscale.com/util/mak"
	"tailscale.com/util/rands"
)

// A Server is an in-process LocalAPI server that can be used in end-to-end tests.
type Server struct {
	tb testing.TB

	ctx       context.Context
	cancelCtx context.CancelFunc

	lb        *ipnlocal.LocalBackend
	ipnServer *ipnserver.Server

	// mu protects the following fields.
	mu           sync.Mutex
	started      bool
	httpServer   *httptest.Server
	actorsByName map[string]*ipnauth.TestActor
	lastClientID int
}

// NewUnstartedServer returns a new [Server] with the specified options without starting it.
func NewUnstartedServer(tb testing.TB, opts ...Option) *Server {
	tb.Helper()
	options, err := newOptions(tb, opts...)
	if err != nil {
		tb.Fatalf("invalid options: %v", err)
	}

	s := &Server{tb: tb, lb: options.Backend()}
	s.ctx, s.cancelCtx = context.WithCancel(options.Context())
	s.ipnServer = newUnstartedIPNServer(options)
	s.httpServer = httptest.NewUnstartedServer(http.HandlerFunc(s.serveHTTP))
	s.httpServer.Config.Addr = "http://" + apitype.LocalAPIHost
	s.httpServer.Config.BaseContext = func(_ net.Listener) context.Context { return s.ctx }
	s.httpServer.Config.ErrorLog = logger.StdLogger(logger.WithPrefix(options.Logf(), "lapitest: "))
	tb.Cleanup(s.Close)
	return s
}

// NewServer starts and returns a new [Server] with the specified options.
func NewServer(tb testing.TB, opts ...Option) *Server {
	tb.Helper()
	server := NewUnstartedServer(tb, opts...)
	server.Start()
	return server
}

// Start starts the server from [NewUnstartedServer].
func (s *Server) Start() {
	s.tb.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.started && s.httpServer != nil {
		s.httpServer.Start()
		s.started = true
	}
}

// Backend returns the underlying [ipnlocal.LocalBackend].
func (s *Server) Backend() *ipnlocal.LocalBackend {
	s.tb.Helper()
	return s.lb
}

// Client returns a new [Client] configured for making requests to the server
// as a new [ipnauth.TestActor] with a unique username and [ipnauth.ClientID].
func (s *Server) Client() *Client {
	s.tb.Helper()
	user := s.MakeTestActor("", "") // generate a unique username and client ID
	return s.ClientFor(user)
}

// ClientWithName returns a new [Client] configured for making requests to the server
// as a new [ipnauth.TestActor] with the specified name and a unique [ipnauth.ClientID].
func (s *Server) ClientWithName(name string) *Client {
	s.tb.Helper()
	user := s.MakeTestActor(name, "") // generate a unique client ID
	return s.ClientFor(user)
}

// ClientFor returns a new [Client] configured for making requests to the server
// as the specified actor.
func (s *Server) ClientFor(actor ipnauth.Actor) *Client {
	s.tb.Helper()
	client := &Client{
		tb:    s.tb,
		Actor: actor,
	}
	client.Client = &local.Client{Transport: newRoundTripper(client, s.httpServer)}
	return client
}

// MakeTestActor returns a new [ipnauth.TestActor] with the specified name and client ID.
// If the name is empty, a unique sequential name is generated. Likewise,
// if clientID is empty, a unique sequential client ID is generated.
func (s *Server) MakeTestActor(name string, clientID string) *ipnauth.TestActor {
	s.tb.Helper()

	s.mu.Lock()
	defer s.mu.Unlock()

	// Generate a unique sequential name if the provided name is empty.
	if name == "" {
		n := len(s.actorsByName)
		name = generateSequentialName("User", n)
	}

	if clientID == "" {
		s.lastClientID += 1
		clientID = fmt.Sprintf("Client-%d", s.lastClientID)
	}

	// Create a new base actor if one doesn't already exist for the given name.
	baseActor := s.actorsByName[name]
	if baseActor == nil {
		baseActor = &ipnauth.TestActor{Name: name}
		if envknob.GOOS() == "windows" {
			// Historically, as of 2025-04-15, IPN does not distinguish between
			// different users on non-Windows devices. Therefore, the UID, which is
			// an [ipn.WindowsUserID], should only be populated when the actual or
			// fake GOOS is Windows.
			baseActor.UID = ipn.WindowsUserID(fmt.Sprintf("S-1-5-21-1-0-0-%d", 1001+len(s.actorsByName)))
		}
		mak.Set(&s.actorsByName, name, baseActor)
		s.tb.Cleanup(func() { delete(s.actorsByName, name) })
	}

	// Create a shallow copy of the base actor and assign it the new client ID.
	actor := ptr.To(*baseActor)
	actor.CID = ipnauth.ClientIDFrom(clientID)
	return actor
}

// BlockWhileInUse blocks until the server becomes idle (no active requests),
// or the context is done. It returns the context's error if it is done.
// It is used in tests only.
func (s *Server) BlockWhileInUse(ctx context.Context) error {
	s.tb.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.httpServer == nil {
		return nil
	}
	return s.ipnServer.BlockWhileInUseForTest(ctx)
}

// BlockWhileInUseByOther blocks while the specified actor can't connect to the server
// due to another actor being connected.
// It is used in tests only.
func (s *Server) BlockWhileInUseByOther(ctx context.Context, actor ipnauth.Actor) error {
	s.tb.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.httpServer == nil {
		return nil
	}
	return s.ipnServer.BlockWhileInUseByOtherForTest(ctx, actor)
}

// CheckCurrentUser fails the test if the current user does not match the expected user.
// It is only used on Windows and will be removed as we progress on tailscale/corp#18342.
func (s *Server) CheckCurrentUser(want ipnauth.Actor) {
	s.tb.Helper()
	var wantUID ipn.WindowsUserID
	if want != nil {
		wantUID = want.UserID()
	}
	lb := s.Backend()
	if lb == nil {
		s.tb.Fatalf("Backend: nil")
	}
	gotUID, gotActor := lb.CurrentUserForTest()
	if gotUID != wantUID {
		s.tb.Errorf("CurrentUser: got UID %q; want %q", gotUID, wantUID)
	}
	if hasActor := gotActor != nil; hasActor != (want != nil) || (want != nil && gotActor != want) {
		s.tb.Errorf("CurrentUser: got %v; want %v", gotActor, want)
	}
}

func (s *Server) serveHTTP(w http.ResponseWriter, r *http.Request) {
	actor, err := getActorForRequest(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		s.tb.Errorf("getActorForRequest: %v", err)
		return
	}
	ctx := ipnserver.NewContextWithActorForTest(r.Context(), actor)
	s.ipnServer.ServeHTTPForTest(w, r.Clone(ctx))
}

// Close shuts down the server and blocks until all outstanding requests on this server have completed.
func (s *Server) Close() {
	s.tb.Helper()
	s.mu.Lock()
	server := s.httpServer
	s.httpServer = nil
	s.mu.Unlock()

	if server != nil {
		server.Close()
	}
	s.cancelCtx()
}

// newUnstartedIPNServer returns a new [ipnserver.Server] that exposes
// the specified [ipnlocal.LocalBackend] via LocalAPI, but does not start it.
// The opts carry additional configuration options.
func newUnstartedIPNServer(opts *options) *ipnserver.Server {
	opts.TB().Helper()
	lb := opts.Backend()
	server := ipnserver.New(opts.Logf(), logid.PublicID{}, lb.EventBus(), lb.NetMon())
	server.SetLocalBackend(lb)
	return server
}

// roundTripper is a [http.RoundTripper] that sends requests to a [Server]
// on behalf of the [Client] who owns it.
type roundTripper struct {
	client    *Client
	transport http.RoundTripper
}

// newRoundTripper returns a new [http.RoundTripper] that sends requests
// to the specified server as the specified client.
func newRoundTripper(client *Client, server *httptest.Server) http.RoundTripper {
	return &roundTripper{
		client: client,
		transport: &http.Transport{DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			var std net.Dialer
			return std.DialContext(ctx, network, server.Listener.Addr().(*net.TCPAddr).String())
		}},
	}
}

// requestIDHeaderName is the name of the header used to pass request IDs
// between the client and server. It is used to associate requests with their actors.
const requestIDHeaderName = "TS-Request-ID"

// RoundTrip implements [http.RoundTripper] by sending the request to the [ipnserver.Server]
// on behalf of the owning [Client]. It registers each request for the duration
// of the call and associates it with the actor sending the request.
func (rt *roundTripper) RoundTrip(r *http.Request) (*http.Response, error) {
	reqID, unregister := registerRequest(rt.client.Actor)
	defer unregister()
	r = r.Clone(r.Context())
	r.Header.Set(requestIDHeaderName, reqID)
	return rt.transport.RoundTrip(r)
}

// getActorForRequest returns the actor for a given request.
// It returns an error if the request is not associated with an actor,
// such as when it wasn't sent by a [roundTripper].
func getActorForRequest(r *http.Request) (ipnauth.Actor, error) {
	reqID := r.Header.Get(requestIDHeaderName)
	if reqID == "" {
		return nil, fmt.Errorf("missing %s header", requestIDHeaderName)
	}
	actor, ok := getActorByRequestID(reqID)
	if !ok {
		return nil, fmt.Errorf("unknown request: %s", reqID)
	}
	return actor, nil
}

var (
	inFlightRequestsMu sync.Mutex
	inFlightRequests   map[string]ipnauth.Actor
)

// registerRequest associates a request with the specified actor and returns a unique request ID
// which can be used to retrieve the actor later. The returned function unregisters the request.
func registerRequest(actor ipnauth.Actor) (requestID string, unregister func()) {
	inFlightRequestsMu.Lock()
	defer inFlightRequestsMu.Unlock()
	for {
		requestID = rands.HexString(16)
		if _, ok := inFlightRequests[requestID]; !ok {
			break
		}
	}
	mak.Set(&inFlightRequests, requestID, actor)
	return requestID, func() {
		inFlightRequestsMu.Lock()
		defer inFlightRequestsMu.Unlock()
		delete(inFlightRequests, requestID)
	}
}

// getActorByRequestID returns the actor associated with the specified request ID.
// It returns the actor and true if found, or nil and false if not.
func getActorByRequestID(requestID string) (ipnauth.Actor, bool) {
	inFlightRequestsMu.Lock()
	defer inFlightRequestsMu.Unlock()
	actor, ok := inFlightRequests[requestID]
	return actor, ok
}
