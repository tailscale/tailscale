// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package ipnserver runs the LocalAPI HTTP server that communicates
// with the LocalBackend.
package ipnserver

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os/user"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"

	"tailscale.com/envknob"
	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnlocal"
	"tailscale.com/ipn/localapi"
	"tailscale.com/net/netmon"
	"tailscale.com/types/logger"
	"tailscale.com/types/logid"
	"tailscale.com/util/set"
)

// Server is an IPN backend and its set of 0 or more active localhost
// TCP or unix socket connections talking to that backend.
type Server struct {
	lb           atomic.Pointer[ipnlocal.LocalBackend]
	logf         logger.Logf
	netMon       *netmon.Monitor // must be non-nil
	backendLogID logid.PublicID
	// resetOnZero is whether to call bs.Reset on transition from
	// 1->0 active HTTP requests. That is, this is whether the backend is
	// being run in "client mode" that requires an active GUI
	// connection (such as on Windows by default). Even if this
	// is true, the ForceDaemon pref can override this.
	resetOnZero bool

	// mu guards the fields that follow.
	// lock order: mu, then LocalBackend.mu
	mu            sync.Mutex
	lastUserID    ipn.WindowsUserID // tracks last userid; on change, Reset state for paranoia
	backendWaiter waiterSet         // of LocalBackend waiters
	zeroReqWaiter waiterSet         // of blockUntilZeroConnections waiters
}

func (s *Server) mustBackend() *ipnlocal.LocalBackend {
	lb := s.lb.Load()
	if lb == nil {
		panic("unexpected: call to mustBackend in path where SetLocalBackend should've been called")
	}
	return lb
}

// waiterSet is a set of callers waiting on something. Each item (map value) in
// the set is a func that wakes up that waiter's context. The waiter is responsible
// for removing itself from the set when woken up. The (*waiterSet).add method
// returns a cleanup method which does that removal. The caller than defers that
// cleanup.
//
// TODO(bradfitz): this is a generally useful pattern. Move elsewhere?
type waiterSet set.HandleSet[context.CancelFunc]

// add registers a new waiter in the set.
// It acquires mu to add the waiter, and does so again when cleanup is called to remove it.
// ready is closed when the waiter is ready (or ctx is done).
func (s *waiterSet) add(mu *sync.Mutex, ctx context.Context) (ready <-chan struct{}, cleanup func()) {
	ctx, cancel := context.WithCancel(ctx)
	hs := (*set.HandleSet[context.CancelFunc])(s) // change method set
	mu.Lock()
	h := hs.Add(cancel)
	mu.Unlock()
	return ctx.Done(), func() {
		mu.Lock()
		delete(*hs, h)
		mu.Unlock()
		cancel()
	}
}

// wakeAll wakes up all waiters in the set.
func (w waiterSet) wakeAll() {
	for _, cancel := range w {
		cancel() // they'll remove themselves
	}
}

func (s *Server) awaitBackend(ctx context.Context) (_ *ipnlocal.LocalBackend, ok bool) {
	lb := s.lb.Load()
	if lb != nil {
		return lb, true
	}

	ready, cleanup := s.backendWaiter.add(&s.mu, ctx)
	defer cleanup()

	// Try again, now that we've registered, in case there was a
	// race.
	lb = s.lb.Load()
	if lb != nil {
		return lb, true
	}

	<-ready
	lb = s.lb.Load()
	return lb, lb != nil
}

// serveServerStatus serves the /server-status endpoint which reports whether
// the LocalBackend is up yet.
// This is primarily for the Windows GUI, because wintun can take awhile to
// come up. See https://github.com/tailscale/tailscale/issues/6522.
func (s *Server) serveServerStatus(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	w.Header().Set("Content-Type", "application/json")
	var res struct {
		Error string `json:"error,omitempty"`
	}

	lb := s.lb.Load()
	if lb == nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		if wait, _ := strconv.ParseBool(r.FormValue("wait")); wait {
			w.(http.Flusher).Flush()
			lb, _ = s.awaitBackend(ctx)
		}
	}

	if lb == nil {
		res.Error = "backend not ready"
	}
	json.NewEncoder(w).Encode(res)
}

func (s *Server) serveHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if r.Method == "CONNECT" {
		if envknob.GOOS() == "windows" {
			// For the GUI client when using an exit node. See docs on handleProxyConnectConn.
			// LANSCAPING
		} else {
			http.Error(w, "bad method for platform", http.StatusMethodNotAllowed)
		}
		return
	}

	// Check for this method before the awaitBackend call, as it reports whether
	// the backend is available.
	if r.Method == "GET" && r.URL.Path == "/server-status" {
		s.serveServerStatus(w, r)
		return
	}

	lb, ok := s.awaitBackend(ctx)
	if !ok {
		// Almost certainly because the context was canceled so the response
		// here doesn't really matter. The client is gone.
		http.Error(w, "no backend", http.StatusServiceUnavailable)
		return
	}

	onDone, err := s.addActiveHTTPRequest(r)
	if err != nil {
		if ou, ok := err.(inUseOtherUserError); ok && localapi.InUseOtherUserIPNStream(w, r, ou.Unwrap()) {
			w.(http.Flusher).Flush()
			return
		}
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}
	defer onDone()

	if strings.HasPrefix(r.URL.Path, "/localapi/") {
		lah := localapi.NewHandler(lb, s.logf, s.backendLogID)
		lah.PermitRead, lah.PermitWrite = true, true
		lah.ServeHTTP(w, r)
		return
	}

	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}

	io.WriteString(w, "<html><title>Tailscale</title><body><h1>Tailscale</h1>This is the local Tailscale daemon.\n")
}

// inUseOtherUserError is the error type for when the server is in use
// by a different local user.
type inUseOtherUserError struct{ error }

func (e inUseOtherUserError) Unwrap() error { return e.error }

// checkConnIdentityLocked checks whether the provided identity is
// allowed to connect to the server.
//
// The returned error, when non-nil, will be of type inUseOtherUserError.
//
// s.mu must be held.
func (s *Server) checkConnIdentityLocked() error {

	return nil
}

// userIDFromString maps from either a numeric user id in string form
// ("998") or username ("caddy") to its string userid ("998").
// It returns the empty string on error.
func userIDFromString(v string) string {
	if v == "" || isAllDigit(v) {
		return v
	}
	u, err := user.Lookup(v)
	if err != nil {
		return ""
	}
	return u.Uid
}

func isAllDigit(s string) bool {
	for i := range len(s) {
		if b := s[i]; b < '0' || b > '9' {
			return false
		}
	}
	return true
}

// addActiveHTTPRequest adds c to the server's list of active HTTP requests.
//
// It returns an error if the specified actor is not allowed to connect.
// The returned error may be of type [inUseOtherUserError].
//
// onDone must be called when the HTTP request is done.
func (s *Server) addActiveHTTPRequest(req *http.Request) (onDone func(), err error) {

	lb := s.mustBackend()

	// If the connected user changes, reset the backend server state to make
	// sure node keys don't leak between users.
	var doReset bool
	defer func() {
		if doReset {
			s.logf("identity changed; resetting server")
			lb.ResetForClientDisconnect()
		}
	}()

	s.mu.Lock()
	defer s.mu.Unlock()

	if err := s.checkConnIdentityLocked(); err != nil {
		return nil, err
	}

	onDone = func() {

	}

	return onDone, nil
}

// New returns a new Server.
//
// To start it, use the Server.Run method.
//
// At some point, either before or after Run, the Server's SetLocalBackend
// method must also be called before Server can do anything useful.
func New(logf logger.Logf, netMon *netmon.Monitor) *Server {
	if netMon == nil {
		panic("nil netMon")
	}
	return &Server{
		logf:        logf,
		netMon:      netMon,
		resetOnZero: envknob.GOOS() == "windows",
	}
}

// SetLocalBackend sets the server's LocalBackend.
//
// It should only call be called after calling lb.Start.
func (s *Server) SetLocalBackend(lb *ipnlocal.LocalBackend) {
	if lb == nil {
		panic("nil LocalBackend")
	}

	if !s.lb.CompareAndSwap(nil, lb) {
		panic("already set")
	}

	s.mu.Lock()
	s.backendWaiter.wakeAll()
	s.mu.Unlock()

	// TODO(bradfitz): send status update to GUI long poller waiter. See
	// https://github.com/tailscale/tailscale/issues/6522
}

// Run runs the server, accepting connections from ln forever.
//
// If the context is done, the listener is closed. It is also the base context
// of all HTTP requests.
//
// If the Server's LocalBackend has already been set, Run starts it.
// Otherwise, the next call to SetLocalBackend will start it.
func (s *Server) Run(ctx context.Context, ln net.Listener) error {
	defer func() {
		if lb := s.lb.Load(); lb != nil {
			lb.Shutdown()
		}
	}()

	runDone := make(chan struct{})
	defer close(runDone)

	// When the context is closed or when we return, whichever is first, close our listener
	// and all open connections.
	go func() {
		select {
		case <-ctx.Done():
		case <-runDone:
		}
		ln.Close()
	}()

	hs := &http.Server{
		Handler:     http.HandlerFunc(s.serveHTTP),
		BaseContext: func(_ net.Listener) context.Context { return ctx },
		ErrorLog:    logger.StdLogger(logger.WithPrefix(s.logf, "ipnserver: ")),
	}
	if err := hs.Serve(ln); err != nil {
		if err := ctx.Err(); err != nil {
			return err
		}
		return err
	}
	return nil
}
