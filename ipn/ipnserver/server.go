// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package ipnserver runs the LocalAPI HTTP server that communicates
// with the LocalBackend.
package ipnserver

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os/user"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"unicode"

	"tailscale.com/client/tailscale/apitype"
	"tailscale.com/envknob"
	"tailscale.com/feature"
	"tailscale.com/feature/buildfeatures"
	"tailscale.com/ipn/ipnauth"
	"tailscale.com/ipn/ipnlocal"
	"tailscale.com/ipn/localapi"
	"tailscale.com/net/netmon"
	"tailscale.com/types/logger"
	"tailscale.com/types/logid"
	"tailscale.com/util/eventbus"
	"tailscale.com/util/mak"
	"tailscale.com/util/set"
	"tailscale.com/util/testenv"
)

// Server is an IPN backend and its set of 0 or more active localhost
// TCP or unix socket connections talking to that backend.
type Server struct {
	lb           atomic.Pointer[ipnlocal.LocalBackend]
	logf         logger.Logf
	bus          *eventbus.Bus
	netMon       *netmon.Monitor // must be non-nil
	backendLogID logid.PublicID

	// mu guards the fields that follow.
	// lock order: mu, then LocalBackend.mu
	mu            sync.Mutex
	activeReqs    map[*http.Request]ipnauth.Actor
	backendWaiter waiterSet // of LocalBackend waiters
	zeroReqWaiter waiterSet // of blockUntilZeroConnections waiters
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
	if !buildfeatures.HasDebug && runtime.GOOS != "windows" {
		http.Error(w, feature.ErrUnavailable.Error(), http.StatusNotFound)
		return
	}
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
			s.handleProxyConnectConn(w, r)
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

	ci, err := actorFromContext(r.Context())
	if err != nil {
		if errors.Is(err, errNoActor) {
			http.Error(w, "internal error: "+err.Error(), http.StatusInternalServerError)
		} else {
			http.Error(w, err.Error(), http.StatusUnauthorized)
		}
		return
	}

	onDone, err := s.addActiveHTTPRequest(r, ci)
	if err != nil {
		if ou, ok := err.(inUseOtherUserError); ok && localapi.InUseOtherUserIPNStream(w, r, ou.Unwrap()) {
			w.(http.Flusher).Flush()
			s.blockWhileIdentityInUse(ctx, ci)
			return
		}
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}
	defer onDone()

	if strings.HasPrefix(r.URL.Path, "/localapi/") {
		if actor, ok := ci.(*actor); ok {
			reason, err := base64.StdEncoding.DecodeString(r.Header.Get(apitype.RequestReasonHeader))
			if err != nil {
				http.Error(w, "invalid reason header", http.StatusBadRequest)
				return
			}
			ci = actorWithAccessOverride(actor, string(reason))
		}

		lah := localapi.NewHandler(localapi.HandlerConfig{
			Actor:    ci,
			Backend:  lb,
			Logf:     s.logf,
			LogID:    s.backendLogID,
			EventBus: lb.Sys().Bus.Get(),
		})
		if actor, ok := ci.(*actor); ok {
			lah.PermitRead, lah.PermitWrite = actor.Permissions(lb.OperatorUserID())
			lah.PermitCert = actor.CanFetchCerts()
		} else if testenv.InTest() {
			lah.PermitRead, lah.PermitWrite = true, true
		}
		lah.ServeHTTP(w, r)
		return
	}

	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}

	if envknob.GOOS() == "windows" {
		// TODO(bradfitz): remove this once we moved to named pipes for LocalAPI
		// on Windows. This could then move to all platforms instead at
		// 100.100.100.100 or something (quad100 handler in LocalAPI)
		s.ServeHTMLStatus(w, r)
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
func (s *Server) checkConnIdentityLocked(ci ipnauth.Actor) error {
	// If clients are already connected, verify they're the same user.
	// This mostly matters on Windows at the moment.
	if len(s.activeReqs) > 0 {
		var active ipnauth.Actor
		for _, active = range s.activeReqs {
			break
		}
		if active != nil {
			// Always allow Windows SYSTEM user to connect,
			// even if Tailscale is currently being used by another user.
			if ci.IsLocalSystem() {
				return nil
			}

			if ci.UserID() != active.UserID() {
				var b strings.Builder
				b.WriteString("Tailscale already in use")
				if username, err := active.Username(); err == nil {
					fmt.Fprintf(&b, " by %s", username)
				}
				if active, ok := active.(*actor); ok {
					fmt.Fprintf(&b, ", pid %d", active.pid())
				}
				return inUseOtherUserError{errors.New(b.String())}
			}
		}
	}
	if err := s.mustBackend().CheckIPNConnectionAllowed(ci); err != nil {
		return inUseOtherUserError{err}
	}
	return nil
}

// blockWhileIdentityInUse blocks while ci can't connect to the server because
// the server is in use by a different user.
//
// This is primarily used for the Windows GUI, to block until one user's done
// controlling the tailscaled process.
func (s *Server) blockWhileIdentityInUse(ctx context.Context, actor ipnauth.Actor) error {
	inUse := func() bool {
		s.mu.Lock()
		defer s.mu.Unlock()
		_, ok := s.checkConnIdentityLocked(actor).(inUseOtherUserError)
		return ok
	}
	for inUse() {
		// Check whenever the connection count drops down to zero.
		ready, cleanup := s.zeroReqWaiter.add(&s.mu, ctx)
		if inUse() {
			// If the server was in use at the time of the initial check,
			// but disconnected and was removed from the activeReqs map
			// by the time we registered a waiter, the ready channel
			// will never be closed, resulting in a deadlock. To avoid
			// this, we can check again after registering the waiter.
			//
			// This method is planned for complete removal as part of the
			// multi-user improvements in tailscale/corp#18342,
			// and this approach should be fine as a temporary solution.
			<-ready
		}
		cleanup()
		if err := ctx.Err(); err != nil {
			return err
		}
	}
	return nil
}

// Permissions returns the actor's permissions for accessing
// the Tailscale local daemon API. The operatorUID is only used on
// Unix-like platforms and specifies the ID of a local user
// (in the os/user.User.Uid string form) who is allowed
// to operate tailscaled without being root or using sudo.
//
// Sandboxed macos clients must directly supply, or be able to read,
// an explicit token. Permission is inferred by validating that
// token. Sandboxed macos clients also don't use ipnserver.actor at all
// (and prior to that, they didn't use ipnauth.ConnIdentity)
//
// See safesocket and safesocket_darwin.
func (a *actor) Permissions(operatorUID string) (read, write bool) {
	switch envknob.GOOS() {
	case "windows":
		// As of 2024-08-27, according to the current permission model,
		// Windows users always have read/write access to the local API if
		// they're allowed to connect. Whether a user is allowed to connect
		// is determined by [Server.checkConnIdentityLocked] when adding a
		// new connection in [Server.addActiveHTTPRequest]. Therefore, it's
		// acceptable to permit read and write access without any additional
		// checks here. Note that this permission model is being changed in
		// tailscale/corp#18342.
		return true, true
	case "js", "plan9":
		return true, true
	}
	if a.ci.IsUnixSock() {
		return true, !a.ci.IsReadonlyConn(operatorUID, logger.Discard)
	}
	return false, false
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

// CanFetchCerts reports whether the actor is allowed to fetch HTTPS
// certs from this server when it wouldn't otherwise be able to.
//
// That is, this reports whether the actor should grant additional
// capabilities over what the actor would otherwise be able to do.
//
// For now this only returns true on Unix machines when
// TS_PERMIT_CERT_UID is set the to the userid of the peer
// connection. It's intended to give your non-root webserver access
// (www-data, caddy, nginx, etc) to certs.
func (a *actor) CanFetchCerts() bool {
	if !buildfeatures.HasACME {
		return false
	}
	if a.ci.IsUnixSock() && a.ci.Creds() != nil {
		connUID, ok := a.ci.Creds().UserID()
		if ok && connUID == userIDFromString(envknob.String("TS_PERMIT_CERT_UID")) {
			return true
		}
	}
	return false
}

// addActiveHTTPRequest adds c to the server's list of active HTTP requests.
//
// It returns an error if the specified actor is not allowed to connect.
// The returned error may be of type [inUseOtherUserError].
//
// onDone must be called when the HTTP request is done.
func (s *Server) addActiveHTTPRequest(req *http.Request, actor ipnauth.Actor) (onDone func(), err error) {
	if runtime.GOOS != "windows" && !buildfeatures.HasUnixSocketIdentity {
		return func() {}, nil
	}

	if actor == nil {
		return nil, errors.New("internal error: nil actor")
	}

	lb := s.mustBackend()

	s.mu.Lock()
	defer s.mu.Unlock()

	if err := s.checkConnIdentityLocked(actor); err != nil {
		return nil, err
	}

	mak.Set(&s.activeReqs, req, actor)

	if len(s.activeReqs) == 1 {
		if envknob.GOOS() == "windows" && !actor.IsLocalSystem() {
			// Tell the LocalBackend about the identity we're now running as,
			// unless its the SYSTEM user. That user is not a real account and
			// doesn't have a home directory.
			lb.SetCurrentUser(actor)
		}
	}

	onDone = func() {
		s.mu.Lock()
		defer s.mu.Unlock()
		delete(s.activeReqs, req)
		if len(s.activeReqs) != 0 {
			// The server is not idle yet.
			return
		}

		if envknob.GOOS() == "windows" && !actor.IsLocalSystem() {
			lb.SetCurrentUser(nil)
		}

		// Wake up callers waiting for the server to be idle:
		s.zeroReqWaiter.wakeAll()
	}

	return onDone, nil
}

// New returns a new Server.
//
// To start it, use the Server.Run method.
//
// At some point, either before or after Run, the Server's SetLocalBackend
// method must also be called before Server can do anything useful.
func New(logf logger.Logf, logID logid.PublicID, bus *eventbus.Bus, netMon *netmon.Monitor) *Server {
	if netMon == nil {
		panic("nil netMon")
	}
	return &Server{
		backendLogID: logID,
		logf:         logf,
		bus:          bus,
		netMon:       netMon,
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

	ec := s.bus.Client("ipnserver.Server")
	defer ec.Close()
	shutdownSub := eventbus.Subscribe[localapi.Shutdown](ec)

	// When the context is closed, a [localapi.Shutdown] event is received,
	// or when we return, whichever is first, close our listener
	// and all open connections.
	go func() {
		select {
		case <-shutdownSub.Events():
		case <-ctx.Done():
		case <-runDone:
		}
		ln.Close()
	}()

	if ready, ok := feature.HookSystemdReady.GetOk(); ok {
		ready()
	}

	hs := &http.Server{
		Handler:     http.HandlerFunc(s.serveHTTP),
		BaseContext: func(_ net.Listener) context.Context { return ctx },
		ConnContext: func(ctx context.Context, c net.Conn) context.Context {
			return contextWithActor(ctx, s.logf, c)
		},
		ErrorLog: logger.StdLogger(logger.WithPrefix(s.logf, "ipnserver: ")),
	}
	if err := hs.Serve(ln); err != nil {
		if err := ctx.Err(); err != nil {
			return err
		}
		return err
	}
	return nil
}

// ServeHTMLStatus serves an HTML status page at http://localhost:41112/ for
// Windows and via $DEBUG_LISTENER/debug/ipn when tailscaled's --debug flag
// is used to run a debug server.
func (s *Server) ServeHTMLStatus(w http.ResponseWriter, r *http.Request) {
	if !buildfeatures.HasDebug {
		http.Error(w, feature.ErrUnavailable.Error(), http.StatusNotFound)
		return
	}
	lb := s.lb.Load()
	if lb == nil {
		http.Error(w, "no LocalBackend", http.StatusServiceUnavailable)
		return
	}

	// As this is only meant for debug, verify there's no DNS name being used to
	// access this.
	if !strings.HasPrefix(r.Host, "localhost:") && strings.IndexFunc(r.Host, unicode.IsLetter) != -1 {
		http.Error(w, "invalid host", http.StatusForbidden)
		return
	}

	w.Header().Set("Content-Security-Policy", `default-src 'none'; frame-ancestors 'none'; script-src 'none'; script-src-elem 'none'; script-src-attr 'none'`)
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	st := lb.Status()
	// TODO(bradfitz): add LogID and opts to st?
	st.WriteHTML(w)
}
