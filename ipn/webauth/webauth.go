// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// TODO: package docs
package webauth

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"tailscale.com/client/tailscale"
	"tailscale.com/client/tailscale/apitype"
	"tailscale.com/tailcfg"
	"tailscale.com/util/httpm"
)

type Server struct {
	// sessions is an in-memory cache of user browser sessions.
	//
	// Users obtain a valid browser session by connecting to the
	// app's UI over Tailscale and verifying their identity by
	// authenticating on the control server.
	//
	// sessions get reset on every webAuthServer initialization.
	//
	// The map provides a lookup of the session by cookie value
	// (browserSession.ID => browserSession).
	sessions sync.Map

	lc      *tailscale.LocalClient
	timeNow func() time.Time
}

func NewServer(lc *tailscale.LocalClient, timeNow func() time.Time) *Server {
	return &Server{
		lc:      lc,
		timeNow: timeNow,
	}
}

func (s *Server) IsLoggedIn(r *http.Request) bool {
	session, _, err := s.getTailscaleBrowserSession(r)
	if err != nil {
		return false
	}
	return session.isAuthorized(s.timeNow())
}

type LoginResponse struct {
	OK      bool   `json:"ok"`                // true when user is already logged in
	AuthURL string `json:"authUrl,omitempty"` // filled when user has control login action to take
}

func (s *Server) ServeLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != httpm.GET {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var resp LoginResponse

	session, whois, err := s.getTailscaleBrowserSession(r)
	switch {
	case err != nil && !errors.Is(err, errNoSession):
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	case session.isAuthorized(s.timeNow()):
		resp = LoginResponse{OK: true} // already logged in
	case session == nil:
		// Create a new session for the user to log in.
		d, err := s.getOrAwaitAuth(r.Context(), "", whois.Node.ID)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		sid, err := s.newSessionID()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		session := &browserSession{
			ID:      sid,
			SrcNode: whois.Node.ID,
			SrcUser: whois.UserProfile.ID,
			AuthID:  d.ID,
			AuthURL: d.URL,
			Created: s.timeNow(),
		}
		s.sessions.Store(sid, session)
		// Set the cookie on browser.
		http.SetCookie(w, &http.Cookie{
			Name:    sessionCookieName,
			Value:   sid,
			Raw:     sid,
			Path:    "/",
			Expires: session.expires(),
		})
		resp = LoginResponse{OK: false, AuthURL: session.AuthURL}
	default:
		// Otherwise there's already an active ongoing login.
		// If the user has requested that this request "wait" for login,
		// we block until the user control auth has been completed.
		// Otherwise we directly return the login URL.
		if r.URL.Query().Get("wait") != "true" {
			resp = LoginResponse{OK: false, AuthURL: session.AuthURL}
			break // quick return
		}
		// Block until user completes auth.
		d, err := s.getOrAwaitAuth(r.Context(), session.AuthID, whois.Node.ID)
		if err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			// Clean up the session. Doing this on any error from control
			// server to avoid the user getting stuck with a bad session
			// cookie.
			s.sessions.Delete(session.ID)
			return
		}
		if d.Complete {
			session.Authenticated = d.Complete
			s.sessions.Store(session.ID, session)
		}
		if session.isAuthorized(s.timeNow()) {
			resp = LoginResponse{OK: true}
		} else {
			resp = LoginResponse{OK: false, AuthURL: session.AuthURL}
		}
	}

	if err := json.NewEncoder(w).Encode(resp); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
}

// browserSession holds data about a user's browser session.
type browserSession struct {
	// ID is the unique identifier for the session.
	// It is passed in the user's "TS-Web-Session" browser cookie.
	ID            string
	SrcNode       tailcfg.NodeID
	SrcUser       tailcfg.UserID
	AuthID        string // from tailcfg.WebClientAuthResponse
	AuthURL       string // from tailcfg.WebClientAuthResponse
	Created       time.Time
	Authenticated bool
}

const (
	sessionCookieName   = "TS-Web-Session"    // default session cookie name; TODO(sonia): make configurable, pass through NewServer
	sessionCookieExpiry = time.Hour * 24 * 30 // default session expiry, 30 days
)

// isAuthorized reports true if the given session is authorized
// to be used by its associated user to access the full management
// web client.
//
// isAuthorized is true only when s.Authenticated is true (i.e.
// the user has authenticated the session) and the session is not
// expired.
// 2023-10-05: Sessions expire by default 30 days after creation.
func (s *browserSession) isAuthorized(now time.Time) bool {
	switch {
	case s == nil:
		return false
	case !s.Authenticated:
		return false // awaiting auth
	case s.isExpired(now):
		return false // expired
	}
	return true
}

// isExpired reports true if s is expired.
// 2023-10-05: Sessions expire by default 30 days after creation.
func (s *browserSession) isExpired(now time.Time) bool {
	return !s.Created.IsZero() && now.After(s.expires())
}

// expires reports when the given session expires.
func (s *browserSession) expires() time.Time {
	return s.Created.Add(sessionCookieExpiry)
}

var (
	errNoSession          = errors.New("no-browser-session")
	errNotUsingTailscale  = errors.New("not-using-tailscale")
	errTaggedRemoteSource = errors.New("tagged-remote-source")
	errTaggedLocalSource  = errors.New("tagged-local-source")
	errNotOwner           = errors.New("not-owner")
)

// getTailscaleBrowserSession retrieves the browser session associated with
// the request, if one exists.
//
// An error is returned in any of the following cases:
//
//   - (errNotUsingTailscale) The request was not made over tailscale.
//
//   - (errNoSession) The request does not have a session.
//
//   - (errTaggedRemoteSource) The source is remote (another node) and tagged.
//     Users must use their own user-owned devices to manage other nodes'
//     web clients.
//
//   - (errTaggedLocalSource) The source is local (the same node) and tagged.
//     Tagged nodes can only be remotely managed, allowing ACLs to dictate
//     access to web clients.
//
//   - (errNotOwner) The source is not the owner of this client (if the
//     client is user-owned). Only the owner is allowed to manage the
//     node via the web client.
//
// If no error is returned, the browserSession is always non-nil.
// getTailscaleBrowserSession does not check whether the session has been
// authorized by the user. Callers can use browserSession.isAuthorized.
//
// The WhoIsResponse is always populated, with a non-nil Node and UserProfile,
// unless getTailscaleBrowserSession reports errNotUsingTailscale.
func (s *Server) getTailscaleBrowserSession(r *http.Request) (*browserSession, *apitype.WhoIsResponse, error) {
	whoIs, whoIsErr := s.lc.WhoIs(r.Context(), r.RemoteAddr)
	status, statusErr := s.lc.StatusWithoutPeers(r.Context())
	switch {
	case whoIsErr != nil:
		return nil, nil, errNotUsingTailscale
	case statusErr != nil:
		return nil, whoIs, statusErr
	case status.Self == nil:
		return nil, whoIs, errors.New("missing self node in tailscale status")
		// TODO: these whois rules would not be general...
	case whoIs.Node.IsTagged() && whoIs.Node.StableID == status.Self.ID:
		return nil, whoIs, errTaggedLocalSource
	case whoIs.Node.IsTagged():
		return nil, whoIs, errTaggedRemoteSource
	case !status.Self.IsTagged() && status.Self.UserID != whoIs.UserProfile.ID:
		return nil, whoIs, errNotOwner
	}
	srcNode := whoIs.Node.ID
	srcUser := whoIs.UserProfile.ID

	cookie, err := r.Cookie(sessionCookieName)
	if errors.Is(err, http.ErrNoCookie) {
		return nil, whoIs, errNoSession
	} else if err != nil {
		return nil, whoIs, err
	}
	v, ok := s.sessions.Load(cookie.Value)
	if !ok {
		return nil, whoIs, errNoSession
	}
	session := v.(*browserSession)
	if session.SrcNode != srcNode || session.SrcUser != srcUser {
		// In this case the browser cookie is associated with another tailscale node.
		// Maybe the source browser's machine was logged out and then back in as a different node.
		// Return errNoSession because there is no session for this user.
		return nil, whoIs, errNoSession
	} else if session.isExpired(s.timeNow()) {
		// Session expired, remove from session map and return errNoSession.
		s.sessions.Delete(session.ID)
		return nil, whoIs, errNoSession
	}
	return session, whoIs, nil
}

func (s *Server) newSessionID() (string, error) {
	raw := make([]byte, 16)
	for i := 0; i < 5; i++ {
		if _, err := rand.Read(raw); err != nil {
			return "", err
		}
		cookie := "ts-web-" + base64.RawURLEncoding.EncodeToString(raw)
		if _, ok := s.sessions.Load(cookie); !ok {
			return cookie, nil
		}
	}
	return "", errors.New("webAuthServer.newSessionID: too many collisions generating new session; please refresh page")
}

// getOrAwaitAuth connects to the control server for user auth,
// with the following behavior:
//
//  1. If authID is provided empty, a new auth URL is created on the control
//     server and reported back here, which can then be used to redirect the
//     user on the frontend.
//  2. If authID is provided non-empty, the connection to control blocks until
//     the user has completed authenticating the associated auth URL,
//     or until ctx is canceled.
func (s *Server) getOrAwaitAuth(ctx context.Context, authID string, src tailcfg.NodeID) (*tailcfg.WebClientAuthResponse, error) {
	type data struct {
		ID  string
		Src tailcfg.NodeID
	}
	var b bytes.Buffer
	if err := json.NewEncoder(&b).Encode(data{ID: authID, Src: src}); err != nil {
		return nil, err
	}
	url := "http://" + apitype.LocalAPIHost + "/localapi/v0/debug-web-client"
	req, err := http.NewRequestWithContext(ctx, "POST", url, &b)
	if err != nil {
		return nil, err
	}
	resp, err := s.lc.DoLocalRequest(req)
	if err != nil {
		return nil, err
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed request: %s", body)
	}
	var authResp *tailcfg.WebClientAuthResponse
	if err := json.Unmarshal(body, &authResp); err != nil {
		return nil, err
	}
	return authResp, nil
}
