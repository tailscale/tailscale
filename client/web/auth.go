// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package web

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"net/http"
	"time"

	"tailscale.com/client/tailscale/apitype"
	"tailscale.com/tailcfg"
)

const (
	sessionCookieName   = "TS-Web-Session"
	sessionCookieExpiry = time.Hour * 24 * 30 // 30 days
)

// browserSession holds data about a user's browser session
// on the full management web client.
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

// getSession retrieves the browser session associated with the request,
// if one exists.
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
func (s *Server) getSession(r *http.Request) (*browserSession, *apitype.WhoIsResponse, error) {
	whoIs, whoIsErr := s.lc.WhoIs(r.Context(), r.RemoteAddr)
	status, statusErr := s.lc.StatusWithoutPeers(r.Context())
	switch {
	case whoIsErr != nil:
		return nil, nil, errNotUsingTailscale
	case statusErr != nil:
		return nil, whoIs, statusErr
	case status.Self == nil:
		return nil, whoIs, errors.New("missing self node in tailscale status")
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
	v, ok := s.browserSessions.Load(cookie.Value)
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
		s.browserSessions.Delete(session.ID)
		return nil, whoIs, errNoSession
	}
	return session, whoIs, nil
}

// newSession creates a new session associated with the given source user/node,
// and stores it back to the session cache. Creating of a new session includes
// generating a new auth URL from the control server.
func (s *Server) newSession(ctx context.Context, src *apitype.WhoIsResponse) (*browserSession, error) {
	a, err := s.newAuthURL(ctx, src.Node.ID)
	if err != nil {
		return nil, err
	}
	sid, err := s.newSessionID()
	if err != nil {
		return nil, err
	}
	session := &browserSession{
		ID:      sid,
		SrcNode: src.Node.ID,
		SrcUser: src.UserProfile.ID,
		AuthID:  a.ID,
		AuthURL: a.URL,
		Created: s.timeNow(),
	}
	s.browserSessions.Store(sid, session)
	return session, nil
}

// awaitUserAuth blocks until the given session auth has been completed
// by the user on the control server, then updates the session cache upon
// completion. An error is returned if control auth failed for any reason.
func (s *Server) awaitUserAuth(ctx context.Context, session *browserSession) error {
	if session.isAuthorized(s.timeNow()) {
		return nil // already authorized
	}
	a, err := s.waitAuthURL(ctx, session.AuthID, session.SrcNode)
	if err != nil {
		// Clean up the session. Doing this on any error from control
		// server to avoid the user getting stuck with a bad session
		// cookie.
		s.browserSessions.Delete(session.ID)
		return err
	}
	if a.Complete {
		session.Authenticated = a.Complete
		s.browserSessions.Store(session.ID, session)
	}
	return nil
}

func (s *Server) newSessionID() (string, error) {
	raw := make([]byte, 16)
	for i := 0; i < 5; i++ {
		if _, err := rand.Read(raw); err != nil {
			return "", err
		}
		cookie := "ts-web-" + base64.RawURLEncoding.EncodeToString(raw)
		if _, ok := s.browserSessions.Load(cookie); !ok {
			return cookie, nil
		}
	}
	return "", errors.New("too many collisions generating new session; please refresh page")
}
