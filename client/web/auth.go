// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package web

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"tailscale.com/client/tailscale/apitype"
	"tailscale.com/ipn/ipnstate"
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
func (s *Server) getSession(r *http.Request) (*browserSession, *apitype.WhoIsResponse, *ipnstate.Status, error) {
	whoIs, whoIsErr := s.lc.WhoIs(r.Context(), r.RemoteAddr)
	status, statusErr := s.lc.StatusWithoutPeers(r.Context())
	switch {
	case whoIsErr != nil:
		return nil, nil, status, errNotUsingTailscale
	case statusErr != nil:
		return nil, whoIs, nil, statusErr
	case status.Self == nil:
		return nil, whoIs, status, errors.New("missing self node in tailscale status")
	case whoIs.Node.IsTagged() && whoIs.Node.StableID == status.Self.ID:
		return nil, whoIs, status, errTaggedLocalSource
	case whoIs.Node.IsTagged():
		return nil, whoIs, status, errTaggedRemoteSource
	case !status.Self.IsTagged() && status.Self.UserID != whoIs.UserProfile.ID:
		return nil, whoIs, status, errNotOwner
	}
	srcNode := whoIs.Node.ID
	srcUser := whoIs.UserProfile.ID

	cookie, err := r.Cookie(sessionCookieName)
	if errors.Is(err, http.ErrNoCookie) {
		return nil, whoIs, status, errNoSession
	} else if err != nil {
		return nil, whoIs, status, err
	}
	v, ok := s.browserSessions.Load(cookie.Value)
	if !ok {
		return nil, whoIs, status, errNoSession
	}
	session := v.(*browserSession)
	if session.SrcNode != srcNode || session.SrcUser != srcUser {
		// In this case the browser cookie is associated with another tailscale node.
		// Maybe the source browser's machine was logged out and then back in as a different node.
		// Return errNoSession because there is no session for this user.
		return nil, whoIs, status, errNoSession
	} else if session.isExpired(s.timeNow()) {
		// Session expired, remove from session map and return errNoSession.
		s.browserSessions.Delete(session.ID)
		return nil, whoIs, status, errNoSession
	}
	return session, whoIs, status, nil
}

// newSession creates a new session associated with the given source user/node,
// and stores it back to the session cache. Creating of a new session includes
// generating a new auth URL from the control server.
func (s *Server) newSession(ctx context.Context, src *apitype.WhoIsResponse) (*browserSession, error) {
	sid, err := s.newSessionID()
	if err != nil {
		return nil, err
	}
	session := &browserSession{
		ID:      sid,
		SrcNode: src.Node.ID,
		SrcUser: src.UserProfile.ID,
		Created: s.timeNow(),
	}

	if s.controlSupportsCheckMode(ctx) {
		// control supports check mode, so get a new auth URL and return.
		a, err := s.newAuthURL(ctx, src.Node.ID)
		if err != nil {
			return nil, err
		}
		session.AuthID = a.ID
		session.AuthURL = a.URL
	} else {
		// control does not support check mode, so there is no additional auth we can do.
		session.Authenticated = true
	}

	s.browserSessions.Store(sid, session)
	return session, nil
}

// controlSupportsCheckMode returns whether the current control server supports web client check mode, to verify a user's identity.
// We assume that only "tailscale.com" control servers support check mode.
// This allows the web client to be used with non-standard control servers.
// If an error occurs getting the control URL, this method returns true to fail closed.
//
// TODO(juanfont/headscale#1623): adjust or remove this when headscale supports check mode.
func (s *Server) controlSupportsCheckMode(ctx context.Context) bool {
	prefs, err := s.lc.GetPrefs(ctx)
	if err != nil {
		return true
	}
	controlURL, err := url.Parse(prefs.ControlURLOrDefault())
	if err != nil {
		return true
	}
	return strings.HasSuffix(controlURL.Host, ".tailscale.com")
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

// peerCapabilities holds information about what a source
// peer is allowed to edit via the web UI.
//
// map value is true if the peer can edit the given feature.
// Only capFeatures included in validCaps will be included.
type peerCapabilities map[capFeature]bool

// canEdit is true if the peerCapabilities grant edit access
// to the given feature.
func (p peerCapabilities) canEdit(feature capFeature) bool {
	if p == nil {
		return false
	}
	if p[capFeatureAll] {
		return true
	}
	return p[feature]
}

// isEmpty is true if p is either nil or has no capabilities
// with value true.
func (p peerCapabilities) isEmpty() bool {
	if p == nil {
		return true
	}
	for _, v := range p {
		if v == true {
			return false
		}
	}
	return true
}

type capFeature string

const (
	// The following values should not be edited.
	// New caps can be added, but existing ones should not be changed,
	// as these exact values are used by users in tailnet policy files.
	//
	// IMPORTANT: When adding a new cap, also update validCaps slice below.

	capFeatureAll       capFeature = "*"         // grants peer management of all features
	capFeatureSSH       capFeature = "ssh"       // grants peer SSH server management
	capFeatureSubnets   capFeature = "subnets"   // grants peer subnet routes management
	capFeatureExitNodes capFeature = "exitnodes" // grants peer ability to advertise-as and use exit nodes
	capFeatureAccount   capFeature = "account"   // grants peer ability to turn on auto updates and log out of node
)

// validCaps contains the list of valid capabilities used in the web client.
// Any capabilities included in a peer's grants that do not fall into this
// list will be ignored.
var validCaps []capFeature = []capFeature{
	capFeatureAll,
	capFeatureSSH,
	capFeatureSubnets,
	capFeatureExitNodes,
	capFeatureAccount,
}

type capRule struct {
	CanEdit []string `json:"canEdit,omitempty"` // list of features peer is allowed to edit
}

// toPeerCapabilities parses out the web ui capabilities from the
// given whois response.
func toPeerCapabilities(status *ipnstate.Status, whois *apitype.WhoIsResponse) (peerCapabilities, error) {
	if whois == nil || status == nil {
		return peerCapabilities{}, nil
	}
	if whois.Node.IsTagged() {
		// We don't allow management *from* tagged nodes, so ignore caps.
		// The web client auth flow relies on having a true user identity
		// that can be verified through login.
		return peerCapabilities{}, nil
	}

	if !status.Self.IsTagged() {
		// User owned nodes are only ever manageable by the owner.
		if status.Self.UserID != whois.UserProfile.ID {
			return peerCapabilities{}, nil
		} else {
			return peerCapabilities{capFeatureAll: true}, nil // owner can edit all features
		}
	}

	// For tagged nodes, we actually look at the granted capabilities.
	caps := peerCapabilities{}
	rules, err := tailcfg.UnmarshalCapJSON[capRule](whois.CapMap, tailcfg.PeerCapabilityWebUI)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal capability: %v", err)
	}
	for _, c := range rules {
		for _, f := range c.CanEdit {
			cap := capFeature(strings.ToLower(f))
			if slices.Contains(validCaps, cap) {
				caps[cap] = true
			}
		}
	}
	return caps, nil
}
