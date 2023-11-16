// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package web

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"tailscale.com/client/tailscale"
	"tailscale.com/client/tailscale/apitype"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/net/memnet"
	"tailscale.com/tailcfg"
	"tailscale.com/types/views"
	"tailscale.com/util/httpm"
)

func TestQnapAuthnURL(t *testing.T) {
	query := url.Values{
		"qtoken": []string{"token"},
	}
	tests := []struct {
		name string
		in   string
		want string
	}{
		{
			name: "localhost http",
			in:   "http://localhost:8088/",
			want: "http://localhost:8088/cgi-bin/authLogin.cgi?qtoken=token",
		},
		{
			name: "localhost https",
			in:   "https://localhost:5000/",
			want: "https://localhost:5000/cgi-bin/authLogin.cgi?qtoken=token",
		},
		{
			name: "IP http",
			in:   "http://10.1.20.4:80/",
			want: "http://10.1.20.4:80/cgi-bin/authLogin.cgi?qtoken=token",
		},
		{
			name: "IP6 https",
			in:   "https://[ff7d:0:1:2::1]/",
			want: "https://[ff7d:0:1:2::1]/cgi-bin/authLogin.cgi?qtoken=token",
		},
		{
			name: "hostname https",
			in:   "https://qnap.example.com/",
			want: "https://qnap.example.com/cgi-bin/authLogin.cgi?qtoken=token",
		},
		{
			name: "invalid URL",
			in:   "This is not a URL, it is a really really really really really really really really really really really really long string to exercise the URL truncation code in the error path.",
			want: "http://localhost/cgi-bin/authLogin.cgi?qtoken=token",
		},
		{
			name: "err != nil",
			in:   "http://192.168.0.%31/",
			want: "http://localhost/cgi-bin/authLogin.cgi?qtoken=token",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u := qnapAuthnURL(tt.in, query)
			if u != tt.want {
				t.Errorf("expected url: %q, got: %q", tt.want, u)
			}
		})
	}
}

// TestServeAPI tests the web client api's handling of
//  1. invalid endpoint errors
//  2. localapi proxy allowlist
func TestServeAPI(t *testing.T) {
	lal := memnet.Listen("local-tailscaled.sock:80")
	defer lal.Close()
	// Serve dummy localapi. Just returns "success".
	localapi := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "success")
	})}
	defer localapi.Close()

	go localapi.Serve(lal)
	s := &Server{lc: &tailscale.LocalClient{Dial: lal.Dial}}

	tests := []struct {
		name       string
		reqPath    string
		wantResp   string
		wantStatus int
	}{{
		name:       "invalid_endpoint",
		reqPath:    "/not-an-endpoint",
		wantResp:   "invalid endpoint",
		wantStatus: http.StatusNotFound,
	}, {
		name:       "not_in_localapi_allowlist",
		reqPath:    "/local/v0/not-allowlisted",
		wantResp:   "/v0/not-allowlisted not allowed from localapi proxy",
		wantStatus: http.StatusForbidden,
	}, {
		name:       "in_localapi_allowlist",
		reqPath:    "/local/v0/logout",
		wantResp:   "success", // Successfully allowed to hit localapi.
		wantStatus: http.StatusOK,
	}}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest("POST", "/api"+tt.reqPath, nil)
			w := httptest.NewRecorder()

			s.serveAPI(w, r)
			res := w.Result()
			defer res.Body.Close()
			if gotStatus := res.StatusCode; tt.wantStatus != gotStatus {
				t.Errorf("wrong status; want=%v, got=%v", tt.wantStatus, gotStatus)
			}
			body, err := io.ReadAll(res.Body)
			if err != nil {
				t.Fatal(err)
			}
			gotResp := strings.TrimSuffix(string(body), "\n") // trim trailing newline
			if tt.wantResp != gotResp {
				t.Errorf("wrong response; want=%q, got=%q", tt.wantResp, gotResp)
			}
		})
	}
}

func TestGetTailscaleBrowserSession(t *testing.T) {
	userA := &tailcfg.UserProfile{ID: tailcfg.UserID(1)}
	userB := &tailcfg.UserProfile{ID: tailcfg.UserID(2)}

	userANodeIP := "100.100.100.101"
	userBNodeIP := "100.100.100.102"
	taggedNodeIP := "100.100.100.103"

	var selfNode *ipnstate.PeerStatus
	tags := views.SliceOf([]string{"tag:server"})
	tailnetNodes := map[string]*apitype.WhoIsResponse{
		userANodeIP: {
			Node:        &tailcfg.Node{ID: 1, StableID: "1"},
			UserProfile: userA,
		},
		userBNodeIP: {
			Node:        &tailcfg.Node{ID: 2, StableID: "2"},
			UserProfile: userB,
		},
		taggedNodeIP: {
			Node: &tailcfg.Node{ID: 3, StableID: "3", Tags: tags.AsSlice()},
		},
	}

	lal := memnet.Listen("local-tailscaled.sock:80")
	defer lal.Close()
	localapi := mockLocalAPI(t, tailnetNodes, func() *ipnstate.PeerStatus { return selfNode })
	defer localapi.Close()
	go localapi.Serve(lal)

	s := &Server{
		timeNow: time.Now,
		lc:      &tailscale.LocalClient{Dial: lal.Dial},
	}

	// Add some browser sessions to cache state.
	userASession := &browserSession{
		ID:            "cookie1",
		SrcNode:       1,
		SrcUser:       userA.ID,
		Created:       time.Now(),
		Authenticated: false, // not yet authenticated
	}
	userBSession := &browserSession{
		ID:            "cookie2",
		SrcNode:       2,
		SrcUser:       userB.ID,
		Created:       time.Now().Add(-2 * sessionCookieExpiry),
		Authenticated: true, // expired
	}
	userASessionAuthorized := &browserSession{
		ID:            "cookie3",
		SrcNode:       1,
		SrcUser:       userA.ID,
		Created:       time.Now(),
		Authenticated: true, // authenticated and not expired
	}
	s.browserSessions.Store(userASession.ID, userASession)
	s.browserSessions.Store(userBSession.ID, userBSession)
	s.browserSessions.Store(userASessionAuthorized.ID, userASessionAuthorized)

	tests := []struct {
		name       string
		selfNode   *ipnstate.PeerStatus
		remoteAddr string
		cookie     string

		wantSession      *browserSession
		wantError        error
		wantIsAuthorized bool // response from session.isAuthorized
	}{
		{
			name:        "not-connected-over-tailscale",
			selfNode:    &ipnstate.PeerStatus{ID: "self", UserID: userA.ID},
			remoteAddr:  "77.77.77.77",
			wantSession: nil,
			wantError:   errNotUsingTailscale,
		},
		{
			name:        "no-session-user-self-node",
			selfNode:    &ipnstate.PeerStatus{ID: "self", UserID: userA.ID},
			remoteAddr:  userANodeIP,
			cookie:      "not-a-cookie",
			wantSession: nil,
			wantError:   errNoSession,
		},
		{
			name:        "no-session-tagged-self-node",
			selfNode:    &ipnstate.PeerStatus{ID: "self", Tags: &tags},
			remoteAddr:  userANodeIP,
			wantSession: nil,
			wantError:   errNoSession,
		},
		{
			name:        "not-owner",
			selfNode:    &ipnstate.PeerStatus{ID: "self", UserID: userA.ID},
			remoteAddr:  userBNodeIP,
			wantSession: nil,
			wantError:   errNotOwner,
		},
		{
			name:        "tagged-remote-source",
			selfNode:    &ipnstate.PeerStatus{ID: "self", UserID: userA.ID},
			remoteAddr:  taggedNodeIP,
			wantSession: nil,
			wantError:   errTaggedRemoteSource,
		},
		{
			name:        "tagged-local-source",
			selfNode:    &ipnstate.PeerStatus{ID: "3"},
			remoteAddr:  taggedNodeIP, // same node as selfNode
			wantSession: nil,
			wantError:   errTaggedLocalSource,
		},
		{
			name:        "not-tagged-local-source",
			selfNode:    &ipnstate.PeerStatus{ID: "1", UserID: userA.ID},
			remoteAddr:  userANodeIP, // same node as selfNode
			cookie:      userASession.ID,
			wantSession: userASession,
			wantError:   nil, // should not error
		},
		{
			name:        "has-session",
			selfNode:    &ipnstate.PeerStatus{ID: "self", UserID: userA.ID},
			remoteAddr:  userANodeIP,
			cookie:      userASession.ID,
			wantSession: userASession,
			wantError:   nil,
		},
		{
			name:             "has-authorized-session",
			selfNode:         &ipnstate.PeerStatus{ID: "self", UserID: userA.ID},
			remoteAddr:       userANodeIP,
			cookie:           userASessionAuthorized.ID,
			wantSession:      userASessionAuthorized,
			wantError:        nil,
			wantIsAuthorized: true,
		},
		{
			name:        "session-associated-with-different-source",
			selfNode:    &ipnstate.PeerStatus{ID: "self", UserID: userB.ID},
			remoteAddr:  userBNodeIP,
			cookie:      userASession.ID,
			wantSession: nil,
			wantError:   errNoSession,
		},
		{
			name:        "session-expired",
			selfNode:    &ipnstate.PeerStatus{ID: "self", UserID: userB.ID},
			remoteAddr:  userBNodeIP,
			cookie:      userBSession.ID,
			wantSession: nil,
			wantError:   errNoSession,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			selfNode = tt.selfNode
			r := &http.Request{RemoteAddr: tt.remoteAddr, Header: http.Header{}}
			if tt.cookie != "" {
				r.AddCookie(&http.Cookie{Name: sessionCookieName, Value: tt.cookie})
			}
			session, _, err := s.getSession(r)
			if !errors.Is(err, tt.wantError) {
				t.Errorf("wrong error; want=%v, got=%v", tt.wantError, err)
			}
			if diff := cmp.Diff(session, tt.wantSession); diff != "" {
				t.Errorf("wrong session; (-got+want):%v", diff)
			}
			if gotIsAuthorized := session.isAuthorized(s.timeNow()); gotIsAuthorized != tt.wantIsAuthorized {
				t.Errorf("wrong isAuthorized; want=%v, got=%v", tt.wantIsAuthorized, gotIsAuthorized)
			}
		})
	}
}

// TestAuthorizeRequest tests the s.authorizeRequest function.
// 2023-10-18: These tests currently cover tailscale auth mode (not platform auth).
func TestAuthorizeRequest(t *testing.T) {
	// Create self and remoteNode owned by same user.
	// See TestGetTailscaleBrowserSession for tests of
	// browser sessions w/ different users.
	user := &tailcfg.UserProfile{ID: tailcfg.UserID(1)}
	self := &ipnstate.PeerStatus{ID: "self", UserID: user.ID}
	remoteNode := &apitype.WhoIsResponse{Node: &tailcfg.Node{StableID: "node"}, UserProfile: user}
	remoteIP := "100.100.100.101"

	lal := memnet.Listen("local-tailscaled.sock:80")
	defer lal.Close()
	localapi := mockLocalAPI(t,
		map[string]*apitype.WhoIsResponse{remoteIP: remoteNode},
		func() *ipnstate.PeerStatus { return self },
	)
	defer localapi.Close()
	go localapi.Serve(lal)

	s := &Server{
		mode:    ManageServerMode,
		lc:      &tailscale.LocalClient{Dial: lal.Dial},
		timeNow: time.Now,
	}
	validCookie := "ts-cookie"
	s.browserSessions.Store(validCookie, &browserSession{
		ID:            validCookie,
		SrcNode:       remoteNode.Node.ID,
		SrcUser:       user.ID,
		Created:       time.Now(),
		Authenticated: true,
	})

	tests := []struct {
		reqPath   string
		reqMethod string

		wantOkNotOverTailscale bool // simulates req over public internet
		wantOkWithoutSession   bool // simulates req over TS without valid browser session
		wantOkWithSession      bool // simulates req over TS with valid browser session
	}{{
		reqPath:                "/api/data",
		reqMethod:              httpm.GET,
		wantOkNotOverTailscale: false,
		wantOkWithoutSession:   true,
		wantOkWithSession:      true,
	}, {
		reqPath:                "/api/data",
		reqMethod:              httpm.POST,
		wantOkNotOverTailscale: false,
		wantOkWithoutSession:   false,
		wantOkWithSession:      true,
	}, {
		reqPath:                "/api/somethingelse",
		reqMethod:              httpm.GET,
		wantOkNotOverTailscale: false,
		wantOkWithoutSession:   false,
		wantOkWithSession:      true,
	}, {
		reqPath:                "/assets/styles.css",
		wantOkNotOverTailscale: false,
		wantOkWithoutSession:   true,
		wantOkWithSession:      true,
	}}
	for _, tt := range tests {
		t.Run(fmt.Sprintf("%s-%s", tt.reqMethod, tt.reqPath), func(t *testing.T) {
			doAuthorize := func(remoteAddr string, cookie string) bool {
				r := httptest.NewRequest(tt.reqMethod, tt.reqPath, nil)
				r.RemoteAddr = remoteAddr
				if cookie != "" {
					r.AddCookie(&http.Cookie{Name: sessionCookieName, Value: cookie})
				}
				w := httptest.NewRecorder()
				return s.authorizeRequest(w, r)
			}
			// Do request from non-Tailscale IP.
			if gotOk := doAuthorize("123.456.789.999", ""); gotOk != tt.wantOkNotOverTailscale {
				t.Errorf("wantOkNotOverTailscale; want=%v, got=%v", tt.wantOkNotOverTailscale, gotOk)
			}
			// Do request from Tailscale IP w/o associated session.
			if gotOk := doAuthorize(remoteIP, ""); gotOk != tt.wantOkWithoutSession {
				t.Errorf("wantOkWithoutSession; want=%v, got=%v", tt.wantOkWithoutSession, gotOk)
			}
			// Do request from Tailscale IP w/ associated session.
			if gotOk := doAuthorize(remoteIP, validCookie); gotOk != tt.wantOkWithSession {
				t.Errorf("wantOkWithSession; want=%v, got=%v", tt.wantOkWithSession, gotOk)
			}
		})
	}
}

func TestServeAuth(t *testing.T) {
	user := &tailcfg.UserProfile{LoginName: "user@example.com", ID: tailcfg.UserID(1)}
	self := &ipnstate.PeerStatus{
		ID:           "self",
		UserID:       user.ID,
		TailscaleIPs: []netip.Addr{netip.MustParseAddr("100.1.2.3")},
	}
	remoteIP := "100.100.100.101"
	remoteNode := &apitype.WhoIsResponse{
		Node: &tailcfg.Node{
			Name:      "nodey",
			ID:        1,
			Addresses: []netip.Prefix{netip.MustParsePrefix(remoteIP + "/32")},
		},
		UserProfile: user,
	}
	vi := &viewerIdentity{
		LoginName:     user.LoginName,
		NodeName:      remoteNode.Node.Name,
		NodeIP:        remoteIP,
		ProfilePicURL: user.ProfilePicURL,
	}

	lal := memnet.Listen("local-tailscaled.sock:80")
	defer lal.Close()
	localapi := mockLocalAPI(t,
		map[string]*apitype.WhoIsResponse{remoteIP: remoteNode},
		func() *ipnstate.PeerStatus { return self },
	)
	defer localapi.Close()
	go localapi.Serve(lal)

	timeNow := time.Now()
	oneHourAgo := timeNow.Add(-time.Hour)
	sixtyDaysAgo := timeNow.Add(-sessionCookieExpiry * 2)

	s := &Server{
		mode:        ManageServerMode,
		lc:          &tailscale.LocalClient{Dial: lal.Dial},
		timeNow:     func() time.Time { return timeNow },
		newAuthURL:  mockNewAuthURL,
		waitAuthURL: mockWaitAuthURL,
	}

	successCookie := "ts-cookie-success"
	s.browserSessions.Store(successCookie, &browserSession{
		ID:      successCookie,
		SrcNode: remoteNode.Node.ID,
		SrcUser: user.ID,
		Created: oneHourAgo,
		AuthID:  testAuthPathSuccess,
		AuthURL: testControlURL + testAuthPathSuccess,
	})
	failureCookie := "ts-cookie-failure"
	s.browserSessions.Store(failureCookie, &browserSession{
		ID:      failureCookie,
		SrcNode: remoteNode.Node.ID,
		SrcUser: user.ID,
		Created: oneHourAgo,
		AuthID:  testAuthPathError,
		AuthURL: testControlURL + testAuthPathError,
	})
	expiredCookie := "ts-cookie-expired"
	s.browserSessions.Store(expiredCookie, &browserSession{
		ID:      expiredCookie,
		SrcNode: remoteNode.Node.ID,
		SrcUser: user.ID,
		Created: sixtyDaysAgo,
		AuthID:  "/a/old-auth-url",
		AuthURL: testControlURL + "/a/old-auth-url",
	})

	tests := []struct {
		name string

		cookie        string          // cookie attached to request
		wantNewCookie bool            // want new cookie generated during request
		wantSession   *browserSession // session associated w/ cookie after request

		path       string
		wantStatus int
		wantResp   any
	}{
		{
			name:          "no-session",
			path:          "/api/auth",
			wantStatus:    http.StatusOK,
			wantResp:      &authResponse{AuthNeeded: tailscaleAuth, ViewerIdentity: vi},
			wantNewCookie: false,
			wantSession:   nil,
		},
		{
			name:          "new-session",
			path:          "/api/auth/session/new",
			wantStatus:    http.StatusOK,
			wantResp:      &newSessionAuthResponse{AuthURL: testControlURL + testAuthPath},
			wantNewCookie: true,
			wantSession: &browserSession{
				ID:            "GENERATED_ID", // gets swapped for newly created ID by test
				SrcNode:       remoteNode.Node.ID,
				SrcUser:       user.ID,
				Created:       timeNow,
				AuthID:        testAuthPath,
				AuthURL:       testControlURL + testAuthPath,
				Authenticated: false,
			},
		},
		{
			name:       "query-existing-incomplete-session",
			path:       "/api/auth",
			cookie:     successCookie,
			wantStatus: http.StatusOK,
			wantResp:   &authResponse{AuthNeeded: tailscaleAuth, ViewerIdentity: vi},
			wantSession: &browserSession{
				ID:            successCookie,
				SrcNode:       remoteNode.Node.ID,
				SrcUser:       user.ID,
				Created:       oneHourAgo,
				AuthID:        testAuthPathSuccess,
				AuthURL:       testControlURL + testAuthPathSuccess,
				Authenticated: false,
			},
		},
		{
			name:       "existing-session-used",
			path:       "/api/auth/session/new", // should not create new session
			cookie:     successCookie,
			wantStatus: http.StatusOK,
			wantResp:   &newSessionAuthResponse{AuthURL: testControlURL + testAuthPathSuccess},
			wantSession: &browserSession{
				ID:            successCookie,
				SrcNode:       remoteNode.Node.ID,
				SrcUser:       user.ID,
				Created:       oneHourAgo,
				AuthID:        testAuthPathSuccess,
				AuthURL:       testControlURL + testAuthPathSuccess,
				Authenticated: false,
			},
		},
		{
			name:       "transition-to-successful-session",
			path:       "/api/auth/session/wait",
			cookie:     successCookie,
			wantStatus: http.StatusOK,
			wantResp:   nil,
			wantSession: &browserSession{
				ID:            successCookie,
				SrcNode:       remoteNode.Node.ID,
				SrcUser:       user.ID,
				Created:       oneHourAgo,
				AuthID:        testAuthPathSuccess,
				AuthURL:       testControlURL + testAuthPathSuccess,
				Authenticated: true,
			},
		},
		{
			name:       "query-existing-complete-session",
			path:       "/api/auth",
			cookie:     successCookie,
			wantStatus: http.StatusOK,
			wantResp:   &authResponse{CanManageNode: true, ViewerIdentity: vi},
			wantSession: &browserSession{
				ID:            successCookie,
				SrcNode:       remoteNode.Node.ID,
				SrcUser:       user.ID,
				Created:       oneHourAgo,
				AuthID:        testAuthPathSuccess,
				AuthURL:       testControlURL + testAuthPathSuccess,
				Authenticated: true,
			},
		},
		{
			name:        "transition-to-failed-session",
			path:        "/api/auth/session/wait",
			cookie:      failureCookie,
			wantStatus:  http.StatusUnauthorized,
			wantResp:    nil,
			wantSession: nil, // session deleted
		},
		{
			name:          "failed-session-cleaned-up",
			path:          "/api/auth/session/new",
			cookie:        failureCookie,
			wantStatus:    http.StatusOK,
			wantResp:      &newSessionAuthResponse{AuthURL: testControlURL + testAuthPath},
			wantNewCookie: true,
			wantSession: &browserSession{
				ID:            "GENERATED_ID",
				SrcNode:       remoteNode.Node.ID,
				SrcUser:       user.ID,
				Created:       timeNow,
				AuthID:        testAuthPath,
				AuthURL:       testControlURL + testAuthPath,
				Authenticated: false,
			},
		},
		{
			name:          "expired-cookie-gets-new-session",
			path:          "/api/auth/session/new",
			cookie:        expiredCookie,
			wantStatus:    http.StatusOK,
			wantResp:      &newSessionAuthResponse{AuthURL: testControlURL + testAuthPath},
			wantNewCookie: true,
			wantSession: &browserSession{
				ID:            "GENERATED_ID",
				SrcNode:       remoteNode.Node.ID,
				SrcUser:       user.ID,
				Created:       timeNow,
				AuthID:        testAuthPath,
				AuthURL:       testControlURL + testAuthPath,
				Authenticated: false,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest("GET", "http://100.1.2.3:5252"+tt.path, nil)
			r.RemoteAddr = remoteIP
			r.AddCookie(&http.Cookie{Name: sessionCookieName, Value: tt.cookie})
			w := httptest.NewRecorder()
			s.serve(w, r)
			res := w.Result()
			defer res.Body.Close()

			// Validate response status/data.
			if gotStatus := res.StatusCode; tt.wantStatus != gotStatus {
				t.Errorf("wrong status; want=%v, got=%v", tt.wantStatus, gotStatus)
			}
			var gotResp string
			if res.StatusCode == http.StatusOK {
				body, err := io.ReadAll(res.Body)
				if err != nil {
					t.Fatal(err)
				}
				gotResp = strings.Trim(string(body), "\n")
			}
			var wantResp string
			if tt.wantResp != nil {
				b, _ := json.Marshal(tt.wantResp)
				wantResp = string(b)
			}
			if diff := cmp.Diff(gotResp, string(wantResp)); diff != "" {
				t.Errorf("wrong response; (-got+want):%v", diff)
			}
			// Validate cookie creation.
			sessionID := tt.cookie
			var gotCookie bool
			for _, c := range w.Result().Cookies() {
				if c.Name == sessionCookieName {
					gotCookie = true
					sessionID = c.Value
					break
				}
			}
			if gotCookie != tt.wantNewCookie {
				t.Errorf("wantNewCookie wrong; want=%v, got=%v", tt.wantNewCookie, gotCookie)
			}
			// Validate browser session contents.
			var gotSesson *browserSession
			if s, ok := s.browserSessions.Load(sessionID); ok {
				gotSesson = s.(*browserSession)
			}
			if tt.wantSession != nil && tt.wantSession.ID == "GENERATED_ID" {
				// If requested, swap in the generated session ID before
				// comparing got/want.
				tt.wantSession.ID = sessionID
			}
			if diff := cmp.Diff(gotSesson, tt.wantSession); diff != "" {
				t.Errorf("wrong session; (-got+want):%v", diff)
			}
		})
	}
}

func TestRequireTailscaleIP(t *testing.T) {
	self := &ipnstate.PeerStatus{
		TailscaleIPs: []netip.Addr{
			netip.MustParseAddr("100.1.2.3"),
			netip.MustParseAddr("fd7a:115c::1234"),
		},
	}

	lal := memnet.Listen("local-tailscaled.sock:80")
	defer lal.Close()
	localapi := mockLocalAPI(t, nil, func() *ipnstate.PeerStatus { return self })
	defer localapi.Close()
	go localapi.Serve(lal)

	s := &Server{
		mode:    ManageServerMode,
		lc:      &tailscale.LocalClient{Dial: lal.Dial},
		timeNow: time.Now,
		logf:    t.Logf,
	}

	tests := []struct {
		name         string
		target       string
		wantHandled  bool
		wantLocation string
	}{
		{
			name:         "localhost",
			target:       "http://localhost/",
			wantHandled:  true,
			wantLocation: "http://100.1.2.3:5252/",
		},
		{
			name:         "ipv4-no-port",
			target:       "http://100.1.2.3/",
			wantHandled:  true,
			wantLocation: "http://100.1.2.3:5252/",
		},
		{
			name:        "ipv4-correct-port",
			target:      "http://100.1.2.3:5252/",
			wantHandled: false,
		},
		{
			name:         "ipv6-no-port",
			target:       "http://[fd7a:115c::1234]/",
			wantHandled:  true,
			wantLocation: "http://100.1.2.3:5252/",
		},
		{
			name:        "ipv6-correct-port",
			target:      "http://[fd7a:115c::1234]:5252/",
			wantHandled: false,
		},
		{
			name:        "quad-100",
			target:      "http://100.100.100.100/",
			wantHandled: false,
		},
		{
			name:        "ipv6-service-addr",
			target:      "http://[fd7a:115c:a1e0::53]/",
			wantHandled: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.target, func(t *testing.T) {
			s.logf = t.Logf
			r := httptest.NewRequest(httpm.GET, tt.target, nil)
			w := httptest.NewRecorder()
			handled := s.requireTailscaleIP(w, r)

			if handled != tt.wantHandled {
				t.Errorf("request(%q) was handled; want=%v, got=%v", tt.target, tt.wantHandled, handled)
			}

			location := w.Header().Get("Location")
			if location != tt.wantLocation {
				t.Errorf("request(%q) wrong location; want=%q, got=%q", tt.target, tt.wantLocation, location)
			}
		})
	}
}

var (
	testControlURL      = "http://localhost:8080"
	testAuthPath        = "/a/12345"
	testAuthPathSuccess = "/a/will-succeed"
	testAuthPathError   = "/a/will-error"
)

// mockLocalAPI constructs a test localapi handler that can be used
// to simulate localapi responses without a functioning tailnet.
//
// self accepts a function that resolves to a self node status,
// so that tests may swap out the /localapi/v0/status response
// as desired.
func mockLocalAPI(t *testing.T, whoIs map[string]*apitype.WhoIsResponse, self func() *ipnstate.PeerStatus) *http.Server {
	return &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/localapi/v0/whois":
			addr := r.URL.Query().Get("addr")
			if addr == "" {
				t.Fatalf("/whois call missing \"addr\" query")
			}
			if node := whoIs[addr]; node != nil {
				writeJSON(w, &node)
				return
			}
			http.Error(w, "not a node", http.StatusUnauthorized)
			return
		case "/localapi/v0/status":
			writeJSON(w, ipnstate.Status{Self: self()})
			return
		default:
			t.Fatalf("unhandled localapi test endpoint %q, add to localapi handler func in test", r.URL.Path)
		}
	})}
}

func mockNewAuthURL(_ context.Context, src tailcfg.NodeID) (*tailcfg.WebClientAuthResponse, error) {
	// Create new dummy auth URL.
	return &tailcfg.WebClientAuthResponse{ID: testAuthPath, URL: testControlURL + testAuthPath}, nil
}

func mockWaitAuthURL(_ context.Context, id string, src tailcfg.NodeID) (*tailcfg.WebClientAuthResponse, error) {
	switch id {
	case testAuthPathSuccess: // successful auth URL
		return &tailcfg.WebClientAuthResponse{Complete: true}, nil
	case testAuthPathError: // error auth URL
		return nil, errors.New("authenticated as wrong user")
	default:
		return nil, errors.New("unknown id")
	}
}
