// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package web

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"tailscale.com/client/local"
	"tailscale.com/client/tailscale/apitype"
	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/net/memnet"
	"tailscale.com/tailcfg"
	"tailscale.com/types/views"
	"tailscale.com/util/httpm"
	"tailscale.com/util/syspolicy/policyclient"
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
//  2. permissioning of api endpoints based on node capabilities
func TestServeAPI(t *testing.T) {
	selfTags := views.SliceOf([]string{"tag:server"})
	self := &ipnstate.PeerStatus{ID: "self", Tags: &selfTags}
	prefs := &ipn.Prefs{}

	remoteUser := &tailcfg.UserProfile{ID: tailcfg.UserID(1)}
	remoteIPWithAllCapabilities := "100.100.100.101"
	remoteIPWithNoCapabilities := "100.100.100.102"

	lal := memnet.Listen("local-tailscaled.sock:80")
	defer lal.Close()
	localapi := mockLocalAPI(t,
		map[string]*apitype.WhoIsResponse{
			remoteIPWithAllCapabilities: {
				Node:        &tailcfg.Node{StableID: "node1"},
				UserProfile: remoteUser,
				CapMap:      tailcfg.PeerCapMap{tailcfg.PeerCapabilityWebUI: []tailcfg.RawMessage{"{\"canEdit\":[\"*\"]}"}},
			},
			remoteIPWithNoCapabilities: {
				Node:        &tailcfg.Node{StableID: "node2"},
				UserProfile: remoteUser,
			},
		},
		func() *ipnstate.PeerStatus { return self },
		func() *ipn.Prefs { return prefs },
		nil,
	)
	defer localapi.Close()
	go localapi.Serve(lal)

	s := &Server{
		mode:    ManageServerMode,
		lc:      &local.Client{Dial: lal.Dial},
		timeNow: time.Now,
	}

	type requestTest struct {
		remoteIP     string
		wantResponse string
		wantStatus   int
	}

	tests := []struct {
		reqPath        string
		reqMethod      string
		reqContentType string
		reqBody        string
		tests          []requestTest
	}{{
		reqPath:   "/not-an-endpoint",
		reqMethod: httpm.POST,
		tests: []requestTest{{
			remoteIP:     remoteIPWithNoCapabilities,
			wantResponse: "invalid endpoint",
			wantStatus:   http.StatusNotFound,
		}, {
			remoteIP:     remoteIPWithAllCapabilities,
			wantResponse: "invalid endpoint",
			wantStatus:   http.StatusNotFound,
		}},
	}, {
		reqPath:   "/local/v0/not-an-endpoint",
		reqMethod: httpm.POST,
		tests: []requestTest{{
			remoteIP:     remoteIPWithNoCapabilities,
			wantResponse: "invalid endpoint",
			wantStatus:   http.StatusNotFound,
		}, {
			remoteIP:     remoteIPWithAllCapabilities,
			wantResponse: "invalid endpoint",
			wantStatus:   http.StatusNotFound,
		}},
	}, {
		reqPath:   "/local/v0/logout",
		reqMethod: httpm.POST,
		tests: []requestTest{{
			remoteIP:     remoteIPWithNoCapabilities,
			wantResponse: "not allowed", // requesting node has insufficient permissions
			wantStatus:   http.StatusUnauthorized,
		}, {
			remoteIP:     remoteIPWithAllCapabilities,
			wantResponse: "success", // requesting node has sufficient permissions
			wantStatus:   http.StatusOK,
		}},
	}, {
		reqPath:   "/exit-nodes",
		reqMethod: httpm.GET,
		tests: []requestTest{{
			remoteIP:     remoteIPWithNoCapabilities,
			wantResponse: "null",
			wantStatus:   http.StatusOK, // allowed, no additional capabilities required
		}, {
			remoteIP:     remoteIPWithAllCapabilities,
			wantResponse: "null",
			wantStatus:   http.StatusOK,
		}},
	}, {
		reqPath:   "/routes",
		reqMethod: httpm.POST,
		reqBody:   "{\"setExitNode\":true}",
		tests: []requestTest{{
			remoteIP:     remoteIPWithNoCapabilities,
			wantResponse: "not allowed",
			wantStatus:   http.StatusUnauthorized,
		}, {
			remoteIP:   remoteIPWithAllCapabilities,
			wantStatus: http.StatusOK,
		}},
	}, {
		reqPath:        "/local/v0/prefs",
		reqMethod:      httpm.PATCH,
		reqBody:        "{\"runSSHSet\":true}",
		reqContentType: "application/json",
		tests: []requestTest{{
			remoteIP:     remoteIPWithNoCapabilities,
			wantResponse: "not allowed",
			wantStatus:   http.StatusUnauthorized,
		}, {
			remoteIP:   remoteIPWithAllCapabilities,
			wantStatus: http.StatusOK,
		}},
	}, {
		reqPath:        "/local/v0/prefs",
		reqMethod:      httpm.PATCH,
		reqContentType: "multipart/form-data",
		tests: []requestTest{{
			remoteIP:     remoteIPWithNoCapabilities,
			wantResponse: "invalid request",
			wantStatus:   http.StatusBadRequest,
		}, {
			remoteIP:     remoteIPWithAllCapabilities,
			wantResponse: "invalid request",
			wantStatus:   http.StatusBadRequest,
		}},
	}}
	for _, tt := range tests {
		for _, req := range tt.tests {
			t.Run(req.remoteIP+"_requesting_"+tt.reqPath, func(t *testing.T) {
				var reqBody io.Reader
				if tt.reqBody != "" {
					reqBody = bytes.NewBuffer([]byte(tt.reqBody))
				}
				r := httptest.NewRequest(tt.reqMethod, "/api"+tt.reqPath, reqBody)
				r.RemoteAddr = req.remoteIP
				if tt.reqContentType != "" {
					r.Header.Add("Content-Type", tt.reqContentType)
				}
				w := httptest.NewRecorder()

				s.serveAPI(w, r)
				res := w.Result()
				defer res.Body.Close()
				if gotStatus := res.StatusCode; req.wantStatus != gotStatus {
					t.Errorf("wrong status; want=%v, got=%v", req.wantStatus, gotStatus)
				}
				body, err := io.ReadAll(res.Body)
				if err != nil {
					t.Fatal(err)
				}
				gotResp := strings.TrimSuffix(string(body), "\n") // trim trailing newline
				if req.wantResponse != gotResp {
					t.Errorf("wrong response; want=%q, got=%q", req.wantResponse, gotResp)
				}
			})
		}
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
	localapi := mockLocalAPI(t, tailnetNodes, func() *ipnstate.PeerStatus { return selfNode }, nil, nil)
	defer localapi.Close()
	go localapi.Serve(lal)

	s := &Server{
		timeNow: time.Now,
		lc:      &local.Client{Dial: lal.Dial},
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
			session, _, _, err := s.getSession(r)
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
		nil,
		nil,
	)
	defer localapi.Close()
	go localapi.Serve(lal)

	s := &Server{
		mode:    ManageServerMode,
		lc:      &local.Client{Dial: lal.Dial},
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
		Capabilities:  peerCapabilities{capFeatureAll: true},
	}

	testControlURL := &defaultControlURL

	lal := memnet.Listen("local-tailscaled.sock:80")
	defer lal.Close()
	localapi := mockLocalAPI(t,
		map[string]*apitype.WhoIsResponse{remoteIP: remoteNode},
		func() *ipnstate.PeerStatus { return self },
		func() *ipn.Prefs {
			return &ipn.Prefs{ControlURL: *testControlURL}
		},
		nil,
	)
	defer localapi.Close()
	go localapi.Serve(lal)

	timeNow := time.Now()
	oneHourAgo := timeNow.Add(-time.Hour)
	sixtyDaysAgo := timeNow.Add(-sessionCookieExpiry * 2)

	s := &Server{
		mode:        ManageServerMode,
		lc:          &local.Client{Dial: lal.Dial},
		timeNow:     func() time.Time { return timeNow },
		newAuthURL:  mockNewAuthURL,
		waitAuthURL: mockWaitAuthURL,
		polc:        policyclient.NoPolicyClient{},
	}

	successCookie := "ts-cookie-success"
	s.browserSessions.Store(successCookie, &browserSession{
		ID:      successCookie,
		SrcNode: remoteNode.Node.ID,
		SrcUser: user.ID,
		Created: oneHourAgo,
		AuthID:  testAuthPathSuccess,
		AuthURL: *testControlURL + testAuthPathSuccess,
	})
	failureCookie := "ts-cookie-failure"
	s.browserSessions.Store(failureCookie, &browserSession{
		ID:      failureCookie,
		SrcNode: remoteNode.Node.ID,
		SrcUser: user.ID,
		Created: oneHourAgo,
		AuthID:  testAuthPathError,
		AuthURL: *testControlURL + testAuthPathError,
	})
	expiredCookie := "ts-cookie-expired"
	s.browserSessions.Store(expiredCookie, &browserSession{
		ID:      expiredCookie,
		SrcNode: remoteNode.Node.ID,
		SrcUser: user.ID,
		Created: sixtyDaysAgo,
		AuthID:  "/a/old-auth-url",
		AuthURL: *testControlURL + "/a/old-auth-url",
	})

	tests := []struct {
		name string

		controlURL    string          // if empty, defaultControlURL is used
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
			wantResp:      &authResponse{ViewerIdentity: vi, ServerMode: ManageServerMode},
			wantNewCookie: false,
			wantSession:   nil,
		},
		{
			name:          "new-session",
			path:          "/api/auth/session/new",
			wantStatus:    http.StatusOK,
			wantResp:      &newSessionAuthResponse{AuthURL: *testControlURL + testAuthPath},
			wantNewCookie: true,
			wantSession: &browserSession{
				ID:            "GENERATED_ID", // gets swapped for newly created ID by test
				SrcNode:       remoteNode.Node.ID,
				SrcUser:       user.ID,
				Created:       timeNow,
				AuthID:        testAuthPath,
				AuthURL:       *testControlURL + testAuthPath,
				Authenticated: false,
			},
		},
		{
			name:       "query-existing-incomplete-session",
			path:       "/api/auth",
			cookie:     successCookie,
			wantStatus: http.StatusOK,
			wantResp:   &authResponse{ViewerIdentity: vi, ServerMode: ManageServerMode},
			wantSession: &browserSession{
				ID:            successCookie,
				SrcNode:       remoteNode.Node.ID,
				SrcUser:       user.ID,
				Created:       oneHourAgo,
				AuthID:        testAuthPathSuccess,
				AuthURL:       *testControlURL + testAuthPathSuccess,
				Authenticated: false,
			},
		},
		{
			name:       "existing-session-used",
			path:       "/api/auth/session/new", // should not create new session
			cookie:     successCookie,
			wantStatus: http.StatusOK,
			wantResp:   &newSessionAuthResponse{AuthURL: *testControlURL + testAuthPathSuccess},
			wantSession: &browserSession{
				ID:            successCookie,
				SrcNode:       remoteNode.Node.ID,
				SrcUser:       user.ID,
				Created:       oneHourAgo,
				AuthID:        testAuthPathSuccess,
				AuthURL:       *testControlURL + testAuthPathSuccess,
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
				AuthURL:       *testControlURL + testAuthPathSuccess,
				Authenticated: true,
			},
		},
		{
			name:       "query-existing-complete-session",
			path:       "/api/auth",
			cookie:     successCookie,
			wantStatus: http.StatusOK,
			wantResp:   &authResponse{Authorized: true, ViewerIdentity: vi, ServerMode: ManageServerMode},
			wantSession: &browserSession{
				ID:            successCookie,
				SrcNode:       remoteNode.Node.ID,
				SrcUser:       user.ID,
				Created:       oneHourAgo,
				AuthID:        testAuthPathSuccess,
				AuthURL:       *testControlURL + testAuthPathSuccess,
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
			wantResp:      &newSessionAuthResponse{AuthURL: *testControlURL + testAuthPath},
			wantNewCookie: true,
			wantSession: &browserSession{
				ID:            "GENERATED_ID",
				SrcNode:       remoteNode.Node.ID,
				SrcUser:       user.ID,
				Created:       timeNow,
				AuthID:        testAuthPath,
				AuthURL:       *testControlURL + testAuthPath,
				Authenticated: false,
			},
		},
		{
			name:          "expired-cookie-gets-new-session",
			path:          "/api/auth/session/new",
			cookie:        expiredCookie,
			wantStatus:    http.StatusOK,
			wantResp:      &newSessionAuthResponse{AuthURL: *testControlURL + testAuthPath},
			wantNewCookie: true,
			wantSession: &browserSession{
				ID:            "GENERATED_ID",
				SrcNode:       remoteNode.Node.ID,
				SrcUser:       user.ID,
				Created:       timeNow,
				AuthID:        testAuthPath,
				AuthURL:       *testControlURL + testAuthPath,
				Authenticated: false,
			},
		},
		{
			name:          "control-server-no-check-mode",
			controlURL:    "http://alternate-server.com/",
			path:          "/api/auth/session/new",
			wantStatus:    http.StatusOK,
			wantResp:      &newSessionAuthResponse{},
			wantNewCookie: true,
			wantSession: &browserSession{
				ID:            "GENERATED_ID", // gets swapped for newly created ID by test
				SrcNode:       remoteNode.Node.ID,
				SrcUser:       user.ID,
				Created:       timeNow,
				Authenticated: true,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.controlURL != "" {
				testControlURL = &tt.controlURL
			} else {
				testControlURL = &defaultControlURL
			}

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

// TestServeAPIAuthMetricLogging specifically tests metric logging in the serveAPIAuth function.
// For each given test case, we assert that the local API received a request to log the expected metric.
func TestServeAPIAuthMetricLogging(t *testing.T) {
	user := &tailcfg.UserProfile{LoginName: "user@example.com", ID: tailcfg.UserID(1)}
	otherUser := &tailcfg.UserProfile{LoginName: "user2@example.com", ID: tailcfg.UserID(2)}
	self := &ipnstate.PeerStatus{
		ID:           "self",
		UserID:       user.ID,
		TailscaleIPs: []netip.Addr{netip.MustParseAddr("100.1.2.3")},
	}
	remoteIP := "100.100.100.101"
	remoteNode := &apitype.WhoIsResponse{
		Node: &tailcfg.Node{
			Name:      "remote-managed",
			ID:        1,
			Addresses: []netip.Prefix{netip.MustParsePrefix(remoteIP + "/32")},
		},
		UserProfile: user,
	}
	remoteTaggedIP := "100.123.100.213"
	remoteTaggedNode := &apitype.WhoIsResponse{
		Node: &tailcfg.Node{
			Name:      "remote-tagged",
			ID:        2,
			Addresses: []netip.Prefix{netip.MustParsePrefix(remoteTaggedIP + "/32")},
			Tags:      []string{"dev-machine"},
		},
		UserProfile: user,
	}
	localIP := "100.1.2.3"
	localNode := &apitype.WhoIsResponse{
		Node: &tailcfg.Node{
			Name:      "local-managed",
			ID:        3,
			StableID:  "self",
			Addresses: []netip.Prefix{netip.MustParsePrefix(localIP + "/32")},
		},
		UserProfile: user,
	}
	localTaggedIP := "100.1.2.133"
	localTaggedNode := &apitype.WhoIsResponse{
		Node: &tailcfg.Node{
			Name:      "local-tagged",
			ID:        4,
			StableID:  "self",
			Addresses: []netip.Prefix{netip.MustParsePrefix(localTaggedIP + "/32")},
			Tags:      []string{"prod-machine"},
		},
		UserProfile: user,
	}
	otherIP := "100.100.2.3"
	otherNode := &apitype.WhoIsResponse{
		Node: &tailcfg.Node{
			Name:      "other-node",
			ID:        5,
			Addresses: []netip.Prefix{netip.MustParsePrefix(otherIP + "/32")},
		},
		UserProfile: otherUser,
	}
	nonTailscaleIP := "10.100.2.3"

	testControlURL := &defaultControlURL
	var loggedMetrics []string

	lal := memnet.Listen("local-tailscaled.sock:80")
	defer lal.Close()
	localapi := mockLocalAPI(t,
		map[string]*apitype.WhoIsResponse{remoteIP: remoteNode, localIP: localNode, otherIP: otherNode, localTaggedIP: localTaggedNode, remoteTaggedIP: remoteTaggedNode},
		func() *ipnstate.PeerStatus { return self },
		func() *ipn.Prefs {
			return &ipn.Prefs{ControlURL: *testControlURL}
		},
		func(metricName string) {
			loggedMetrics = append(loggedMetrics, metricName)
		},
	)
	defer localapi.Close()
	go localapi.Serve(lal)

	timeNow := time.Now()
	oneHourAgo := timeNow.Add(-time.Hour)

	s := &Server{
		mode:        ManageServerMode,
		lc:          &local.Client{Dial: lal.Dial},
		timeNow:     func() time.Time { return timeNow },
		newAuthURL:  mockNewAuthURL,
		waitAuthURL: mockWaitAuthURL,
	}

	authenticatedRemoteNodeCookie := "ts-cookie-remote-node-authenticated"
	s.browserSessions.Store(authenticatedRemoteNodeCookie, &browserSession{
		ID:            authenticatedRemoteNodeCookie,
		SrcNode:       remoteNode.Node.ID,
		SrcUser:       user.ID,
		Created:       oneHourAgo,
		AuthID:        testAuthPathSuccess,
		AuthURL:       *testControlURL + testAuthPathSuccess,
		Authenticated: true,
	})
	authenticatedLocalNodeCookie := "ts-cookie-local-node-authenticated"
	s.browserSessions.Store(authenticatedLocalNodeCookie, &browserSession{
		ID:            authenticatedLocalNodeCookie,
		SrcNode:       localNode.Node.ID,
		SrcUser:       user.ID,
		Created:       oneHourAgo,
		AuthID:        testAuthPathSuccess,
		AuthURL:       *testControlURL + testAuthPathSuccess,
		Authenticated: true,
	})
	unauthenticatedRemoteNodeCookie := "ts-cookie-remote-node-unauthenticated"
	s.browserSessions.Store(unauthenticatedRemoteNodeCookie, &browserSession{
		ID:            unauthenticatedRemoteNodeCookie,
		SrcNode:       remoteNode.Node.ID,
		SrcUser:       user.ID,
		Created:       oneHourAgo,
		AuthID:        testAuthPathSuccess,
		AuthURL:       *testControlURL + testAuthPathSuccess,
		Authenticated: false,
	})
	unauthenticatedLocalNodeCookie := "ts-cookie-local-node-unauthenticated"
	s.browserSessions.Store(unauthenticatedLocalNodeCookie, &browserSession{
		ID:            unauthenticatedLocalNodeCookie,
		SrcNode:       localNode.Node.ID,
		SrcUser:       user.ID,
		Created:       oneHourAgo,
		AuthID:        testAuthPathSuccess,
		AuthURL:       *testControlURL + testAuthPathSuccess,
		Authenticated: false,
	})

	tests := []struct {
		name       string
		cookie     string // cookie attached to request
		remoteAddr string // remote address to hit

		wantLoggedMetric string // expected metric to be logged
	}{
		{
			name:             "managing-remote",
			cookie:           authenticatedRemoteNodeCookie,
			remoteAddr:       remoteIP,
			wantLoggedMetric: "web_client_managing_remote",
		},
		{
			name:             "managing-local",
			cookie:           authenticatedLocalNodeCookie,
			remoteAddr:       localIP,
			wantLoggedMetric: "web_client_managing_local",
		},
		{
			name:             "viewing-not-owner",
			cookie:           authenticatedRemoteNodeCookie,
			remoteAddr:       otherIP,
			wantLoggedMetric: "web_client_viewing_not_owner",
		},
		{
			name:             "viewing-local-tagged",
			cookie:           authenticatedLocalNodeCookie,
			remoteAddr:       localTaggedIP,
			wantLoggedMetric: "web_client_viewing_local_tag",
		},
		{
			name:             "viewing-remote-tagged",
			cookie:           authenticatedRemoteNodeCookie,
			remoteAddr:       remoteTaggedIP,
			wantLoggedMetric: "web_client_viewing_remote_tag",
		},
		{
			name:             "viewing-local-non-tailscale",
			cookie:           authenticatedLocalNodeCookie,
			remoteAddr:       nonTailscaleIP,
			wantLoggedMetric: "web_client_viewing_local",
		},
		{
			name:             "viewing-local-unauthenticated",
			cookie:           unauthenticatedLocalNodeCookie,
			remoteAddr:       localIP,
			wantLoggedMetric: "web_client_viewing_local",
		},
		{
			name:             "viewing-remote-unauthenticated",
			cookie:           unauthenticatedRemoteNodeCookie,
			remoteAddr:       remoteIP,
			wantLoggedMetric: "web_client_viewing_remote",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			testControlURL = &defaultControlURL

			r := httptest.NewRequest("GET", "http://100.1.2.3:5252/api/auth", nil)
			r.RemoteAddr = tt.remoteAddr
			r.AddCookie(&http.Cookie{Name: sessionCookieName, Value: tt.cookie})
			w := httptest.NewRecorder()
			s.serveAPIAuth(w, r)

			if !slices.Contains(loggedMetrics, tt.wantLoggedMetric) {
				t.Errorf("expected logged metrics to contain: '%s' but was: '%v'", tt.wantLoggedMetric, loggedMetrics)
			}
			loggedMetrics = []string{}

			res := w.Result()
			defer res.Body.Close()
		})
	}
}

// TestPathPrefix tests that the provided path prefix is normalized correctly.
// If a leading '/' is missing, one should be added.
// If multiple leading '/' are present, they should be collapsed to one.
// Additionally verify that this prevents open redirects when enforcing the path prefix.
func TestPathPrefix(t *testing.T) {
	tests := []struct {
		name         string
		prefix       string
		wantPrefix   string
		wantLocation string
	}{
		{
			name:         "no-leading-slash",
			prefix:       "javascript:alert(1)",
			wantPrefix:   "/javascript:alert(1)",
			wantLocation: "/javascript:alert(1)/",
		},
		{
			name:   "2-slashes",
			prefix: "//evil.example.com/goat",
			// We must also get the trailing slash added:
			wantPrefix:   "/evil.example.com/goat",
			wantLocation: "/evil.example.com/goat/",
		},
		{
			name:   "absolute-url",
			prefix: "http://evil.example.com",
			// We must also get the trailing slash added:
			wantPrefix:   "/http:/evil.example.com",
			wantLocation: "/http:/evil.example.com/",
		},
		{
			name:   "double-dot",
			prefix: "/../.././etc/passwd",
			// We must also get the trailing slash added:
			wantPrefix:   "/etc/passwd",
			wantLocation: "/etc/passwd/",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			options := ServerOpts{
				Mode:       LoginServerMode,
				PathPrefix: tt.prefix,
				CGIMode:    true,
			}
			s, err := NewServer(options)
			if err != nil {
				t.Error(err)
			}

			// verify provided prefix was normalized correctly
			if s.pathPrefix != tt.wantPrefix {
				t.Errorf("prefix was not normalized correctly; want=%q, got=%q", tt.wantPrefix, s.pathPrefix)
			}

			s.logf = t.Logf
			r := httptest.NewRequest(httpm.GET, "http://localhost/", nil)
			w := httptest.NewRecorder()
			s.ServeHTTP(w, r)
			res := w.Result()
			defer res.Body.Close()

			location := w.Header().Get("Location")
			if location != tt.wantLocation {
				t.Errorf("request got wrong location; want=%q, got=%q", tt.wantLocation, location)
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
	localapi := mockLocalAPI(t, nil, func() *ipnstate.PeerStatus { return self }, nil, nil)
	defer localapi.Close()
	go localapi.Serve(lal)

	s := &Server{
		mode:    ManageServerMode,
		lc:      &local.Client{Dial: lal.Dial},
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
		{
			name:        "quad-100:80",
			target:      "http://100.100.100.100:80/",
			wantHandled: false,
		},
		{
			name:        "ipv6-service-addr:80",
			target:      "http://[fd7a:115c:a1e0::53]:80/",
			wantHandled: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
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

func TestPeerCapabilities(t *testing.T) {
	userOwnedStatus := &ipnstate.Status{Self: &ipnstate.PeerStatus{UserID: tailcfg.UserID(1)}}
	tags := views.SliceOf[string]([]string{"tag:server"})
	tagOwnedStatus := &ipnstate.Status{Self: &ipnstate.PeerStatus{Tags: &tags}}

	// Testing web.toPeerCapabilities
	toPeerCapsTests := []struct {
		name     string
		status   *ipnstate.Status
		whois    *apitype.WhoIsResponse
		wantCaps peerCapabilities
	}{
		{
			name:     "empty-whois",
			status:   userOwnedStatus,
			whois:    nil,
			wantCaps: peerCapabilities{},
		},
		{
			name:   "user-owned-node-non-owner-caps-ignored",
			status: userOwnedStatus,
			whois: &apitype.WhoIsResponse{
				UserProfile: &tailcfg.UserProfile{ID: tailcfg.UserID(2)},
				Node:        &tailcfg.Node{ID: tailcfg.NodeID(1)},
				CapMap: tailcfg.PeerCapMap{
					tailcfg.PeerCapabilityWebUI: []tailcfg.RawMessage{
						"{\"canEdit\":[\"ssh\",\"subnets\"]}",
					},
				},
			},
			wantCaps: peerCapabilities{},
		},
		{
			name:   "user-owned-node-owner-caps-ignored",
			status: userOwnedStatus,
			whois: &apitype.WhoIsResponse{
				UserProfile: &tailcfg.UserProfile{ID: tailcfg.UserID(1)},
				Node:        &tailcfg.Node{ID: tailcfg.NodeID(1)},
				CapMap: tailcfg.PeerCapMap{
					tailcfg.PeerCapabilityWebUI: []tailcfg.RawMessage{
						"{\"canEdit\":[\"ssh\",\"subnets\"]}",
					},
				},
			},
			wantCaps: peerCapabilities{capFeatureAll: true}, // should just have wildcard
		},
		{
			name:   "tag-owned-no-webui-caps",
			status: tagOwnedStatus,
			whois: &apitype.WhoIsResponse{
				Node: &tailcfg.Node{ID: tailcfg.NodeID(1)},
				CapMap: tailcfg.PeerCapMap{
					tailcfg.PeerCapabilityDebugPeer: []tailcfg.RawMessage{},
				},
			},
			wantCaps: peerCapabilities{},
		},
		{
			name:   "tag-owned-one-webui-cap",
			status: tagOwnedStatus,
			whois: &apitype.WhoIsResponse{
				Node: &tailcfg.Node{ID: tailcfg.NodeID(1)},
				CapMap: tailcfg.PeerCapMap{
					tailcfg.PeerCapabilityWebUI: []tailcfg.RawMessage{
						"{\"canEdit\":[\"ssh\",\"subnets\"]}",
					},
				},
			},
			wantCaps: peerCapabilities{
				capFeatureSSH:     true,
				capFeatureSubnets: true,
			},
		},
		{
			name:   "tag-owned-multiple-webui-cap",
			status: tagOwnedStatus,
			whois: &apitype.WhoIsResponse{
				Node: &tailcfg.Node{ID: tailcfg.NodeID(1)},
				CapMap: tailcfg.PeerCapMap{
					tailcfg.PeerCapabilityWebUI: []tailcfg.RawMessage{
						"{\"canEdit\":[\"ssh\",\"subnets\"]}",
						"{\"canEdit\":[\"subnets\",\"exitnodes\",\"*\"]}",
					},
				},
			},
			wantCaps: peerCapabilities{
				capFeatureSSH:       true,
				capFeatureSubnets:   true,
				capFeatureExitNodes: true,
				capFeatureAll:       true,
			},
		},
		{
			name:   "tag-owned-case-insensitive-caps",
			status: tagOwnedStatus,
			whois: &apitype.WhoIsResponse{
				Node: &tailcfg.Node{ID: tailcfg.NodeID(1)},
				CapMap: tailcfg.PeerCapMap{
					tailcfg.PeerCapabilityWebUI: []tailcfg.RawMessage{
						"{\"canEdit\":[\"SSH\",\"sUBnets\"]}",
					},
				},
			},
			wantCaps: peerCapabilities{
				capFeatureSSH:     true,
				capFeatureSubnets: true,
			},
		},
		{
			name:   "tag-owned-random-canEdit-contents-get-dropped",
			status: tagOwnedStatus,
			whois: &apitype.WhoIsResponse{
				Node: &tailcfg.Node{ID: tailcfg.NodeID(1)},
				CapMap: tailcfg.PeerCapMap{
					tailcfg.PeerCapabilityWebUI: []tailcfg.RawMessage{
						"{\"canEdit\":[\"unknown-feature\"]}",
					},
				},
			},
			wantCaps: peerCapabilities{},
		},
		{
			name:   "tag-owned-no-canEdit-section",
			status: tagOwnedStatus,
			whois: &apitype.WhoIsResponse{
				Node: &tailcfg.Node{ID: tailcfg.NodeID(1)},
				CapMap: tailcfg.PeerCapMap{
					tailcfg.PeerCapabilityWebUI: []tailcfg.RawMessage{
						"{\"canDoSomething\":[\"*\"]}",
					},
				},
			},
			wantCaps: peerCapabilities{},
		},
		{
			name:   "tagged-source-caps-ignored",
			status: tagOwnedStatus,
			whois: &apitype.WhoIsResponse{
				Node: &tailcfg.Node{ID: tailcfg.NodeID(1), Tags: tags.AsSlice()},
				CapMap: tailcfg.PeerCapMap{
					tailcfg.PeerCapabilityWebUI: []tailcfg.RawMessage{
						"{\"canEdit\":[\"ssh\",\"subnets\"]}",
					},
				},
			},
			wantCaps: peerCapabilities{},
		},
	}
	for _, tt := range toPeerCapsTests {
		t.Run("toPeerCapabilities-"+tt.name, func(t *testing.T) {
			got, err := toPeerCapabilities(tt.status, tt.whois)
			if err != nil {
				t.Fatalf("unexpected: %v", err)
			}
			if diff := cmp.Diff(got, tt.wantCaps); diff != "" {
				t.Errorf("wrong caps; (-got+want):%v", diff)
			}
		})
	}

	// Testing web.peerCapabilities.canEdit
	canEditTests := []struct {
		name        string
		caps        peerCapabilities
		wantCanEdit map[capFeature]bool
	}{
		{
			name: "empty-caps",
			caps: nil,
			wantCanEdit: map[capFeature]bool{
				capFeatureAll:       false,
				capFeatureSSH:       false,
				capFeatureSubnets:   false,
				capFeatureExitNodes: false,
				capFeatureAccount:   false,
			},
		},
		{
			name: "some-caps",
			caps: peerCapabilities{capFeatureSSH: true, capFeatureAccount: true},
			wantCanEdit: map[capFeature]bool{
				capFeatureAll:       false,
				capFeatureSSH:       true,
				capFeatureSubnets:   false,
				capFeatureExitNodes: false,
				capFeatureAccount:   true,
			},
		},
		{
			name: "wildcard-in-caps",
			caps: peerCapabilities{capFeatureAll: true, capFeatureAccount: true},
			wantCanEdit: map[capFeature]bool{
				capFeatureAll:       true,
				capFeatureSSH:       true,
				capFeatureSubnets:   true,
				capFeatureExitNodes: true,
				capFeatureAccount:   true,
			},
		},
	}
	for _, tt := range canEditTests {
		t.Run("canEdit-"+tt.name, func(t *testing.T) {
			for f, want := range tt.wantCanEdit {
				if got := tt.caps.canEdit(f); got != want {
					t.Errorf("wrong canEdit(%s); got=%v, want=%v", f, got, want)
				}
			}
		})
	}
}

var (
	defaultControlURL   = "https://controlplane.tailscale.com"
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
func mockLocalAPI(t *testing.T, whoIs map[string]*apitype.WhoIsResponse, self func() *ipnstate.PeerStatus, prefs func() *ipn.Prefs, metricCapture func(string)) *http.Server {
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
		case "/localapi/v0/prefs":
			writeJSON(w, prefs())
			return
		case "/localapi/v0/upload-client-metrics":
			type metricName struct {
				Name string `json:"name"`
			}

			var metricNames []metricName
			if err := json.NewDecoder(r.Body).Decode(&metricNames); err != nil {
				http.Error(w, "invalid JSON body", http.StatusBadRequest)
				return
			}
			metricCapture(metricNames[0].Name)
			writeJSON(w, struct{}{})
			return
		case "/localapi/v0/logout":
			fmt.Fprintf(w, "success")
			return
		default:
			t.Fatalf("unhandled localapi test endpoint %q, add to localapi handler func in test", r.URL.Path)
		}
	})}
}

func mockNewAuthURL(_ context.Context, src tailcfg.NodeID) (*tailcfg.WebClientAuthResponse, error) {
	// Create new dummy auth URL.
	return &tailcfg.WebClientAuthResponse{ID: testAuthPath, URL: defaultControlURL + testAuthPath}, nil
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

func TestCSRFProtect(t *testing.T) {
	tests := []struct {
		name           string
		method         string
		secFetchSite   string
		host           string
		origin         string
		originOverride string
		wantError      bool
	}{
		{
			name:   "GET requests with no header are allowed",
			method: "GET",
		},
		{
			name:         "POST requests with same-origin are allowed",
			method:       "POST",
			secFetchSite: "same-origin",
		},
		{
			name:         "POST requests with cross-site are not allowed",
			method:       "POST",
			secFetchSite: "cross-site",
			wantError:    true,
		},
		{
			name:         "POST requests with unknown sec-fetch-site values are not allowed",
			method:       "POST",
			secFetchSite: "new-unknown-value",
			wantError:    true,
		},
		{
			name:         "POST requests with none are not allowed",
			method:       "POST",
			secFetchSite: "none",
			wantError:    true,
		},
		{
			name:   "POST requests with no sec-fetch-site header but matching host and origin are allowed",
			method: "POST",
			host:   "example.com",
			origin: "https://example.com",
		},
		{
			name:      "POST requests with no sec-fetch-site and non-matching host and origin are not allowed",
			method:    "POST",
			host:      "example.com",
			origin:    "https://example.net",
			wantError: true,
		},
		{
			name:           "POST requests with no sec-fetch-site and and origin that matches the override are allowed",
			method:         "POST",
			originOverride: "example.net",
			host:           "internal.example.foo", // Host can be changed by reverse proxies
			origin:         "http://example.net",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				fmt.Fprintf(w, "OK")
			})

			s := &Server{
				originOverride: tt.originOverride,
			}
			withCSRF := s.csrfProtect(handler)

			r := httptest.NewRequest(tt.method, "http://example.com/", nil)
			if tt.secFetchSite != "" {
				r.Header.Set("Sec-Fetch-Site", tt.secFetchSite)
			}
			if tt.host != "" {
				r.Host = tt.host
			}
			if tt.origin != "" {
				r.Header.Set("Origin", tt.origin)
			}

			w := httptest.NewRecorder()
			withCSRF.ServeHTTP(w, r)
			res := w.Result()
			defer res.Body.Close()
			if tt.wantError {
				if res.StatusCode != http.StatusForbidden {
					t.Errorf("expected status forbidden, got %v", res.StatusCode)
				}
				return
			}
			if res.StatusCode != http.StatusOK {
				t.Errorf("expected status ok, got %v", res.StatusCode)
			}
		})
	}
}
