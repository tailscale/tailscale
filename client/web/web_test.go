// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package web

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"tailscale.com/client/tailscale"
	"tailscale.com/client/tailscale/apitype"
	"tailscale.com/net/memnet"
	"tailscale.com/tailcfg"
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

// TestAuthorizeRequest tests the s.authorizeRequest function.
// 2023-10-18: These tests currently cover tailscale auth mode (not platform auth).
func TestAuthorizeRequest(t *testing.T) {
	remoteTSAddr := "100.100.100.101"

	lal := memnet.Listen("local-tailscaled.sock:80")
	defer lal.Close()
	localapi := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/localapi/v0/whois":
			// Just passes back a whois response when request was made from `remoteTSAddr`.
			if addr := r.URL.Query().Get("addr"); addr == remoteTSAddr {
				if err := json.NewEncoder(w).Encode(&apitype.WhoIsResponse{
					Node:        &tailcfg.Node{StableID: "node"},
					UserProfile: &tailcfg.UserProfile{ID: tailcfg.UserID(1)},
				}); err != nil {
					http.Error(w, err.Error(), http.StatusInternalServerError)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				return
			}
			http.Error(w, "not a node", http.StatusUnauthorized)
			return
		default:
			t.Fatalf("unhandled localapi test endpoint %q, add to localapi handler func in test", r.URL.Path)
		}
	})}
	defer localapi.Close()
	go localapi.Serve(lal)

	s := &Server{
		lc:          &tailscale.LocalClient{Dial: lal.Dial},
		tsDebugMode: "full",
		timeNow:     time.Now,
		auth:        &mockAuthServer{},
	}

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
		reqPath:                "/api/auth",
		reqMethod:              httpm.GET,
		wantOkNotOverTailscale: false,
		wantOkWithoutSession:   true,
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
					r.AddCookie(&http.Cookie{Name: mockCookieName, Value: cookie})
				}
				w := httptest.NewRecorder()
				return s.authorizeRequest(w, r)
			}
			// Do request from non-Tailscale IP.
			if gotOk := doAuthorize("123.456.789.999", ""); gotOk != tt.wantOkNotOverTailscale {
				t.Errorf("wantOkNotOverTailscale; want=%v, got=%v", tt.wantOkNotOverTailscale, gotOk)
			}
			// Do request from Tailscale IP w/o associated session.
			if gotOk := doAuthorize(remoteTSAddr, ""); gotOk != tt.wantOkWithoutSession {
				t.Errorf("wantOkWithoutSession; want=%v, got=%v", tt.wantOkWithoutSession, gotOk)
			}
			// Do request from Tailscale IP w/ associated session.
			if gotOk := doAuthorize(remoteTSAddr, mockValidCookie); gotOk != tt.wantOkWithSession {
				t.Errorf("wantOkWithSession; want=%v, got=%v", tt.wantOkWithSession, gotOk)
			}
		})
	}
}

type mockAuthServer struct{}

var (
	mockCookieName  = "TS-Web-Session"
	mockValidCookie = "ts-cookie-valid"
)

func (s *mockAuthServer) IsLoggedIn(r *http.Request) bool {
	c, err := r.Cookie(mockCookieName)
	return err == nil && c.Value == mockValidCookie
}
func (s *mockAuthServer) ServeLogin(w http.ResponseWriter, r *http.Request) {
	// Not used by any tests.
	// Leaving unimplemented until needed.
	http.Error(w, "unimplemented", http.StatusInternalServerError)
	return
}
