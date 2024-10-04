// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package safeweb

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/gorilla/csrf"
)

func TestCompleteCORSConfig(t *testing.T) {
	_, err := NewServer(Config{AccessControlAllowOrigin: []string{"https://foobar.com"}})
	if err == nil {
		t.Fatalf("expected error when AccessControlAllowOrigin is provided without AccessControlAllowMethods")
	}

	_, err = NewServer(Config{AccessControlAllowMethods: []string{"GET", "POST"}})
	if err == nil {
		t.Fatalf("expected error when AccessControlAllowMethods is provided without AccessControlAllowOrigin")
	}

	_, err = NewServer(Config{AccessControlAllowOrigin: []string{"https://foobar.com"}, AccessControlAllowMethods: []string{"GET", "POST"}})
	if err != nil {
		t.Fatalf("error creating server with complete CORS configuration: %v", err)
	}
}

func TestPostRequestContentTypeValidation(t *testing.T) {
	tests := []struct {
		name         string
		browserRoute bool
		contentType  string
		wantErr      bool
	}{
		{
			name:         "API routes should accept `application/json` content-type",
			browserRoute: false,
			contentType:  "application/json",
			wantErr:      false,
		},
		{
			name:         "API routes should reject `application/x-www-form-urlencoded` content-type",
			browserRoute: false,
			contentType:  "application/x-www-form-urlencoded",
			wantErr:      true,
		},
		{
			name:         "Browser routes should accept `application/x-www-form-urlencoded` content-type",
			browserRoute: true,
			contentType:  "application/x-www-form-urlencoded",
			wantErr:      false,
		},
		{
			name:         "non Browser routes should accept `application/json` content-type",
			browserRoute: true,
			contentType:  "application/json",
			wantErr:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := &http.ServeMux{}
			h.Handle("/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Write([]byte("ok"))
			}))
			var s *Server
			var err error
			if tt.browserRoute {
				s, err = NewServer(Config{BrowserMux: h})
			} else {
				s, err = NewServer(Config{APIMux: h})
			}
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()

			req := httptest.NewRequest("POST", "/", nil)
			req.Header.Set("Content-Type", tt.contentType)

			w := httptest.NewRecorder()
			s.h.Handler.ServeHTTP(w, req)
			resp := w.Result()
			if tt.wantErr && resp.StatusCode != http.StatusBadRequest {
				t.Fatalf("content type validation failed: got %v; want %v", resp.StatusCode, http.StatusBadRequest)
			}
		})
	}
}

func TestAPIMuxCrossOriginResourceSharingHeaders(t *testing.T) {
	tests := []struct {
		name            string
		httpMethod      string
		wantCORSHeaders bool
		corsOrigins     []string
		corsMethods     []string
	}{
		{
			name:            "do not set CORS headers for non-OPTIONS requests",
			corsOrigins:     []string{"https://foobar.com"},
			corsMethods:     []string{"GET", "POST", "HEAD"},
			httpMethod:      "GET",
			wantCORSHeaders: false,
		},
		{
			name:            "set CORS headers for non-OPTIONS requests",
			corsOrigins:     []string{"https://foobar.com"},
			corsMethods:     []string{"GET", "POST", "HEAD"},
			httpMethod:      "OPTIONS",
			wantCORSHeaders: true,
		},
		{
			name:            "do not serve CORS headers for OPTIONS requests with no configured origins",
			httpMethod:      "OPTIONS",
			wantCORSHeaders: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := &http.ServeMux{}
			h.Handle("/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Write([]byte("ok"))
			}))
			s, err := NewServer(Config{
				APIMux:                    h,
				AccessControlAllowOrigin:  tt.corsOrigins,
				AccessControlAllowMethods: tt.corsMethods,
			})
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()

			req := httptest.NewRequest(tt.httpMethod, "/", nil)
			w := httptest.NewRecorder()
			s.h.Handler.ServeHTTP(w, req)
			resp := w.Result()

			if (resp.Header.Get("Access-Control-Allow-Origin") == "") == tt.wantCORSHeaders {
				t.Fatalf("access-control-allow-origin want: %v; got: %v", tt.wantCORSHeaders, resp.Header.Get("Access-Control-Allow-Origin"))
			}
		})
	}
}

func TestCSRFProtection(t *testing.T) {
	tests := []struct {
		name          string
		apiRoute      bool
		passCSRFToken bool
		wantStatus    int
	}{
		{
			name:          "POST requests to non-API routes require CSRF token and fail if not provided",
			apiRoute:      false,
			passCSRFToken: false,
			wantStatus:    http.StatusForbidden,
		},
		{
			name:          "POST requests to non-API routes require CSRF token and pass if provided",
			apiRoute:      false,
			passCSRFToken: true,
			wantStatus:    http.StatusOK,
		},
		{
			name:          "POST requests to /api/ routes do not require CSRF token",
			apiRoute:      true,
			passCSRFToken: false,
			wantStatus:    http.StatusOK,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := &http.ServeMux{}
			h.Handle("/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Write([]byte("ok"))
			}))
			var s *Server
			var err error
			if tt.apiRoute {
				s, err = NewServer(Config{APIMux: h})
			} else {
				s, err = NewServer(Config{BrowserMux: h})
			}
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()

			// construct the test request
			req := httptest.NewRequest("POST", "/", nil)

			// send JSON for API routes, form data for browser routes
			if tt.apiRoute {
				req.Header.Set("Content-Type", "application/json")
			} else {
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			}

			// retrieve CSRF cookie & pass it in the test request
			// ref: https://github.com/gorilla/csrf/blob/main/csrf_test.go#L344-L347
			var token string
			if tt.passCSRFToken {
				h.Handle("/csrf", http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
					token = csrf.Token(r)
				}))
				get := httptest.NewRequest("GET", "/csrf", nil)
				w := httptest.NewRecorder()
				s.h.Handler.ServeHTTP(w, get)
				resp := w.Result()

				// pass the token & cookie in our subsequent test request
				req.Header.Set("X-CSRF-Token", token)
				for _, c := range resp.Cookies() {
					req.AddCookie(c)
				}
			}

			w := httptest.NewRecorder()
			s.h.Handler.ServeHTTP(w, req)
			resp := w.Result()

			if resp.StatusCode != tt.wantStatus {
				t.Fatalf("csrf protection check failed: got %v; want %v", resp.StatusCode, tt.wantStatus)
			}
		})
	}
}

func TestContentSecurityPolicyHeader(t *testing.T) {
	tests := []struct {
		name     string
		apiRoute bool
		wantCSP  bool
	}{
		{
			name:     "default routes get CSP headers",
			apiRoute: false,
			wantCSP:  true,
		},
		{
			name:     "`/api/*` routes do not get CSP headers",
			apiRoute: true,
			wantCSP:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := &http.ServeMux{}
			h.Handle("/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Write([]byte("ok"))
			}))
			var s *Server
			var err error
			if tt.apiRoute {
				s, err = NewServer(Config{APIMux: h})
			} else {
				s, err = NewServer(Config{BrowserMux: h})
			}
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()

			req := httptest.NewRequest("GET", "/", nil)
			w := httptest.NewRecorder()
			s.h.Handler.ServeHTTP(w, req)
			resp := w.Result()

			if (resp.Header.Get("Content-Security-Policy") == "") == tt.wantCSP {
				t.Fatalf("content security policy want: %v; got: %v", tt.wantCSP, resp.Header.Get("Content-Security-Policy"))
			}
		})
	}
}

func TestCSRFCookieSecureMode(t *testing.T) {
	tests := []struct {
		name       string
		secureMode bool
		wantSecure bool
	}{
		{
			name:       "CSRF cookie should be secure when server is in secure context",
			secureMode: true,
			wantSecure: true,
		},
		{
			name:       "CSRF cookie should not be secure when server is not in secure context",
			secureMode: false,
			wantSecure: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := &http.ServeMux{}
			h.Handle("/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Write([]byte("ok"))
			}))
			s, err := NewServer(Config{BrowserMux: h, SecureContext: tt.secureMode})
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()

			req := httptest.NewRequest("GET", "/", nil)
			w := httptest.NewRecorder()
			s.h.Handler.ServeHTTP(w, req)
			resp := w.Result()

			cookie := resp.Cookies()[0]
			if (cookie.Secure == tt.wantSecure) == false {
				t.Fatalf("csrf cookie secure flag want: %v; got: %v", tt.wantSecure, cookie.Secure)
			}
		})
	}
}

func TestRefererPolicy(t *testing.T) {
	tests := []struct {
		name              string
		browserRoute      bool
		wantRefererPolicy bool
	}{
		{
			name:              "BrowserMux routes get Referer-Policy headers",
			browserRoute:      true,
			wantRefererPolicy: true,
		},
		{
			name:              "APIMux routes do not get Referer-Policy headers",
			browserRoute:      false,
			wantRefererPolicy: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := &http.ServeMux{}
			h.Handle("/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Write([]byte("ok"))
			}))
			var s *Server
			var err error
			if tt.browserRoute {
				s, err = NewServer(Config{BrowserMux: h})
			} else {
				s, err = NewServer(Config{APIMux: h})
			}
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()

			req := httptest.NewRequest("GET", "/", nil)
			w := httptest.NewRecorder()
			s.h.Handler.ServeHTTP(w, req)
			resp := w.Result()

			if (resp.Header.Get("Referer-Policy") == "") == tt.wantRefererPolicy {
				t.Fatalf("referer policy want: %v; got: %v", tt.wantRefererPolicy, resp.Header.Get("Referer-Policy"))
			}
		})
	}
}

func TestCSPAllowInlineStyles(t *testing.T) {
	for _, allow := range []bool{false, true} {
		t.Run(strconv.FormatBool(allow), func(t *testing.T) {
			h := &http.ServeMux{}
			h.Handle("/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Write([]byte("ok"))
			}))
			s, err := NewServer(Config{BrowserMux: h, CSPAllowInlineStyles: allow})
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()

			req := httptest.NewRequest("GET", "/", nil)
			w := httptest.NewRecorder()
			s.h.Handler.ServeHTTP(w, req)
			resp := w.Result()

			csp := resp.Header.Get("Content-Security-Policy")
			allowsStyles := strings.Contains(csp, "style-src 'self' 'unsafe-inline'")
			if allowsStyles != allow {
				t.Fatalf("CSP inline styles want: %v; got: %v", allow, allowsStyles)
			}
		})
	}
}

func TestRouting(t *testing.T) {
	for _, tt := range []struct {
		desc            string
		browserPatterns []string
		apiPatterns     []string
		requestPath     string
		want            string
	}{
		{
			desc:            "only browser mux",
			browserPatterns: []string{"/"},
			requestPath:     "/index.html",
			want:            "browser",
		},
		{
			desc:        "only API mux",
			apiPatterns: []string{"/api/"},
			requestPath: "/api/foo",
			want:        "api",
		},
		{
			desc:            "browser mux match",
			browserPatterns: []string{"/content/"},
			apiPatterns:     []string{"/api/"},
			requestPath:     "/content/index.html",
			want:            "browser",
		},
		{
			desc:            "API mux match",
			browserPatterns: []string{"/content/"},
			apiPatterns:     []string{"/api/"},
			requestPath:     "/api/foo",
			want:            "api",
		},
		{
			desc:            "browser wildcard match",
			browserPatterns: []string{"/"},
			apiPatterns:     []string{"/api/"},
			requestPath:     "/index.html",
			want:            "browser",
		},
		{
			desc:            "API wildcard match",
			browserPatterns: []string{"/content/"},
			apiPatterns:     []string{"/"},
			requestPath:     "/api/foo",
			want:            "api",
		},
		{
			desc:            "path conflict",
			browserPatterns: []string{"/foo/"},
			apiPatterns:     []string{"/foo/bar/"},
			requestPath:     "/foo/bar/baz",
			want:            "api",
		},
		{
			desc:            "no match",
			browserPatterns: []string{"/foo/"},
			apiPatterns:     []string{"/bar/"},
			requestPath:     "/baz",
			want:            "404 page not found",
		},
	} {
		t.Run(tt.desc, func(t *testing.T) {
			bm := &http.ServeMux{}
			for _, p := range tt.browserPatterns {
				bm.HandleFunc(p, func(w http.ResponseWriter, r *http.Request) {
					w.Write([]byte("browser"))
				})
			}
			am := &http.ServeMux{}
			for _, p := range tt.apiPatterns {
				am.HandleFunc(p, func(w http.ResponseWriter, r *http.Request) {
					w.Write([]byte("api"))
				})
			}
			s, err := NewServer(Config{BrowserMux: bm, APIMux: am})
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()

			req := httptest.NewRequest("GET", tt.requestPath, nil)
			w := httptest.NewRecorder()
			s.h.Handler.ServeHTTP(w, req)
			resp, err := io.ReadAll(w.Result().Body)
			if err != nil {
				t.Fatal(err)
			}
			if got := strings.TrimSpace(string(resp)); got != tt.want {
				t.Errorf("got response %q, want %q", got, tt.want)
			}
		})
	}
}

func TestGetMoreSpecificPattern(t *testing.T) {
	for _, tt := range []struct {
		desc string
		a    string
		b    string
		want handlerType
	}{
		{
			desc: "identical",
			a:    "/foo/bar",
			b:    "/foo/bar",
			want: unknownHandler,
		},
		{
			desc: "identical prefix",
			a:    "/foo/bar/",
			b:    "/foo/bar/",
			want: unknownHandler,
		},
		{
			desc: "trailing slash",
			a:    "/foo",
			b:    "/foo/", // path.Clean will strip the trailing slash.
			want: unknownHandler,
		},
		{
			desc: "same prefix",
			a:    "/foo/bar/quux",
			b:    "/foo/bar/",
			want: apiHandler,
		},
		{
			desc: "almost same prefix, but not a path component",
			a:    "/goat/sheep/cheese",
			b:    "/goat/sheepcheese/",
			want: apiHandler,
		},
		{
			desc: "attempt to make less-specific pattern look more specific",
			a:    "/goat/cat/buddy",
			b:    "/goat/../../../../../../../cat", // path.Clean catches this foolishness
			want: apiHandler,
		},
		{
			desc: "2 names for / (1)",
			a:    "/",
			b:    "/../../../../../../",
			want: unknownHandler,
		},
		{
			desc: "2 names for / (2)",
			a:    "/",
			b:    "///////",
			want: unknownHandler,
		},
	} {
		t.Run(tt.desc, func(t *testing.T) {
			got := checkHandlerType(tt.a, tt.b)
			if got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestStrictTransportSecurityOptions(t *testing.T) {
	tests := []struct {
		name          string
		options       string
		secureContext bool
		expect        string
	}{
		{
			name: "off by default",
		},
		{
			name:          "default HSTS options in the secure context",
			secureContext: true,
			expect:        DefaultStrictTransportSecurityOptions,
		},
		{
			name:          "custom options sent in the secure context",
			options:       DefaultStrictTransportSecurityOptions + "; includeSubDomains",
			secureContext: true,
			expect:        DefaultStrictTransportSecurityOptions + "; includeSubDomains",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := &http.ServeMux{}
			h.Handle("/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Write([]byte("ok"))
			}))
			s, err := NewServer(Config{BrowserMux: h, SecureContext: tt.secureContext, StrictTransportSecurityOptions: tt.options})
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()

			req := httptest.NewRequest("GET", "/", nil)
			w := httptest.NewRecorder()
			s.h.Handler.ServeHTTP(w, req)
			resp := w.Result()

			if cmp.Diff(tt.expect, resp.Header.Get("Strict-Transport-Security")) != "" {
				t.Fatalf("HSTS want: %q; got: %q", tt.expect, resp.Header.Get("Strict-Transport-Security"))
			}
		})
	}
}

func TestOverrideHTTPServer(t *testing.T) {
	s, err := NewServer(Config{})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	if s.h.IdleTimeout != 0 {
		t.Fatalf("got %v; want 0", s.h.IdleTimeout)
	}

	c := http.Server{
		IdleTimeout: 10 * time.Second,
	}

	s, err = NewServer(Config{HTTPServer: &c})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	if s.h.IdleTimeout != c.IdleTimeout {
		t.Fatalf("got %v; want %v", s.h.IdleTimeout, c.IdleTimeout)
	}
}
