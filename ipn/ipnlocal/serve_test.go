// Copyright (c) 2022 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ipnlocal

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"

	"tailscale.com/ipn"
)

func TestExpandProxyArg(t *testing.T) {
	type res struct {
		target   string
		insecure bool
	}
	tests := []struct {
		in   string
		want res
	}{
		{"", res{}},
		{"3030", res{"http://127.0.0.1:3030", false}},
		{"localhost:3030", res{"http://localhost:3030", false}},
		{"10.2.3.5:3030", res{"http://10.2.3.5:3030", false}},
		{"http://foo.com", res{"http://foo.com", false}},
		{"https://foo.com", res{"https://foo.com", false}},
		{"https+insecure://10.2.3.4", res{"https://10.2.3.4", true}},
	}
	for _, tt := range tests {
		target, insecure := expandProxyArg(tt.in)
		got := res{target, insecure}
		if got != tt.want {
			t.Errorf("expandProxyArg(%q) = %v, want %v", tt.in, got, tt.want)
		}
	}
}

func TestGetServeHandler(t *testing.T) {
	const serverName = "example.ts.net"
	conf1 := &ipn.ServeConfig{
		Web: map[ipn.HostPort]*ipn.WebServerConfig{
			serverName + ":443": {
				Handlers: map[string]*ipn.HTTPHandler{
					"/":         {},
					"/bar":      {},
					"/foo/":     {},
					"/foo/bar":  {},
					"/foo/bar/": {},
				},
			},
		},
	}

	tests := []struct {
		name string
		port uint16 // or 443 is zero
		path string // http.Request.URL.Path
		conf *ipn.ServeConfig
		want string // mountPoint
	}{
		{
			name: "nothing",
			path: "/",
			conf: nil,
			want: "",
		},
		{
			name: "root",
			conf: conf1,
			path: "/",
			want: "/",
		},
		{
			name: "root-other",
			conf: conf1,
			path: "/other",
			want: "/",
		},
		{
			name: "bar",
			conf: conf1,
			path: "/bar",
			want: "/bar",
		},
		{
			name: "foo-bar",
			conf: conf1,
			path: "/foo/bar",
			want: "/foo/bar",
		},
		{
			name: "foo-bar-slash",
			conf: conf1,
			path: "/foo/bar/",
			want: "/foo/bar/",
		},
		{
			name: "foo-bar-other",
			conf: conf1,
			path: "/foo/bar/other",
			want: "/foo/bar/",
		},
		{
			name: "foo-other",
			conf: conf1,
			path: "/foo/other",
			want: "/foo/",
		},
		{
			name: "foo-no-trailing-slash",
			conf: conf1,
			path: "/foo",
			want: "/foo/",
		},
		{
			name: "dot-dots",
			conf: conf1,
			path: "/foo/../../../../../../../../etc/passwd",
			want: "/",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := &LocalBackend{
				serveConfig: tt.conf.View(),
				logf:        t.Logf,
			}
			req := &http.Request{
				URL: &url.URL{
					Path: tt.path,
				},
				TLS: &tls.ConnectionState{ServerName: serverName},
			}
			port := tt.port
			if port == 0 {
				port = 443
			}
			req = req.WithContext(context.WithValue(req.Context(), serveHTTPContextKey{}, &serveHTTPContext{
				DestPort: port,
			}))

			h, got, ok := b.getServeHandler(req)
			if (got != "") != ok {
				t.Fatalf("got ok=%v, but got mountPoint=%q", ok, got)
			}
			if h.Valid() != ok {
				t.Fatalf("got ok=%v, but valid=%v", ok, h.Valid())
			}
			if got != tt.want {
				t.Errorf("got handler at mount %q, want %q", got, tt.want)
			}
		})
	}
}

func TestServeFileOrDirectory(t *testing.T) {
	td := t.TempDir()
	writeFile := func(suffix, contents string) {
		if err := os.WriteFile(filepath.Join(td, suffix), []byte(contents), 0600); err != nil {
			t.Fatal(err)
		}
	}
	writeFile("foo", "this is foo")
	writeFile("bar", "this is bar")
	os.MkdirAll(filepath.Join(td, "subdir"), 0700)
	writeFile("subdir/file-a", "this is A")
	writeFile("subdir/file-b", "this is B")
	writeFile("subdir/file-c", "this is C")

	contains := func(subs ...string) func([]byte, *http.Response) error {
		return func(resBody []byte, res *http.Response) error {
			for _, sub := range subs {
				if !bytes.Contains(resBody, []byte(sub)) {
					return fmt.Errorf("response body does not contain %q: %s", sub, resBody)
				}
			}
			return nil
		}
	}
	isStatus := func(wantCode int) func([]byte, *http.Response) error {
		return func(resBody []byte, res *http.Response) error {
			if res.StatusCode != wantCode {
				return fmt.Errorf("response status = %d; want %d", res.StatusCode, wantCode)
			}
			return nil
		}
	}
	isRedirect := func(wantLocation string) func([]byte, *http.Response) error {
		return func(resBody []byte, res *http.Response) error {
			switch res.StatusCode {
			case 301, 302, 303, 307, 308:
				if got := res.Header.Get("Location"); got != wantLocation {
					return fmt.Errorf("got Location = %q; want %q", got, wantLocation)
				}
			default:
				return fmt.Errorf("response status = %d; want redirect. body: %s", res.StatusCode, resBody)
			}
			return nil
		}
	}

	b := &LocalBackend{}

	tests := []struct {
		req   string
		mount string
		want  func(resBody []byte, res *http.Response) error
	}{
		// Mounted at /

		{"/", "/", contains("foo", "bar", "subdir")},
		{"/../../.../../../../../../../etc/passwd", "/", isStatus(404)},
		{"/foo", "/", contains("this is foo")},
		{"/bar", "/", contains("this is bar")},
		{"/bar/inside-file", "/", isStatus(404)},
		{"/subdir", "/", isRedirect("/subdir/")},
		{"/subdir/", "/", contains("file-a", "file-b", "file-c")},
		{"/subdir/file-a", "/", contains("this is A")},
		{"/subdir/file-z", "/", isStatus(404)},

		{"/doc", "/doc/", isRedirect("/doc/")},
		{"/doc/", "/doc/", contains("foo", "bar", "subdir")},
		{"/doc/../../.../../../../../../../etc/passwd", "/doc/", isStatus(404)},
		{"/doc/foo", "/doc/", contains("this is foo")},
		{"/doc/bar", "/doc/", contains("this is bar")},
		{"/doc/bar/inside-file", "/doc/", isStatus(404)},
		{"/doc/subdir", "/doc/", isRedirect("/doc/subdir/")},
		{"/doc/subdir/", "/doc/", contains("file-a", "file-b", "file-c")},
		{"/doc/subdir/file-a", "/doc/", contains("this is A")},
		{"/doc/subdir/file-z", "/doc/", isStatus(404)},
	}
	for _, tt := range tests {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest("GET", tt.req, nil)
		b.serveFileOrDirectory(rec, req, td, tt.mount)
		if tt.want == nil {
			t.Errorf("no want for path %q", tt.req)
			return
		}
		if err := tt.want(rec.Body.Bytes(), rec.Result()); err != nil {
			t.Errorf("error for req %q (mount %v): %v", tt.req, tt.mount, err)
		}
	}
}
