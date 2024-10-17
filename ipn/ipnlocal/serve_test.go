// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package ipnlocal

import (
	"bytes"
	"cmp"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"tailscale.com/health"
	"tailscale.com/ipn"
	"tailscale.com/ipn/store/mem"
	"tailscale.com/tailcfg"
	"tailscale.com/tsd"
	"tailscale.com/tstest"
	"tailscale.com/types/logger"
	"tailscale.com/types/logid"
	"tailscale.com/types/netmap"
	"tailscale.com/util/mak"
	"tailscale.com/util/must"
	"tailscale.com/wgengine"
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
			port := cmp.Or(tt.port, 443)
			req = req.WithContext(serveHTTPContextKey.WithValue(req.Context(), &serveHTTPContext{
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

func getEtag(t *testing.T, b any) string {
	t.Helper()
	bts, err := json.Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(bts)
	return hex.EncodeToString(sum[:])
}

// TestServeConfigForeground tests the inter-dependency
// between a ServeConfig and a WatchIPNBus:
// 1. Creating a WatchIPNBus returns a sessionID, that
// 2. ServeConfig sets it as the key of the Foreground field.
// 3. ServeConfig expects the WatchIPNBus to clean up the Foreground
// config when the session is done.
// 4. WatchIPNBus expects the ServeConfig to send a signal (close the channel)
// if an incoming SetServeConfig removes previous foregrounds.
func TestServeConfigForeground(t *testing.T) {
	b := newTestBackend(t)

	ch1 := make(chan string, 1)
	go func() {
		defer close(ch1)
		b.WatchNotifications(context.Background(), ipn.NotifyInitialState, nil, func(roNotify *ipn.Notify) (keepGoing bool) {
			if roNotify.SessionID != "" {
				ch1 <- roNotify.SessionID
			}
			return true
		})
	}()

	ch2 := make(chan string, 1)
	go func() {
		b.WatchNotifications(context.Background(), ipn.NotifyInitialState, nil, func(roNotify *ipn.Notify) (keepGoing bool) {
			if roNotify.SessionID != "" {
				ch2 <- roNotify.SessionID
				return true
			}
			ch2 <- "again" // let channel know fn was called again
			return true
		})
	}()

	var session1 string
	select {
	case session1 = <-ch1:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting on watch notifications session id")
	}

	var session2 string
	select {
	case session2 = <-ch2:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting on watch notifications session id")
	}

	err := b.SetServeConfig(&ipn.ServeConfig{
		Foreground: map[string]*ipn.ServeConfig{
			session1: {TCP: map[uint16]*ipn.TCPPortHandler{
				443: {TCPForward: "http://localhost:3000"}},
			},
			session2: {TCP: map[uint16]*ipn.TCPPortHandler{
				999: {TCPForward: "http://localhost:4000"}},
			},
		},
	}, "")
	if err != nil {
		t.Fatal(err)
	}

	// Introduce a race between [LocalBackend] sending notifications
	// and [LocalBackend.WatchNotifications] shutting down due to
	// setting the serve config below.
	const N = 1000
	for range N {
		go b.send(ipn.Notify{})
	}

	// Setting a new serve config should shut down WatchNotifications
	// whose session IDs are no longer found: session1 goes, session2 stays.
	err = b.SetServeConfig(&ipn.ServeConfig{
		TCP: map[uint16]*ipn.TCPPortHandler{
			5000: {TCPForward: "http://localhost:5000"},
		},
		Foreground: map[string]*ipn.ServeConfig{
			session2: {TCP: map[uint16]*ipn.TCPPortHandler{
				999: {TCPForward: "http://localhost:4000"}},
			},
		},
	}, "")
	if err != nil {
		t.Fatal(err)
	}

	select {
	case _, ok := <-ch1:
		if ok {
			t.Fatal("expected channel to be closed")
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting on watch notifications closing")
	}

	// check that the second session is still running
	b.send(ipn.Notify{})
	select {
	case _, ok := <-ch2:
		if !ok {
			t.Fatal("expected second session to remain open")
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting on second session")
	}
}

func TestServeConfigETag(t *testing.T) {
	b := newTestBackend(t)

	// a nil config with initial etag should succeed
	err := b.SetServeConfig(nil, getEtag(t, nil))
	if err != nil {
		t.Fatal(err)
	}

	// a nil config with an invalid etag should fail
	err = b.SetServeConfig(nil, "abc")
	if !errors.Is(err, ErrETagMismatch) {
		t.Fatal("expected an error but got nil")
	}

	// a new config with no etag should succeed
	conf := &ipn.ServeConfig{
		Web: map[ipn.HostPort]*ipn.WebServerConfig{
			"example.ts.net:443": {Handlers: map[string]*ipn.HTTPHandler{
				"/": {Proxy: "http://127.0.0.1:3000"},
			}},
		},
	}
	err = b.SetServeConfig(conf, getEtag(t, nil))
	if err != nil {
		t.Fatal(err)
	}

	confView := b.ServeConfig()
	etag := getEtag(t, confView)
	if etag == "" {
		t.Fatal("expected to get an etag but got an empty string")
	}
	conf = confView.AsStruct()
	mak.Set(&conf.AllowFunnel, "example.ts.net:443", true)

	// replacing an existing config with an invalid etag should fail
	err = b.SetServeConfig(conf, "invalid etag")
	if !errors.Is(err, ErrETagMismatch) {
		t.Fatalf("expected an etag mismatch error but got %v", err)
	}

	// replacing an existing config with a valid etag should succeed
	err = b.SetServeConfig(conf, etag)
	if err != nil {
		t.Fatal(err)
	}

	// replacing an existing config with a previous etag should fail
	err = b.SetServeConfig(nil, etag)
	if !errors.Is(err, ErrETagMismatch) {
		t.Fatalf("expected an etag mismatch error but got %v", err)
	}

	// replacing an existing config with the new etag should succeed
	newCfg := b.ServeConfig()
	etag = getEtag(t, newCfg)
	err = b.SetServeConfig(nil, etag)
	if err != nil {
		t.Fatal(err)
	}
}

func TestServeHTTPProxyPath(t *testing.T) {
	b := newTestBackend(t)
	// Start test serve endpoint.
	testServ := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			// Set the request URL path to a response header, so the
			// requested URL path can be checked in tests.
			t.Logf("adding path %s", r.URL.Path)
			w.Header().Add("Path", r.URL.Path)
		},
	))
	defer testServ.Close()
	tests := []struct {
		name            string
		mountPoint      string
		proxyPath       string
		requestPath     string
		wantRequestPath string
	}{
		{
			name:            "/foo -> /foo, with mount point and path /foo",
			mountPoint:      "/foo",
			proxyPath:       "/foo",
			requestPath:     "/foo",
			wantRequestPath: "/foo",
		},
		{
			name:            "/foo/ -> /foo/, with mount point and path /foo",
			mountPoint:      "/foo",
			proxyPath:       "/foo",
			requestPath:     "/foo/",
			wantRequestPath: "/foo/",
		},
		{
			name:            "/foo -> /foo/, with mount point and path /foo/",
			mountPoint:      "/foo/",
			proxyPath:       "/foo/",
			requestPath:     "/foo",
			wantRequestPath: "/foo/",
		},
		{
			name:            "/-> /, with mount point and path /",
			mountPoint:      "/",
			proxyPath:       "/",
			requestPath:     "/",
			wantRequestPath: "/",
		},
		{
			name:            "/foo -> /foo, with mount point and path /",
			mountPoint:      "/",
			proxyPath:       "/",
			requestPath:     "/foo",
			wantRequestPath: "/foo",
		},
		{
			name:            "/foo/bar -> /foo/bar, with mount point and path /foo",
			mountPoint:      "/foo",
			proxyPath:       "/foo",
			requestPath:     "/foo/bar",
			wantRequestPath: "/foo/bar",
		},
		{
			name:            "/foo/bar/baz -> /foo/bar/baz, with mount point and path /foo",
			mountPoint:      "/foo",
			proxyPath:       "/foo",
			requestPath:     "/foo/bar/baz",
			wantRequestPath: "/foo/bar/baz",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conf := &ipn.ServeConfig{
				Web: map[ipn.HostPort]*ipn.WebServerConfig{
					"example.ts.net:443": {Handlers: map[string]*ipn.HTTPHandler{
						tt.mountPoint: {Proxy: testServ.URL + tt.proxyPath},
					}},
				},
			}
			if err := b.SetServeConfig(conf, ""); err != nil {
				t.Fatal(err)
			}
			req := &http.Request{
				URL: &url.URL{Path: tt.requestPath},
				TLS: &tls.ConnectionState{ServerName: "example.ts.net"},
			}
			req = req.WithContext(serveHTTPContextKey.WithValue(req.Context(),
				&serveHTTPContext{
					DestPort: 443,
					SrcAddr:  netip.MustParseAddrPort("1.2.3.4:1234"), // random src
				}))

			w := httptest.NewRecorder()
			b.serveWebHandler(w, req)

			// Verify what path was requested
			p := w.Result().Header.Get("Path")
			if p != tt.wantRequestPath {
				t.Errorf("wanted request path %s got %s", tt.wantRequestPath, p)
			}
		})
	}
}
func TestServeHTTPProxyHeaders(t *testing.T) {
	b := newTestBackend(t)

	// Start test serve endpoint.
	testServ := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			// Piping all the headers through the response writer
			// so we can check their values in tests below.
			for key, val := range r.Header {
				w.Header().Add(key, strings.Join(val, ","))
			}
		},
	))
	defer testServ.Close()

	conf := &ipn.ServeConfig{
		Web: map[ipn.HostPort]*ipn.WebServerConfig{
			"example.ts.net:443": {Handlers: map[string]*ipn.HTTPHandler{
				"/": {Proxy: testServ.URL},
			}},
		},
	}
	if err := b.SetServeConfig(conf, ""); err != nil {
		t.Fatal(err)
	}

	type headerCheck struct {
		header string
		want   string
	}

	tests := []struct {
		name        string
		srcIP       string
		wantHeaders []headerCheck
	}{
		{
			name:  "request-from-user-within-tailnet",
			srcIP: "100.150.151.152",
			wantHeaders: []headerCheck{
				{"X-Forwarded-Proto", "https"},
				{"X-Forwarded-For", "100.150.151.152"},
				{"Tailscale-User-Login", "someone@example.com"},
				{"Tailscale-User-Name", "Some One"},
				{"Tailscale-User-Profile-Pic", "https://example.com/photo.jpg"},
				{"Tailscale-Headers-Info", "https://tailscale.com/s/serve-headers"},
			},
		},
		{
			name:  "request-from-tagged-node-within-tailnet",
			srcIP: "100.150.151.153",
			wantHeaders: []headerCheck{
				{"X-Forwarded-Proto", "https"},
				{"X-Forwarded-For", "100.150.151.153"},
				{"Tailscale-User-Login", ""},
				{"Tailscale-User-Name", ""},
				{"Tailscale-User-Profile-Pic", ""},
				{"Tailscale-Headers-Info", ""},
			},
		},
		{
			name:  "request-from-outside-tailnet",
			srcIP: "100.160.161.162",
			wantHeaders: []headerCheck{
				{"X-Forwarded-Proto", "https"},
				{"X-Forwarded-For", "100.160.161.162"},
				{"Tailscale-User-Login", ""},
				{"Tailscale-User-Name", ""},
				{"Tailscale-User-Profile-Pic", ""},
				{"Tailscale-Headers-Info", ""},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := &http.Request{
				URL: &url.URL{Path: "/"},
				TLS: &tls.ConnectionState{ServerName: "example.ts.net"},
			}
			req = req.WithContext(serveHTTPContextKey.WithValue(req.Context(), &serveHTTPContext{
				DestPort: 443,
				SrcAddr:  netip.MustParseAddrPort(tt.srcIP + ":1234"), // random src port for tests
			}))

			w := httptest.NewRecorder()
			b.serveWebHandler(w, req)

			// Verify the headers.
			h := w.Result().Header
			for _, c := range tt.wantHeaders {
				if got := h.Get(c.header); got != c.want {
					t.Errorf("invalid %q header; want=%q, got=%q", c.header, c.want, got)
				}
			}
		})
	}
}

func Test_reverseProxyConfiguration(t *testing.T) {
	b := newTestBackend(t)
	type test struct {
		backend string
		path    string
		// set to false to test that a proxy has been removed
		shouldExist   bool
		wantsInsecure bool
		wantsURL      url.URL
	}
	runner := func(name string, tests []test) {
		t.Logf("running tests for %s", name)
		host := ipn.HostPort("http://example.ts.net:80")
		conf := &ipn.ServeConfig{
			Web: map[ipn.HostPort]*ipn.WebServerConfig{
				host: {Handlers: map[string]*ipn.HTTPHandler{}},
			},
		}
		for _, tt := range tests {
			if tt.shouldExist {
				conf.Web[host].Handlers[tt.path] = &ipn.HTTPHandler{Proxy: tt.backend}
			}
		}
		if err := b.setServeConfigLocked(conf, ""); err != nil {
			t.Fatal(err)
		}
		// test that reverseproxies have been set up as expected
		for _, tt := range tests {
			rp, ok := b.serveProxyHandlers.Load(tt.backend)
			if !tt.shouldExist && ok {
				t.Errorf("proxy for backend %s should not exist, but it does", tt.backend)
			}
			if !tt.shouldExist {
				continue
			}
			parsedRp, ok := rp.(*reverseProxy)
			if !ok {
				t.Errorf("proxy for backend %q is not a reverseproxy", tt.backend)
			}
			if parsedRp.insecure != tt.wantsInsecure {
				t.Errorf("proxy for backend %q should be insecure: %v got insecure: %v", tt.backend, tt.wantsInsecure, parsedRp.insecure)
			}
			if !reflect.DeepEqual(*parsedRp.url, tt.wantsURL) {
				t.Errorf("proxy for backend %q should have URL %#+v, got URL %+#v", tt.backend, &tt.wantsURL, parsedRp.url)
			}
			if tt.backend != parsedRp.backend {
				t.Errorf("proxy for backend %q should have backend %q got %q", tt.backend, tt.backend, parsedRp.backend)
			}
		}
	}

	// configure local backend with some proxy backends
	runner("initial proxy configs", []test{
		{
			backend:       "http://example.com/docs",
			path:          "/example",
			shouldExist:   true,
			wantsInsecure: false,
			wantsURL:      mustCreateURL(t, "http://example.com/docs"),
		},
		{
			backend:       "https://example1.com",
			path:          "/example1",
			shouldExist:   true,
			wantsInsecure: false,
			wantsURL:      mustCreateURL(t, "https://example1.com"),
		},
		{
			backend:       "https+insecure://example2.com",
			path:          "/example2",
			shouldExist:   true,
			wantsInsecure: true,
			wantsURL:      mustCreateURL(t, "https://example2.com"),
		},
	})

	// reconfigure the local backend with different proxies
	runner("reloaded proxy configs", []test{
		{
			backend:       "http://example.com/docs",
			path:          "/example",
			shouldExist:   true,
			wantsInsecure: false,
			wantsURL:      mustCreateURL(t, "http://example.com/docs"),
		},
		{
			backend:     "https://example1.com",
			shouldExist: false,
		},
		{
			backend:     "https+insecure://example2.com",
			shouldExist: false,
		},
		{
			backend:       "https+insecure://example3.com",
			path:          "/example3",
			shouldExist:   true,
			wantsInsecure: true,
			wantsURL:      mustCreateURL(t, "https://example3.com"),
		},
	})

}

func mustCreateURL(t *testing.T, u string) url.URL {
	t.Helper()
	uParsed, err := url.Parse(u)
	if err != nil {
		t.Fatalf("failed parsing url: %v", err)
	}
	return *uParsed
}

func newTestBackend(t *testing.T) *LocalBackend {
	var logf logger.Logf = logger.Discard
	const debug = true
	if debug {
		logf = logger.WithPrefix(tstest.WhileTestRunningLogger(t), "... ")
	}

	sys := &tsd.System{}
	e, err := wgengine.NewUserspaceEngine(logf, wgengine.Config{
		SetSubsystem:  sys.Set,
		HealthTracker: sys.HealthTracker(),
		Metrics:       sys.UserMetricsRegistry(),
	})
	if err != nil {
		t.Fatal(err)
	}
	sys.Set(e)
	sys.Set(new(mem.Store))

	b, err := NewLocalBackend(logf, logid.PublicID{}, sys, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(b.Shutdown)
	dir := t.TempDir()
	b.SetVarRoot(dir)

	pm := must.Get(newProfileManager(new(mem.Store), logf, new(health.Tracker)))
	pm.currentProfile = &ipn.LoginProfile{ID: "id0"}
	b.pm = pm

	b.netMap = &netmap.NetworkMap{
		SelfNode: (&tailcfg.Node{
			Name: "example.ts.net",
		}).View(),
		UserProfiles: map[tailcfg.UserID]tailcfg.UserProfile{
			tailcfg.UserID(1): {
				LoginName:     "someone@example.com",
				DisplayName:   "Some One",
				ProfilePicURL: "https://example.com/photo.jpg",
			},
		},
	}
	b.peers = map[tailcfg.NodeID]tailcfg.NodeView{
		152: (&tailcfg.Node{
			ID:           152,
			ComputedName: "some-peer",
			User:         tailcfg.UserID(1),
		}).View(),
		153: (&tailcfg.Node{
			ID:           153,
			ComputedName: "some-tagged-peer",
			Tags:         []string{"tag:server", "tag:test"},
			User:         tailcfg.UserID(1),
		}).View(),
	}
	b.nodeByAddr = map[netip.Addr]tailcfg.NodeID{
		netip.MustParseAddr("100.150.151.152"): 152,
		netip.MustParseAddr("100.150.151.153"): 153,
	}
	return b
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

func Test_isGRPCContentType(t *testing.T) {
	tests := []struct {
		contentType string
		want        bool
	}{
		{contentType: "application/grpc", want: true},
		{contentType: "application/grpc;", want: true},
		{contentType: "application/grpc+", want: true},
		{contentType: "application/grpcfoobar"},
		{contentType: "application/text"},
		{contentType: "foobar"},
		{contentType: ""},
	}
	for _, tt := range tests {
		if got := isGRPCContentType(tt.contentType); got != tt.want {
			t.Errorf("isGRPCContentType(%q) = %v, want %v", tt.contentType, got, tt.want)
		}
	}
}

func TestEncTailscaleHeaderValue(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"", ""},
		{"Alice Smith", "Alice Smith"},
		{"Bad\xffUTF-8", ""},
		{"Krūmiņa", "=?utf-8?q?Kr=C5=ABmi=C5=86a?="},
	}
	for _, tt := range tests {
		got := encTailscaleHeaderValue(tt.in)
		if got != tt.want {
			t.Errorf("encTailscaleHeaderValue(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}
