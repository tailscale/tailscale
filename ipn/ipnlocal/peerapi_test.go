// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package ipnlocal

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"io/fs"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"go4.org/netipx"
	"golang.org/x/net/dns/dnsmessage"
	"tailscale.com/appc"
	"tailscale.com/client/tailscale/apitype"
	"tailscale.com/ipn"
	"tailscale.com/ipn/store/mem"
	"tailscale.com/tailcfg"
	"tailscale.com/taildrop"
	"tailscale.com/tstest"
	"tailscale.com/types/logger"
	"tailscale.com/types/netmap"
	"tailscale.com/util/must"
	"tailscale.com/wgengine"
	"tailscale.com/wgengine/filter"
)

type peerAPITestEnv struct {
	ph     *peerAPIHandler
	rr     *httptest.ResponseRecorder
	logBuf tstest.MemLogger
}

type check func(*testing.T, *peerAPITestEnv)

func checks(vv ...check) []check { return vv }

func httpStatus(wantStatus int) check {
	return func(t *testing.T, e *peerAPITestEnv) {
		if res := e.rr.Result(); res.StatusCode != wantStatus {
			t.Errorf("HTTP response code = %v; want %v", res.Status, wantStatus)
		}
	}
}

func bodyContains(sub string) check {
	return func(t *testing.T, e *peerAPITestEnv) {
		if body := e.rr.Body.String(); !strings.Contains(body, sub) {
			t.Errorf("HTTP response body does not contain %q; got: %s", sub, body)
		}
	}
}

func bodyNotContains(sub string) check {
	return func(t *testing.T, e *peerAPITestEnv) {
		if body := e.rr.Body.String(); strings.Contains(body, sub) {
			t.Errorf("HTTP response body unexpectedly contains %q; got: %s", sub, body)
		}
	}
}

func fileHasSize(name string, size int) check {
	return func(t *testing.T, e *peerAPITestEnv) {
		root := e.ph.ps.taildrop.Dir()
		if root == "" {
			t.Errorf("no rootdir; can't check whether %q has size %v", name, size)
			return
		}
		path := filepath.Join(root, name)
		if fi, err := os.Stat(path); err != nil {
			t.Errorf("fileHasSize(%q, %v): %v", name, size, err)
		} else if fi.Size() != int64(size) {
			t.Errorf("file %q has size %v; want %v", name, fi.Size(), size)
		}
	}
}

func fileHasContents(name string, want string) check {
	return func(t *testing.T, e *peerAPITestEnv) {
		root := e.ph.ps.taildrop.Dir()
		if root == "" {
			t.Errorf("no rootdir; can't check contents of %q", name)
			return
		}
		path := filepath.Join(root, name)
		got, err := os.ReadFile(path)
		if err != nil {
			t.Errorf("fileHasContents: %v", err)
			return
		}
		if string(got) != want {
			t.Errorf("file contents = %q; want %q", got, want)
		}
	}
}

func hexAll(v string) string {
	var sb strings.Builder
	for i := 0; i < len(v); i++ {
		fmt.Fprintf(&sb, "%%%02x", v[i])
	}
	return sb.String()
}

func TestHandlePeerAPI(t *testing.T) {
	const nodeFQDN = "self-node.tail-scale.ts.net."
	tests := []struct {
		name       string
		isSelf     bool // the peer sending the request is owned by us
		capSharing bool // self node has file sharing capability
		debugCap   bool // self node has debug capability
		omitRoot   bool // don't configure
		reqs       []*http.Request
		checks     []check
	}{
		{
			name:       "not_peer_api",
			isSelf:     true,
			capSharing: true,
			reqs:       []*http.Request{httptest.NewRequest("GET", "/", nil)},
			checks: checks(
				httpStatus(200),
				bodyContains("This is my Tailscale device."),
				bodyContains("You are the owner of this node."),
			),
		},
		{
			name:       "not_peer_api_not_owner",
			isSelf:     false,
			capSharing: true,
			reqs:       []*http.Request{httptest.NewRequest("GET", "/", nil)},
			checks: checks(
				httpStatus(200),
				bodyContains("This is my Tailscale device."),
				bodyNotContains("You are the owner of this node."),
			),
		},
		{
			name:     "goroutines/deny-self-no-cap",
			isSelf:   true,
			debugCap: false,
			reqs:     []*http.Request{httptest.NewRequest("GET", "/v0/goroutines", nil)},
			checks:   checks(httpStatus(403)),
		},
		{
			name:     "goroutines/deny-nonself",
			isSelf:   false,
			debugCap: true,
			reqs:     []*http.Request{httptest.NewRequest("GET", "/v0/goroutines", nil)},
			checks:   checks(httpStatus(403)),
		},
		{
			name:     "goroutines/accept-self",
			isSelf:   true,
			debugCap: true,
			reqs:     []*http.Request{httptest.NewRequest("GET", "/v0/goroutines", nil)},
			checks: checks(
				httpStatus(200),
				bodyContains("ServeHTTP"),
			),
		},
		{
			name:       "reject_non_owner_put",
			isSelf:     false,
			capSharing: true,
			reqs:       []*http.Request{httptest.NewRequest("PUT", "/v0/put/foo", nil)},
			checks: checks(
				httpStatus(http.StatusForbidden),
				bodyContains("Taildrop disabled"),
			),
		},
		{
			name:       "owner_without_cap",
			isSelf:     true,
			capSharing: false,
			reqs:       []*http.Request{httptest.NewRequest("PUT", "/v0/put/foo", nil)},
			checks: checks(
				httpStatus(http.StatusForbidden),
				bodyContains("Taildrop disabled"),
			),
		},
		{
			name:       "owner_with_cap_no_rootdir",
			omitRoot:   true,
			isSelf:     true,
			capSharing: true,
			reqs:       []*http.Request{httptest.NewRequest("PUT", "/v0/put/foo", nil)},
			checks: checks(
				httpStatus(http.StatusForbidden),
				bodyContains("Taildrop disabled; no storage directory"),
			),
		},
		{
			name:       "bad_method",
			isSelf:     true,
			capSharing: true,
			reqs:       []*http.Request{httptest.NewRequest("POST", "/v0/put/foo", nil)},
			checks: checks(
				httpStatus(405),
				bodyContains("expected method GET or PUT"),
			),
		},
		{
			name:       "put_zero_length",
			isSelf:     true,
			capSharing: true,
			reqs:       []*http.Request{httptest.NewRequest("PUT", "/v0/put/foo", nil)},
			checks: checks(
				httpStatus(200),
				bodyContains("{}"),
				fileHasSize("foo", 0),
				fileHasContents("foo", ""),
			),
		},
		{
			name:       "put_non_zero_length_content_length",
			isSelf:     true,
			capSharing: true,
			reqs:       []*http.Request{httptest.NewRequest("PUT", "/v0/put/foo", strings.NewReader("contents"))},
			checks: checks(
				httpStatus(200),
				bodyContains("{}"),
				fileHasSize("foo", len("contents")),
				fileHasContents("foo", "contents"),
			),
		},
		{
			name:       "put_non_zero_length_chunked",
			isSelf:     true,
			capSharing: true,
			reqs:       []*http.Request{httptest.NewRequest("PUT", "/v0/put/foo", struct{ io.Reader }{strings.NewReader("contents")})},
			checks: checks(
				httpStatus(200),
				bodyContains("{}"),
				fileHasSize("foo", len("contents")),
				fileHasContents("foo", "contents"),
			),
		},
		{
			name:       "bad_filename_partial",
			isSelf:     true,
			capSharing: true,
			reqs:       []*http.Request{httptest.NewRequest("PUT", "/v0/put/foo.partial", nil)},
			checks: checks(
				httpStatus(400),
				bodyContains("invalid filename"),
			),
		},
		{
			name:       "bad_filename_deleted",
			isSelf:     true,
			capSharing: true,
			reqs:       []*http.Request{httptest.NewRequest("PUT", "/v0/put/foo.deleted", nil)},
			checks: checks(
				httpStatus(400),
				bodyContains("invalid filename"),
			),
		},
		{
			name:       "bad_filename_dot",
			isSelf:     true,
			capSharing: true,
			reqs:       []*http.Request{httptest.NewRequest("PUT", "/v0/put/.", nil)},
			checks: checks(
				httpStatus(400),
				bodyContains("invalid filename"),
			),
		},
		{
			name:       "bad_filename_empty",
			isSelf:     true,
			capSharing: true,
			reqs:       []*http.Request{httptest.NewRequest("PUT", "/v0/put/", nil)},
			checks: checks(
				httpStatus(400),
				bodyContains("invalid filename"),
			),
		},
		{
			name:       "bad_filename_slash",
			isSelf:     true,
			capSharing: true,
			reqs:       []*http.Request{httptest.NewRequest("PUT", "/v0/put/foo/bar", nil)},
			checks: checks(
				httpStatus(400),
				bodyContains("invalid filename"),
			),
		},
		{
			name:       "bad_filename_encoded_dot",
			isSelf:     true,
			capSharing: true,
			reqs:       []*http.Request{httptest.NewRequest("PUT", "/v0/put/"+hexAll("."), nil)},
			checks: checks(
				httpStatus(400),
				bodyContains("invalid filename"),
			),
		},
		{
			name:       "bad_filename_encoded_slash",
			isSelf:     true,
			capSharing: true,
			reqs:       []*http.Request{httptest.NewRequest("PUT", "/v0/put/"+hexAll("/"), nil)},
			checks: checks(
				httpStatus(400),
				bodyContains("invalid filename"),
			),
		},
		{
			name:       "bad_filename_encoded_backslash",
			isSelf:     true,
			capSharing: true,
			reqs:       []*http.Request{httptest.NewRequest("PUT", "/v0/put/"+hexAll("\\"), nil)},
			checks: checks(
				httpStatus(400),
				bodyContains("invalid filename"),
			),
		},
		{
			name:       "bad_filename_encoded_dotdot",
			isSelf:     true,
			capSharing: true,
			reqs:       []*http.Request{httptest.NewRequest("PUT", "/v0/put/"+hexAll(".."), nil)},
			checks: checks(
				httpStatus(400),
				bodyContains("invalid filename"),
			),
		},
		{
			name:       "bad_filename_encoded_dotdot_out",
			isSelf:     true,
			capSharing: true,
			reqs:       []*http.Request{httptest.NewRequest("PUT", "/v0/put/"+hexAll("foo/../../../../../etc/passwd"), nil)},
			checks: checks(
				httpStatus(400),
				bodyContains("invalid filename"),
			),
		},
		{
			name:       "put_spaces_and_caps",
			isSelf:     true,
			capSharing: true,
			reqs:       []*http.Request{httptest.NewRequest("PUT", "/v0/put/"+hexAll("Foo Bar.dat"), strings.NewReader("baz"))},
			checks: checks(
				httpStatus(200),
				bodyContains("{}"),
				fileHasContents("Foo Bar.dat", "baz"),
			),
		},
		{
			name:       "put_unicode",
			isSelf:     true,
			capSharing: true,
			reqs:       []*http.Request{httptest.NewRequest("PUT", "/v0/put/"+hexAll("Томас и его друзья.mp3"), strings.NewReader("главный озорник"))},
			checks: checks(
				httpStatus(200),
				bodyContains("{}"),
				fileHasContents("Томас и его друзья.mp3", "главный озорник"),
			),
		},
		{
			name:       "put_invalid_utf8",
			isSelf:     true,
			capSharing: true,
			reqs:       []*http.Request{httptest.NewRequest("PUT", "/v0/put/"+(hexAll("😜")[:3]), nil)},
			checks: checks(
				httpStatus(400),
				bodyContains("invalid filename"),
			),
		},
		{
			name:       "put_invalid_null",
			isSelf:     true,
			capSharing: true,
			reqs:       []*http.Request{httptest.NewRequest("PUT", "/v0/put/%00", nil)},
			checks: checks(
				httpStatus(400),
				bodyContains("invalid filename"),
			),
		},
		{
			name:       "put_invalid_non_printable",
			isSelf:     true,
			capSharing: true,
			reqs:       []*http.Request{httptest.NewRequest("PUT", "/v0/put/%01", nil)},
			checks: checks(
				httpStatus(400),
				bodyContains("invalid filename"),
			),
		},
		{
			name:       "put_invalid_colon",
			isSelf:     true,
			capSharing: true,
			reqs:       []*http.Request{httptest.NewRequest("PUT", "/v0/put/"+hexAll("nul:"), nil)},
			checks: checks(
				httpStatus(400),
				bodyContains("invalid filename"),
			),
		},
		{
			name:       "put_invalid_surrounding_whitespace",
			isSelf:     true,
			capSharing: true,
			reqs:       []*http.Request{httptest.NewRequest("PUT", "/v0/put/"+hexAll(" foo "), nil)},
			checks: checks(
				httpStatus(400),
				bodyContains("invalid filename"),
			),
		},
		{
			name:     "host-val/bad-ip",
			isSelf:   true,
			debugCap: true,
			reqs:     []*http.Request{httptest.NewRequest("GET", "http://12.23.45.66:1234/v0/env", nil)},
			checks: checks(
				httpStatus(403),
			),
		},
		{
			name:     "host-val/no-port",
			isSelf:   true,
			debugCap: true,
			reqs:     []*http.Request{httptest.NewRequest("GET", "http://100.100.100.101/v0/env", nil)},
			checks: checks(
				httpStatus(403),
			),
		},
		{
			name:     "host-val/peer",
			isSelf:   true,
			debugCap: true,
			reqs:     []*http.Request{httptest.NewRequest("GET", "http://peer/v0/env", nil)},
			checks: checks(
				httpStatus(200),
			),
		},
		{
			name:       "duplicate_zero_length",
			isSelf:     true,
			capSharing: true,
			reqs: []*http.Request{
				httptest.NewRequest("PUT", "/v0/put/foo", nil),
				httptest.NewRequest("PUT", "/v0/put/foo", nil),
			},
			checks: checks(
				httpStatus(200),
				func(t *testing.T, env *peerAPITestEnv) {
					got, err := env.ph.ps.taildrop.WaitingFiles()
					if err != nil {
						t.Fatalf("WaitingFiles error: %v", err)
					}
					want := []apitype.WaitingFile{{Name: "foo", Size: 0}}
					if diff := cmp.Diff(got, want); diff != "" {
						t.Fatalf("WaitingFile mismatch (-got +want):\n%s", diff)
					}
				},
			),
		},
		{
			name:       "duplicate_non_zero_length_content_length",
			isSelf:     true,
			capSharing: true,
			reqs: []*http.Request{
				httptest.NewRequest("PUT", "/v0/put/foo", strings.NewReader("contents")),
				httptest.NewRequest("PUT", "/v0/put/foo", strings.NewReader("contents")),
			},
			checks: checks(
				httpStatus(200),
				func(t *testing.T, env *peerAPITestEnv) {
					got, err := env.ph.ps.taildrop.WaitingFiles()
					if err != nil {
						t.Fatalf("WaitingFiles error: %v", err)
					}
					want := []apitype.WaitingFile{{Name: "foo", Size: 8}}
					if diff := cmp.Diff(got, want); diff != "" {
						t.Fatalf("WaitingFile mismatch (-got +want):\n%s", diff)
					}
				},
			),
		},
		{
			name:       "duplicate_different_files",
			isSelf:     true,
			capSharing: true,
			reqs: []*http.Request{
				httptest.NewRequest("PUT", "/v0/put/foo", strings.NewReader("fizz")),
				httptest.NewRequest("PUT", "/v0/put/foo", strings.NewReader("buzz")),
			},
			checks: checks(
				httpStatus(200),
				func(t *testing.T, env *peerAPITestEnv) {
					got, err := env.ph.ps.taildrop.WaitingFiles()
					if err != nil {
						t.Fatalf("WaitingFiles error: %v", err)
					}
					want := []apitype.WaitingFile{{Name: "foo", Size: 4}, {Name: "foo (1)", Size: 4}}
					if diff := cmp.Diff(got, want); diff != "" {
						t.Fatalf("WaitingFile mismatch (-got +want):\n%s", diff)
					}
				},
			),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			selfNode := &tailcfg.Node{
				Addresses: []netip.Prefix{
					netip.MustParsePrefix("100.100.100.101/32"),
				},
			}
			if tt.debugCap {
				selfNode.Capabilities = append(selfNode.Capabilities, tailcfg.CapabilityDebug)
			}
			var e peerAPITestEnv
			lb := &LocalBackend{
				logf:           e.logBuf.Logf,
				capFileSharing: tt.capSharing,
				netMap:         &netmap.NetworkMap{SelfNode: selfNode.View()},
				clock:          &tstest.Clock{},
			}
			e.ph = &peerAPIHandler{
				isSelf:   tt.isSelf,
				selfNode: selfNode.View(),
				peerNode: (&tailcfg.Node{
					ComputedName: "some-peer-name",
				}).View(),
				ps: &peerAPIServer{
					b: lb,
				},
			}
			var rootDir string
			if !tt.omitRoot {
				rootDir = t.TempDir()
				if e.ph.ps.taildrop == nil {
					e.ph.ps.taildrop = taildrop.ManagerOptions{
						Logf: e.logBuf.Logf,
						Dir:  rootDir,
					}.New()
				}
			}
			for _, req := range tt.reqs {
				e.rr = httptest.NewRecorder()
				if req.Host == "example.com" {
					req.Host = "100.100.100.101:12345"
				}
				e.ph.ServeHTTP(e.rr, req)
			}
			for _, f := range tt.checks {
				f(t, &e)
			}
			if t.Failed() && rootDir != "" {
				t.Logf("Contents of %s:", rootDir)
				des, _ := fs.ReadDir(os.DirFS(rootDir), ".")
				for _, de := range des {
					fi, err := de.Info()
					if err != nil {
						t.Log(err)
					} else {
						t.Logf("  %v %5d %s", fi.Mode(), fi.Size(), de.Name())
					}
				}
			}
		})
	}
}

// Windows likes to hold on to file descriptors for some indeterminate
// amount of time after you close them and not let you delete them for
// a bit. So test that we work around that sufficiently.
func TestFileDeleteRace(t *testing.T) {
	dir := t.TempDir()
	ps := &peerAPIServer{
		b: &LocalBackend{
			logf:           t.Logf,
			capFileSharing: true,
			clock:          &tstest.Clock{},
		},
		taildrop: taildrop.ManagerOptions{
			Logf: t.Logf,
			Dir:  dir,
		}.New(),
	}
	ph := &peerAPIHandler{
		isSelf: true,
		peerNode: (&tailcfg.Node{
			ComputedName: "some-peer-name",
		}).View(),
		selfNode: (&tailcfg.Node{
			Addresses: []netip.Prefix{netip.MustParsePrefix("100.100.100.101/32")},
		}).View(),
		ps: ps,
	}
	buf := make([]byte, 2<<20)
	for i := 0; i < 30; i++ {
		rr := httptest.NewRecorder()
		ph.ServeHTTP(rr, httptest.NewRequest("PUT", "http://100.100.100.101:123/v0/put/foo.txt", bytes.NewReader(buf[:rand.Intn(len(buf))])))
		if res := rr.Result(); res.StatusCode != 200 {
			t.Fatal(res.Status)
		}
		wfs, err := ps.taildrop.WaitingFiles()
		if err != nil {
			t.Fatal(err)
		}
		if len(wfs) != 1 {
			t.Fatalf("waiting files = %d; want 1", len(wfs))
		}

		if err := ps.taildrop.DeleteFile("foo.txt"); err != nil {
			t.Fatal(err)
		}
		wfs, err = ps.taildrop.WaitingFiles()
		if err != nil {
			t.Fatal(err)
		}
		if len(wfs) != 0 {
			t.Fatalf("waiting files = %d; want 0", len(wfs))
		}
	}
}

func TestPeerAPIReplyToDNSQueries(t *testing.T) {
	var h peerAPIHandler

	h.isSelf = true
	if !h.replyToDNSQueries() {
		t.Errorf("for isSelf = false; want true")
	}
	h.isSelf = false
	h.remoteAddr = netip.MustParseAddrPort("100.150.151.152:12345")

	eng, _ := wgengine.NewFakeUserspaceEngine(logger.Discard, 0)
	pm := must.Get(newProfileManager(new(mem.Store), t.Logf))
	h.ps = &peerAPIServer{
		b: &LocalBackend{
			e:     eng,
			pm:    pm,
			store: pm.Store(),
		},
	}
	if h.ps.b.OfferingExitNode() {
		t.Fatal("unexpectedly offering exit node")
	}
	h.ps.b.pm.SetPrefs((&ipn.Prefs{
		AdvertiseRoutes: []netip.Prefix{
			netip.MustParsePrefix("0.0.0.0/0"),
			netip.MustParsePrefix("::/0"),
		},
	}).View(), ipn.NetworkProfile{})
	if !h.ps.b.OfferingExitNode() {
		t.Fatal("unexpectedly not offering exit node")
	}

	if h.replyToDNSQueries() {
		t.Errorf("unexpectedly doing DNS without filter")
	}

	h.ps.b.setFilter(filter.NewAllowNone(logger.Discard, new(netipx.IPSet)))
	if h.replyToDNSQueries() {
		t.Errorf("unexpectedly doing DNS without filter")
	}

	f := filter.NewAllowAllForTest(logger.Discard)

	h.ps.b.setFilter(f)
	if !h.replyToDNSQueries() {
		t.Errorf("unexpectedly deny; wanted to be a DNS server")
	}

	// Also test IPv6.
	h.remoteAddr = netip.MustParseAddrPort("[fe70::1]:12345")
	if !h.replyToDNSQueries() {
		t.Errorf("unexpectedly IPv6 deny; wanted to be a DNS server")
	}
}

func TestPeerAPIReplyToDNSQueriesAreObserved(t *testing.T) {
	var h peerAPIHandler
	h.remoteAddr = netip.MustParseAddrPort("100.150.151.152:12345")

	rc := &routeCollector{}
	eng, _ := wgengine.NewFakeUserspaceEngine(logger.Discard, 0)
	pm := must.Get(newProfileManager(new(mem.Store), t.Logf))
	h.ps = &peerAPIServer{
		b: &LocalBackend{
			e:            eng,
			pm:           pm,
			store:        pm.Store(),
			appConnector: appc.NewAppConnector(t.Logf, rc),
		},
	}
	h.ps.b.appConnector.UpdateDomains([]string{"example.com"})

	h.ps.resolver = &fakeResolver{}
	f := filter.NewAllowAllForTest(logger.Discard)
	h.ps.b.setFilter(f)

	if !h.ps.b.OfferingAppConnector() {
		t.Fatal("expecting to be offering app connector")
	}
	if !h.replyToDNSQueries() {
		t.Errorf("unexpectedly deny; wanted to be a DNS server")
	}

	w := httptest.NewRecorder()
	h.handleDNSQuery(w, httptest.NewRequest("GET", "/dns-query?q=true&t=example.com.", nil))
	if w.Code != http.StatusOK {
		t.Errorf("unexpected status code: %v", w.Code)
	}

	wantRoutes := []netip.Prefix{netip.MustParsePrefix("192.0.0.8/32")}
	if !slices.Equal(rc.routes, wantRoutes) {
		t.Errorf("got %v; want %v", rc.routes, wantRoutes)
	}
}

type fakeResolver struct{}

func (f *fakeResolver) HandlePeerDNSQuery(ctx context.Context, q []byte, from netip.AddrPort, allowName func(name string) bool) (res []byte, err error) {
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{})
	b.EnableCompression()
	b.StartAnswers()
	b.AResource(
		dnsmessage.ResourceHeader{
			Name:  dnsmessage.MustNewName("example.com."),
			Type:  dnsmessage.TypeA,
			Class: dnsmessage.ClassINET,
			TTL:   0,
		},
		dnsmessage.AResource{
			A: [4]byte{192, 0, 0, 8},
		},
	)
	return b.Finish()
}
