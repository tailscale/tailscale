// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package taildrop

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"tailscale.com/client/tailscale/apitype"
	"tailscale.com/ipn/ipnlocal"
	"tailscale.com/tailcfg"
	"tailscale.com/tailcfg/nodecap"
	"tailscale.com/tailcfg/peercap"
	"tailscale.com/tstest"
	"tailscale.com/tstime"
	"tailscale.com/types/logger"
	"tailscale.com/util/must"
)

// peerAPIHandler serves the PeerAPI for a source specific client.
type peerAPIHandler struct {
	remoteAddr netip.AddrPort
	isSelf     bool               // whether peerNode is owned by same user as this node
	selfNode   tailcfg.NodeView   // this node; always non-nil
	peerNode   tailcfg.NodeView   // peerNode is who's making the request
	canDebug   bool               // whether peerNode can debug this node (goroutines, metrics, magicsock internal state, etc)
	peerCaps   tailcfg.PeerCapMap // ACL capabilities peerNode has toward this node
}

func (h *peerAPIHandler) IsSelfUntagged() bool {
	return !h.selfNode.IsTagged() && !h.peerNode.IsTagged() && h.isSelf
}
func (h *peerAPIHandler) CanDebug() bool                       { return h.canDebug }
func (h *peerAPIHandler) Peer() tailcfg.NodeView               { return h.peerNode }
func (h *peerAPIHandler) Self() tailcfg.NodeView               { return h.selfNode }
func (h *peerAPIHandler) RemoteAddr() netip.AddrPort           { return h.remoteAddr }
func (h *peerAPIHandler) LocalBackend() *ipnlocal.LocalBackend { panic("unexpected") }
func (h *peerAPIHandler) Logf(format string, a ...any) {
	//h.logf(format, a...)
}

func (h *peerAPIHandler) PeerCaps() tailcfg.PeerCapMap {
	return h.peerCaps
}

type fakeExtension struct {
	logf           logger.Logf
	capFileSharing bool
	clock          tstime.Clock
	taildrop       *manager
}

func (lb *fakeExtension) manager() *manager {
	return lb.taildrop
}
func (lb *fakeExtension) Clock() tstime.Clock { return lb.clock }
func (lb *fakeExtension) hasCapFileSharing() bool {
	return lb.capFileSharing
}

type peerAPITestEnv struct {
	taildrop *manager
	ph       *peerAPIHandler
	rr       *httptest.ResponseRecorder
	logBuf   tstest.MemLogger
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

func fileHasSize(name string, size int) check {
	return func(t *testing.T, e *peerAPITestEnv) {
		fsImpl, ok := e.taildrop.opts.fileOps.(*fsFileOps)
		if !ok {
			t.Skip("fileHasSize only supported on fsFileOps backend")
			return
		}
		root := fsImpl.rootDir
		if root == "" {
			t.Errorf("no rootdir; can't check whether %q has size %v", name, size)
			return
		}
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
		fsImpl, ok := e.taildrop.opts.fileOps.(*fsFileOps)
		if !ok {
			t.Skip("fileHasContents only supported on fsFileOps backend")
			return
		}
		path := filepath.Join(fsImpl.rootDir, name)
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
	for i := range len(v) {
		fmt.Fprintf(&sb, "%%%02x", v[i])
	}
	return sb.String()
}

func TestHandlePeerAPI(t *testing.T) {
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
			// Another user's node may send, but only with consent, so a PUT
			// carrying no token is refused for that reason rather than for
			// being unauthorized outright.
			name:       "reject_non_owner_put",
			isSelf:     false,
			capSharing: true,
			reqs:       []*http.Request{httptest.NewRequest("PUT", "/v0/put/foo", nil)},
			checks: checks(
				httpStatus(http.StatusForbidden),
				bodyContains("has not enabled Taildrop"),
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
				bodyContains("Taildrop disabled"),
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
					got, err := env.taildrop.WaitingFiles()
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
					got, err := env.taildrop.WaitingFiles()
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
					got, err := env.taildrop.WaitingFiles()
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
				selfNode.CapMap = tailcfg.NodeCapMap{nodecap.Debug: nil}
			}
			var rootDir string
			var fo FileOps
			if !tt.omitRoot {
				var err error
				if fo, err = newFileOps(t.TempDir()); err != nil {
					t.Fatalf("newFileOps: %v", err)
				}
			}

			var e peerAPITestEnv
			e.taildrop = managerOptions{
				Logf:    e.logBuf.Logf,
				fileOps: fo,
			}.New()

			ext := &fakeExtension{
				logf:           e.logBuf.Logf,
				capFileSharing: tt.capSharing,
				clock:          &tstest.Clock{},
				taildrop:       e.taildrop,
			}
			e.ph = &peerAPIHandler{
				isSelf:   tt.isSelf,
				selfNode: selfNode.View(),
				peerNode: (&tailcfg.Node{ComputedName: "some-peer-name"}).View(),
			}
			for _, req := range tt.reqs {
				e.rr = httptest.NewRecorder()
				if req.Host == "example.com" {
					req.Host = "100.100.100.101:12345"
				}
				handlePeerPutWithBackend(e.ph, ext, e.rr, req)
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
	taildropMgr := managerOptions{
		Logf:    t.Logf,
		fileOps: must.Get(newFileOps(dir)),
	}.New()

	ph := &peerAPIHandler{
		isSelf: true,
		peerNode: (&tailcfg.Node{
			ComputedName: "some-peer-name",
		}).View(),
		selfNode: (&tailcfg.Node{
			Addresses: []netip.Prefix{netip.MustParsePrefix("100.100.100.101/32")},
		}).View(),
	}
	fakeLB := &fakeExtension{
		logf:           t.Logf,
		capFileSharing: true,
		clock:          &tstest.Clock{},
		taildrop:       taildropMgr,
	}
	buf := make([]byte, 2<<20)
	for range 30 {
		rr := httptest.NewRecorder()
		handlePeerPutWithBackend(ph, fakeLB, rr, httptest.NewRequest("PUT", "http://100.100.100.101:123/v0/put/foo.txt", bytes.NewReader(buf[:rand.Intn(len(buf))])))
		if res := rr.Result(); res.StatusCode != 200 {
			t.Fatal(res.Status)
		}
		wfs, err := taildropMgr.WaitingFiles()
		if err != nil {
			t.Fatal(err)
		}
		if len(wfs) != 1 {
			t.Fatalf("waiting files = %d; want 1", len(wfs))
		}

		if err := taildropMgr.DeleteFile("foo.txt"); err != nil {
			t.Fatal(err)
		}
		wfs, err = taildropMgr.WaitingFiles()
		if err != nil {
			t.Fatal(err)
		}
		if len(wfs) != 0 {
			t.Fatalf("waiting files = %d; want 0", len(wfs))
		}
	}
}

// consentPeerAPIEnv returns a PeerAPI handler and extension wired to a manager
// with consent enabled.
func consentPeerAPIEnv(t *testing.T) (*peerAPIHandler, *fakeExtension, *manager) {
	t.Helper()
	fo, err := newFileOps(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	consent := true
	mgr := managerOptions{
		Logf:                  t.Logf,
		fileOps:               fo,
		AllowExternalTaildrop: func() bool { return true },
		ConsentForOwnDevices:  func() bool { return consent },
	}.New()
	t.Cleanup(mgr.Shutdown)

	ext := &fakeExtension{
		logf:           t.Logf,
		capFileSharing: true,
		clock:          &tstest.Clock{},
		taildrop:       mgr,
	}
	ph := &peerAPIHandler{
		isSelf:   false,
		selfNode: (&tailcfg.Node{Addresses: []netip.Prefix{netip.MustParsePrefix("100.100.100.101/32")}}).View(),
		peerNode: (&tailcfg.Node{StableID: "nPEERCNTRL", ComputedName: "some-peer-name"}).View(),
	}
	return ph, ext, mgr
}

func putRequest(t *testing.T, ph *peerAPIHandler, ext *fakeExtension, name string, size int64) *httptest.ResponseRecorder {
	t.Helper()
	body := must.Get(json.Marshal(testConsentMetadata(name, size)))
	req := httptest.NewRequest("POST", "/v0/put-request/"+name, bytes.NewReader(body))
	rr := httptest.NewRecorder()
	handlePeerPutRequestWithBackend(ph, ext, rr, req)
	return rr
}

// TestHandlePeerPutRequestConsentDisabled verifies that same-user transfers
// bypass consent with either preference setting unless the development override
// is enabled.
func TestHandlePeerPutRequestConsentDisabled(t *testing.T) {
	tests := []struct {
		name    string
		enabled bool
	}{
		{name: "opted_out"},
		{name: "opted_in", enabled: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fo, err := newFileOps(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			mgr := managerOptions{Logf: t.Logf, fileOps: fo, AllowExternalTaildrop: func() bool { return tt.enabled }}.New()
			t.Cleanup(mgr.Shutdown)
			ext := &fakeExtension{logf: t.Logf, capFileSharing: true, clock: &tstest.Clock{}, taildrop: mgr}
			ph := &peerAPIHandler{
				isSelf:   true,
				selfNode: (&tailcfg.Node{}).View(),
				peerNode: (&tailcfg.Node{StableID: "nPEERCNTRL"}).View(),
			}

			// 204 tells a consent-aware sender to go straight to a plain PUT.
			if got := putRequest(t, ph, ext, "foo.txt", 10).Code; got != http.StatusNoContent {
				t.Errorf("status = %d; want %d", got, http.StatusNoContent)
			}

			// And a plain PUT still works, so enabling the protocol costs nothing
			// regardless of the preference.
			rr := httptest.NewRecorder()
			handlePeerPutWithBackend(ph, ext, rr, httptest.NewRequest("PUT", "/v0/put/foo.txt", strings.NewReader("hello")))
			if rr.Code != http.StatusOK {
				t.Errorf("bare PUT status = %d; want 200 (body %q)", rr.Code, rr.Body)
			}

		})
	}
}

// TestHandlePeerPutRequestUnauthorized verifies that unsigned peers cannot
// request approval or generate a recipient prompt, even when their user matches
// the receiver’s.
func TestHandlePeerPutRequestUnauthorized(t *testing.T) {
	tests := []struct {
		name string
		own  bool
	}{
		{name: "other_user"},
		{name: "same_user", own: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// An unsigned peer has no verified identity to show the owner, so it is
			// refused outright rather than being allowed to ask. Consent doesn't
			// change that; it's the one case consent can't rescue.
			//
			// A peer belonging to another user is a different matter, and is covered
			// by TestHandlePeerPutCrossUser.
			ph, ext, mgr := consentPeerAPIEnv(t)
			ph.isSelf = tt.own
			ph.peerNode = (&tailcfg.Node{StableID: "nUNSIGNEDCNTRL", UnsignedPeerAPIOnly: true}).View()

			if got := putRequest(t, ph, ext, "foo.txt", 10).Code; got != http.StatusForbidden {
				t.Errorf("status = %d; want %d", got, http.StatusForbidden)
			}
			// Above all, it must not be able to make the device owner's phone buzz.
			if got := mgr.pendingConsentRequests(); len(got) != 0 {
				t.Errorf("pending requests = %d; want 0", len(got))
			}

		})
	}
}

// TestHandlePeerPutConsentFlow verifies that the peer API requires approval
// before delivery and rejects replay of the resulting token, including for
// empty files and direct-file mode.
func TestHandlePeerPutConsentFlow(t *testing.T) {
	tests := []struct {
		name     string
		contents string
		own      bool
		direct   bool
	}{
		{name: "same_user_forced", contents: "hello", own: true},
		{name: "same_user_forced_apple_direct", contents: "hello", own: true, direct: true},
		{name: "empty"},
		{name: "small_file", contents: "hello"},
		{name: "larger_file", contents: "hello world"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ph, ext, mgr := consentPeerAPIEnv(t)
			contents := tt.contents
			ph.isSelf = tt.own
			mgr.opts.DirectFileMode = tt.direct

			// A bare PUT is refused while consent is required.
			rr := httptest.NewRecorder()
			handlePeerPutWithBackend(ph, ext, rr, httptest.NewRequest("PUT", "/v0/put/foo.txt", strings.NewReader(contents)))
			if rr.Code != http.StatusForbidden {
				t.Fatalf("bare PUT status = %d; want %d", rr.Code, http.StatusForbidden)
			}
			if !strings.Contains(rr.Body.String(), "consent required") {
				t.Errorf("bare PUT body = %q; want it to mention consent", rr.Body)
			}

			// Phase 1: request consent. Pending, with a retry hint.
			rr = putRequest(t, ph, ext, "foo.txt", int64(len(contents)))
			if rr.Code != http.StatusAccepted {
				t.Fatalf("put-request status = %d; want %d", rr.Code, http.StatusAccepted)
			}
			if got := rr.Result().Header.Get("Retry-After"); got == "" {
				t.Error("pending put-request has no Retry-After hint")
			}

			// Phase 2: the owner approves.
			pending := mgr.pendingConsentRequests()
			if len(pending) != 1 {
				t.Fatalf("pending = %d; want 1", len(pending))
			}
			if got := pending[0].PeerName; got != "some-peer-name" {
				t.Errorf("PeerName = %q; want %q", got, "some-peer-name")
			}
			if err := mgr.resolveConsent(pending[0].RequestID, true); err != nil {
				t.Fatal(err)
			}

			rr = putRequest(t, ph, ext, "foo.txt", int64(len(contents)))
			if rr.Code != http.StatusOK {
				t.Fatalf("approved put-request status = %d; want 200 (body %q)", rr.Code, rr.Body)
			}
			var tok ConsentToken
			if err := json.Unmarshal(rr.Body.Bytes(), &tok); err != nil {
				t.Fatalf("decoding token: %v", err)
			}

			// Phase 3: the authorized PUT.
			req := httptest.NewRequest("PUT", "/v0/put/foo.txt", strings.NewReader(contents))
			for k, v := range consentHeaders(&tok) {
				req.Header[k] = v
			}
			rr = httptest.NewRecorder()
			handlePeerPutWithBackend(ph, ext, rr, req)
			if rr.Code != http.StatusOK {
				t.Fatalf("consented PUT status = %d; want 200 (body %q)", rr.Code, rr.Body)
			}

			// Replaying the same token delivers nothing further.
			req = httptest.NewRequest("PUT", "/v0/put/foo.txt", strings.NewReader(contents))
			for k, v := range consentHeaders(&tok) {
				req.Header[k] = v
			}
			rr = httptest.NewRecorder()
			handlePeerPutWithBackend(ph, ext, rr, req)
			if rr.Code != http.StatusConflict {
				t.Errorf("replayed PUT status = %d; want %d", rr.Code, http.StatusConflict)
			}

		})
	}
}

// TestHandlePeerPutRequestDenied verifies that a recipient’s denial is returned
// to the sender as an explicit decline.
func TestHandlePeerPutRequestDenied(t *testing.T) {
	tests := []struct {
		name string
		size int64
	}{
		{name: "empty_file"},
		{name: "nonempty_file", size: 5},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ph, ext, mgr := consentPeerAPIEnv(t)

			if got := putRequest(t, ph, ext, "foo.txt", tt.size).Code; got != http.StatusAccepted {
				t.Fatalf("status = %d; want %d", got, http.StatusAccepted)
			}
			pending := mgr.pendingConsentRequests()
			if len(pending) != 1 {
				t.Fatalf("pending = %d; want 1", len(pending))
			}
			if err := mgr.resolveConsent(pending[0].RequestID, false); err != nil {
				t.Fatal(err)
			}

			rr := putRequest(t, ph, ext, "foo.txt", tt.size)
			if rr.Code != http.StatusForbidden {
				t.Errorf("denied status = %d; want %d", rr.Code, http.StatusForbidden)
			}
			if !strings.Contains(rr.Body.String(), "declined") {
				t.Errorf("denied body = %q; want it to say the peer declined", rr.Body)
			}

		})
	}
}

// TestHandlePeerPutRequestBadInput verifies that malformed consent requests
// fail before creating a prompt; each case isolates the invalid method,
// metadata, or filename it is intended to reject.
func TestHandlePeerPutRequestBadInput(t *testing.T) {
	metadataBody := func(size int64) io.Reader {
		return bytes.NewReader(must.Get(json.Marshal(testConsentMetadata("input", size))))
	}
	tests := []struct {
		name string
		req  *http.Request
		want int
	}{
		{
			"wrong_method",
			httptest.NewRequest("GET", "/v0/put-request/foo.txt", nil),
			http.StatusMethodNotAllowed,
		},
		{
			"bad_json",
			httptest.NewRequest("POST", "/v0/put-request/foo.txt", strings.NewReader("{")),
			http.StatusBadRequest,
		},
		{
			"negative_size",
			httptest.NewRequest("POST", "/v0/put-request/foo.txt", metadataBody(-1)),
			http.StatusBadRequest,
		},
		{
			"partial_suffix_filename",
			httptest.NewRequest("POST", "/v0/put-request/foo.txt.partial", metadataBody(1)),
			http.StatusBadRequest,
		},
		{
			"traversal_filename",
			httptest.NewRequest("POST", "/v0/put-request/"+hexAll("../foo"), metadataBody(1)),
			http.StatusBadRequest,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ph, ext, mgr := consentPeerAPIEnv(t)
			rr := httptest.NewRecorder()
			handlePeerPutRequestWithBackend(ph, ext, rr, tt.req)
			if rr.Code != tt.want {
				t.Errorf("status = %d; want %d (body %q)", rr.Code, tt.want, rr.Body)
			}
			if pending := mgr.pendingConsentRequests(); len(pending) != 0 {
				t.Errorf("invalid request created prompts: %v", pending)
			}
		})
	}
}

// TestHandlePeerPutConsentMultiFile verifies that multiple files receive
// separate prompts and independently usable approvals.
func TestHandlePeerPutConsentMultiFile(t *testing.T) {
	tests := []struct {
		name  string
		files []string
	}{
		{name: "one_file", files: []string{"a.txt"}},
		{name: "multiple_files", files: []string{"a.txt", "b.txt", "c.txt"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ph, ext, mgr := consentPeerAPIEnv(t)
			names := tt.files

			for _, n := range names {
				if got := putRequest(t, ph, ext, n, 4).Code; got != http.StatusAccepted {
					t.Fatalf("%s status = %d; want %d", n, got, http.StatusAccepted)
				}
			}

			// Each file has its own prompt and approval.
			pending := mgr.pendingConsentRequests()
			if len(pending) != len(names) {
				t.Fatalf("pending prompts = %d; want %d", len(pending), len(names))
			}
			for _, p := range pending {
				if len(p.Files) != 1 {
					t.Fatalf("files in prompt = %d; want 1", len(p.Files))
				}
				if err := mgr.resolveConsent(p.RequestID, true); err != nil {
					t.Fatal(err)
				}
			}

			for _, n := range names {
				rr := putRequest(t, ph, ext, n, 4)
				if rr.Code != http.StatusOK {
					t.Fatalf("%s approved status = %d; want 200", n, rr.Code)
				}
				var tok ConsentToken
				if err := json.Unmarshal(rr.Body.Bytes(), &tok); err != nil {
					t.Fatal(err)
				}
				req := httptest.NewRequest("PUT", "/v0/put/"+n, strings.NewReader("abcd"))
				for k, v := range consentHeaders(&tok) {
					req.Header[k] = v
				}
				put := httptest.NewRecorder()
				handlePeerPutWithBackend(ph, ext, put, req)
				if put.Code != http.StatusOK {
					t.Fatalf("%s PUT status = %d; want 200 (body %q)", n, put.Code, put.Body)
				}
			}

		})
	}
}

// TestHandlePeerPutConsentErrorHeader verifies that only consent failures carry
// the protocol’s consent error header, so senders can distinguish them from
// ordinary authorization failures.
func TestHandlePeerPutConsentErrorHeader(t *testing.T) {
	tests := []struct {
		name               string
		approved, unsigned bool
		wantStatus         int
		wantConsentError   bool
	}{
		{name: "consent_required", wantStatus: http.StatusForbidden, wantConsentError: true},
		{name: "approved", approved: true, wantStatus: http.StatusOK},
		{name: "unauthorized", approved: true, unsigned: true, wantStatus: http.StatusForbidden},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ph, ext, _ := consentPeerAPIEnv(t)
			req := httptest.NewRequest("PUT", "/v0/put/ok.txt", strings.NewReader("hi"))
			if tt.approved {
				tok := approveMetadata(t, ph, ext, "ok.txt", testConsentMetadata("ok.txt", 2))
				req.Header = consentHeaders(&tok)
			}
			if tt.unsigned {
				ph.peerNode = (&tailcfg.Node{StableID: "nUNSIGNEDCNTRL", UnsignedPeerAPIOnly: true}).View()
			}
			rr := httptest.NewRecorder()
			handlePeerPutWithBackend(ph, ext, rr, req)
			if rr.Code != tt.wantStatus {
				t.Fatalf("PUT status = %d; want %d: %s", rr.Code, tt.wantStatus, rr.Body)
			}
			if got := rr.Header().Get(hdrConsentError) != ""; got != tt.wantConsentError {
				t.Errorf("consent error header present = %v; want %v", got, tt.wantConsentError)
			}
		})
	}
}

// TestHandlePeerPutCrossUser verifies that cross-user peers can request consent
// without an ACL capability, but only approval authorizes delivery, regardless
// of the same-user testing override.
func TestHandlePeerPutCrossUser(t *testing.T) {
	tests := []struct {
		name              string
		override, approve bool
		wantPutStatus     int
	}{
		{name: "pending", wantPutStatus: http.StatusForbidden},
		{name: "pending_with_override", override: true, wantPutStatus: http.StatusForbidden},
		{name: "approved", approve: true, wantPutStatus: http.StatusOK},
		{name: "approved_with_override", override: true, approve: true, wantPutStatus: http.StatusOK},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// The peer has no ACL capability granting file sharing.
			ph, ext, mgr := consentPeerAPIEnv(t)
			mgr.opts.ConsentForOwnDevices = func() bool { return tt.override }
			rr := putRequest(t, ph, ext, "foo.txt", 5)
			if rr.Code != http.StatusAccepted {
				t.Fatalf("request status = %d; want 202", rr.Code)
			}
			if got := len(mgr.pendingConsentRequests()); got != 1 {
				t.Fatalf("pending = %d; want 1", got)
			}
			req := httptest.NewRequest("PUT", "/v0/put/foo.txt", strings.NewReader("hello"))
			if tt.approve {
				tok := approveMetadata(t, ph, ext, "foo.txt", testConsentMetadata("foo.txt", 5))
				req.Header = consentHeaders(&tok)
			}
			rr = httptest.NewRecorder()
			handlePeerPutWithBackend(ph, ext, rr, req)
			if rr.Code != tt.wantPutStatus {
				t.Fatalf("PUT status = %d; want %d: %s", rr.Code, tt.wantPutStatus, rr.Body)
			}
		})
	}
}

// TestPutAuthMatrix documents, for every shape of peer, whether it may send us
// a file and whether the device owner is asked first.
//
// The intended design is that consent depends only on who the peer is, not on
// an ACL capability. Same-user untagged transfers only prompt under the
// explicit testing override; everything else always does.
func TestPutAuthMatrix(t *testing.T) {
	handler := func(isSelf, selfTagged, peerTagged, unsigned, sendCap bool) *peerAPIHandler {
		self := &tailcfg.Node{}
		if selfTagged {
			self.Tags = []string{"tag:self"}
		}
		peer := &tailcfg.Node{StableID: "nPEERCNTRL", UnsignedPeerAPIOnly: unsigned}
		if peerTagged {
			peer.Tags = []string{"tag:peer"}
		}
		h := &peerAPIHandler{isSelf: isSelf, selfNode: self.View(), peerNode: peer.View()}
		if sendCap {
			h.peerCaps = tailcfg.PeerCapMap{peercap.FileSharingSend: nil}
		}
		return h
	}

	// What the design calls for, independent of any preference.
	const (
		wantAllowedNoPrompt = "allowed, no prompt"
		wantPrompt          = "prompt"
		wantDenied          = "denied"
	)

	tests := []struct {
		name string
		ph   *peerAPIHandler
		want string
	}{
		{"same_user_untagged", handler(true, false, false, false, false), wantAllowedNoPrompt},
		{"same_user_peer_tagged", handler(true, false, true, false, false), wantPrompt},
		{"same_user_self_tagged", handler(true, true, false, false, false), wantPrompt},
		{"other_user", handler(false, false, false, false, false), wantPrompt},
		{"other_user_tagged", handler(false, false, true, false, false), wantPrompt},
		{"unsigned", handler(true, false, false, true, false), wantDenied},
		{"unsigned_other_user", handler(false, false, false, true, false), wantDenied},

		// An ACL capability is the admin saying this peer may send. The
		// question is whether that also waives the owner's say.
		{"other_user_with_send_cap", handler(false, false, false, false, true), wantPrompt},
		{"same_user_tagged_with_send_cap", handler(true, false, true, false, true), wantPrompt},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			describe := func(consentForOwnDevices bool) string {
				switch putAuthFor(tt.ph, consentForOwnDevices) {
				case putDenied:
					return wantDenied
				case putNeedsConsent:
					return wantPrompt
				default:
					return wantAllowedNoPrompt
				}
			}
			if got := describe(false); got != tt.want {
				t.Errorf("got %q; want %q", got, tt.want)
			}
			// The testing override must prompt even for same-user transfers.
			wantOverride := tt.want
			if wantOverride == wantAllowedNoPrompt {
				wantOverride = wantPrompt
			}
			if got := describe(true); got != wantOverride {
				t.Errorf("override authorization: %q; want %q", got, wantOverride)
			}
			if !canPutFile(tt.ph, false) != (tt.want == wantDenied) {
				t.Errorf("canPutFile disagrees with %q", tt.want)
			}
		})
	}
}
