// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package taildrop

import (
	"bytes"
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
	"tailscale.com/tstest"
	"tailscale.com/tstime"
	"tailscale.com/types/logger"
	"tailscale.com/util/must"
)

// peerAPIHandler serves the PeerAPI for a source specific client.
type peerAPIHandler struct {
	remoteAddr netip.AddrPort
	isSelf     bool             // whether peerNode is owned by same user as this node
	selfNode   tailcfg.NodeView // this node; always non-nil
	peerNode   tailcfg.NodeView // peerNode is who's making the request
	canDebug   bool             // whether peerNode can debug this node (goroutines, metrics, magicsock internal state, etc)
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
	return nil
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
				selfNode.CapMap = tailcfg.NodeCapMap{tailcfg.CapabilityDebug: nil}
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
