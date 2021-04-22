// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ipnlocal

import (
	"bytes"
	"fmt"
	"io"
	"io/fs"
	"io/ioutil"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"tailscale.com/tailcfg"
	"tailscale.com/types/netmap"
)

type peerAPITestEnv struct {
	ph     *peerAPIHandler
	rr     *httptest.ResponseRecorder
	logBuf bytes.Buffer
}

func (e *peerAPITestEnv) logf(format string, a ...interface{}) {
	fmt.Fprintf(&e.logBuf, format, a...)
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
		root := e.ph.ps.rootDir
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
		root := e.ph.ps.rootDir
		if root == "" {
			t.Errorf("no rootdir; can't check contents of %q", name)
			return
		}
		path := filepath.Join(root, name)
		got, err := ioutil.ReadFile(path)
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

func TestHandlePeerPut(t *testing.T) {
	tests := []struct {
		name       string
		isSelf     bool // the peer sending the request is owned by us
		capSharing bool // self node has file sharing capabilty
		omitRoot   bool // don't configure
		req        *http.Request
		checks     []check
	}{
		{
			name:       "not_peer_api",
			isSelf:     true,
			capSharing: true,
			req:        httptest.NewRequest("GET", "/", nil),
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
			req:        httptest.NewRequest("GET", "/", nil),
			checks: checks(
				httpStatus(200),
				bodyContains("This is my Tailscale device."),
				bodyNotContains("You are the owner of this node."),
			),
		},
		{
			name:       "reject_non_owner_put",
			isSelf:     false,
			capSharing: true,
			req:        httptest.NewRequest("PUT", "/v0/put/foo", nil),
			checks: checks(
				httpStatus(http.StatusForbidden),
				bodyContains("not owner"),
			),
		},
		{
			name:       "owner_without_cap",
			isSelf:     true,
			capSharing: false,
			req:        httptest.NewRequest("PUT", "/v0/put/foo", nil),
			checks: checks(
				httpStatus(http.StatusForbidden),
				bodyContains("file sharing not enabled by Tailscale admin"),
			),
		},
		{
			name:       "owner_with_cap_no_rootdir",
			omitRoot:   true,
			isSelf:     true,
			capSharing: true,
			req:        httptest.NewRequest("PUT", "/v0/put/foo", nil),
			checks: checks(
				httpStatus(http.StatusInternalServerError),
				bodyContains("no rootdir"),
			),
		},
		{
			name:       "bad_method",
			isSelf:     true,
			capSharing: true,
			req:        httptest.NewRequest("POST", "/v0/put/foo", nil),
			checks: checks(
				httpStatus(405),
				bodyContains("expected method PUT"),
			),
		},
		{
			name:       "put_zero_length",
			isSelf:     true,
			capSharing: true,
			req:        httptest.NewRequest("PUT", "/v0/put/foo", nil),
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
			req:        httptest.NewRequest("PUT", "/v0/put/foo", strings.NewReader("contents")),
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
			req:        httptest.NewRequest("PUT", "/v0/put/foo", struct{ io.Reader }{strings.NewReader("contents")}),
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
			req:        httptest.NewRequest("PUT", "/v0/put/foo.partial", nil),
			checks: checks(
				httpStatus(400),
				bodyContains("bad filename"),
			),
		},
		{
			name:       "bad_filename_dot",
			isSelf:     true,
			capSharing: true,
			req:        httptest.NewRequest("PUT", "/v0/put/.", nil),
			checks: checks(
				httpStatus(400),
				bodyContains("bad filename"),
			),
		},
		{
			name:       "bad_filename_empty",
			isSelf:     true,
			capSharing: true,
			req:        httptest.NewRequest("PUT", "/v0/put/", nil),
			checks: checks(
				httpStatus(400),
				bodyContains("empty filename"),
			),
		},
		{
			name:       "bad_filename_slash",
			isSelf:     true,
			capSharing: true,
			req:        httptest.NewRequest("PUT", "/v0/put/foo/bar", nil),
			checks: checks(
				httpStatus(400),
				bodyContains("directories not supported"),
			),
		},
		{
			name:       "bad_filename_encoded_dot",
			isSelf:     true,
			capSharing: true,
			req:        httptest.NewRequest("PUT", "/v0/put/"+hexAll("."), nil),
			checks: checks(
				httpStatus(400),
				bodyContains("bad filename"),
			),
		},
		{
			name:       "bad_filename_encoded_slash",
			isSelf:     true,
			capSharing: true,
			req:        httptest.NewRequest("PUT", "/v0/put/"+hexAll("/"), nil),
			checks: checks(
				httpStatus(400),
				bodyContains("bad filename"),
			),
		},
		{
			name:       "bad_filename_encoded_backslash",
			isSelf:     true,
			capSharing: true,
			req:        httptest.NewRequest("PUT", "/v0/put/"+hexAll("\\"), nil),
			checks: checks(
				httpStatus(400),
				bodyContains("bad filename"),
			),
		},
		{
			name:       "bad_filename_encoded_dotdot",
			isSelf:     true,
			capSharing: true,
			req:        httptest.NewRequest("PUT", "/v0/put/"+hexAll(".."), nil),
			checks: checks(
				httpStatus(400),
				bodyContains("bad filename"),
			),
		},
		{
			name:       "bad_filename_encoded_dotdot_out",
			isSelf:     true,
			capSharing: true,
			req:        httptest.NewRequest("PUT", "/v0/put/"+hexAll("foo/../../../../../etc/passwd"), nil),
			checks: checks(
				httpStatus(400),
				bodyContains("bad filename"),
			),
		},
		{
			name:       "put_spaces_and_caps",
			isSelf:     true,
			capSharing: true,
			req:        httptest.NewRequest("PUT", "/v0/put/"+hexAll("Foo Bar.dat"), strings.NewReader("baz")),
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
			req:        httptest.NewRequest("PUT", "/v0/put/"+hexAll("Томас и его друзья.mp3"), strings.NewReader("главный озорник")),
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
			req:        httptest.NewRequest("PUT", "/v0/put/"+(hexAll("😜")[:3]), nil),
			checks: checks(
				httpStatus(400),
				bodyContains("bad filename"),
			),
		},
		{
			name:       "put_invalid_null",
			isSelf:     true,
			capSharing: true,
			req:        httptest.NewRequest("PUT", "/v0/put/%00", nil),
			checks: checks(
				httpStatus(400),
				bodyContains("bad filename"),
			),
		},
		{
			name:       "put_invalid_non_printable",
			isSelf:     true,
			capSharing: true,
			req:        httptest.NewRequest("PUT", "/v0/put/%01", nil),
			checks: checks(
				httpStatus(400),
				bodyContains("bad filename"),
			),
		},
		{
			name:       "put_invalid_colon",
			isSelf:     true,
			capSharing: true,
			req:        httptest.NewRequest("PUT", "/v0/put/"+hexAll("nul:"), nil),
			checks: checks(
				httpStatus(400),
				bodyContains("bad filename"),
			),
		},
		{
			name:       "put_invalid_surrounding_whitespace",
			isSelf:     true,
			capSharing: true,
			req:        httptest.NewRequest("PUT", "/v0/put/"+hexAll(" foo "), nil),
			checks: checks(
				httpStatus(400),
				bodyContains("bad filename"),
			),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var caps []string
			if tt.capSharing {
				caps = append(caps, tailcfg.CapabilityFileSharing)
			}
			var e peerAPITestEnv
			lb := &LocalBackend{
				netMap: &netmap.NetworkMap{
					SelfNode: &tailcfg.Node{
						Capabilities: caps,
					},
				},
				logf: e.logf,
			}
			e.ph = &peerAPIHandler{
				isSelf: tt.isSelf,
				peerNode: &tailcfg.Node{
					ComputedName: "some-peer-name",
				},
				ps: &peerAPIServer{
					b: lb,
				},
			}
			var rootDir string
			if !tt.omitRoot {
				rootDir = t.TempDir()
				e.ph.ps.rootDir = rootDir
			}
			e.rr = httptest.NewRecorder()
			e.ph.ServeHTTP(e.rr, tt.req)
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
			logf: t.Logf,
			netMap: &netmap.NetworkMap{
				SelfNode: &tailcfg.Node{
					Capabilities: []string{tailcfg.CapabilityFileSharing},
				},
			},
		},
		rootDir: dir,
	}
	ph := &peerAPIHandler{
		isSelf: true,
		peerNode: &tailcfg.Node{
			ComputedName: "some-peer-name",
		},
		ps: ps,
	}
	buf := make([]byte, 2<<20)
	for i := 0; i < 30; i++ {
		rr := httptest.NewRecorder()
		ph.ServeHTTP(rr, httptest.NewRequest("PUT", "/v0/put/foo.txt", bytes.NewReader(buf[:rand.Intn(len(buf))])))
		if res := rr.Result(); res.StatusCode != 200 {
			t.Fatal(res.Status)
		}
		wfs, err := ps.WaitingFiles()
		if err != nil {
			t.Fatal(err)
		}
		if len(wfs) != 1 {
			t.Fatalf("waiting files = %d; want 1", len(wfs))
		}

		if err := ps.DeleteFile("foo.txt"); err != nil {
			t.Fatal(err)
		}
		wfs, err = ps.WaitingFiles()
		if err != nil {
			t.Fatal(err)
		}
		if len(wfs) != 0 {
			t.Fatalf("waiting files = %d; want 0", len(wfs))
		}
	}
}
