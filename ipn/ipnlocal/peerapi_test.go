// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ipnlocal

import (
	"bytes"
	"fmt"
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

func fileHasSize(name string, size int64) check {
	return func(t *testing.T, e *peerAPITestEnv) {
		root := e.ph.ps.rootDir
		if root == "" {
			t.Errorf("no rootdir; can't check whether %q has size %v", name, size)
			return
		}
		path := filepath.Join(root, name)
		if fi, err := os.Stat(path); err != nil {
			t.Errorf("fileHasSize(%q, %v): %v", name, size, err)
		} else if fi.Size() != size {
			t.Errorf("file %q has size %v; want %v", name, fi.Size(), size)
		}
	}
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
			name:       "owner_with_cap",
			isSelf:     true,
			capSharing: true,
			req:        httptest.NewRequest("PUT", "/v0/put/foo", nil),
			checks: checks(
				httpStatus(200),
				bodyContains("{}"),
				fileHasSize("foo", 0),
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
			if !tt.omitRoot {
				e.ph.ps.rootDir = t.TempDir()
			}
			e.rr = httptest.NewRecorder()
			e.ph.ServeHTTP(e.rr, tt.req)
			for _, f := range tt.checks {
				f(t, &e)
			}
		})
	}
}
