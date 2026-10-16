// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ts_omit_drive

package localapi

import (
	"net/http"
	"net/http/httptest"
	"net/netip"
	"slices"
	"strings"
	"testing"

	"tailscale.com/drive"
	"tailscale.com/ipn/ipnauth"
	"tailscale.com/ipn/ipnlocal"
	"tailscale.com/tailcfg"
	"tailscale.com/tailcfg/nodecap"
	"tailscale.com/types/key"
	"tailscale.com/types/netmap"
	"tailscale.com/util/set"
)

// fakeDriveForRemote is a [drive.FileSystemForRemote] that only records
// what it was configured with.
type fakeDriveForRemote struct {
	addr string
}

func (f *fakeDriveForRemote) SetFileServerAddr(addr string) { f.addr = addr }
func (f *fakeDriveForRemote) SetShares([]*drive.Share)      {}
func (f *fakeDriveForRemote) ServeHTTPWithPerms(drive.Permissions, http.ResponseWriter, *http.Request) {
}
func (f *fakeDriveForRemote) Close() error { return nil }

// newDriveTestBackend returns a LocalBackend that has Taildrive sharing
// enabled via the drive:share node attribute and one share named "docs".
func newDriveTestBackend(t testing.TB, fs drive.FileSystemForRemote) *ipnlocal.LocalBackend {
	t.Helper()
	lb := newTestLocalBackend(t)
	lb.Sys().Set(fs)
	lb.ForTest().SetNetMap(&netmap.NetworkMap{
		SelfNode: (&tailcfg.Node{
			ID:        1,
			Key:       key.NewNode().Public(),
			Addresses: []netip.Prefix{netip.MustParsePrefix("100.64.0.1/32")},
		}).View(),
		AllCaps: set.Of(nodecap.TaildriveShare),
	})
	if !lb.DriveSharingEnabled() {
		t.Fatal("DriveSharingEnabled() = false, want true")
	}
	if err := lb.DriveSetShare(&drive.Share{Name: "docs", Path: t.TempDir(), As: "user"}); err != nil {
		t.Fatalf("DriveSetShare: %v", err)
	}
	return lb
}

func TestServeSharesGate(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	tests := []struct {
		desc        string
		method      string
		body        string
		permitWrite bool
		wantStatus  int
		wantShares  []string
	}{
		{
			desc:       "get-read-only",
			method:     "GET",
			wantStatus: http.StatusOK,
			wantShares: []string{"docs"},
		},
		{
			desc:       "put-read-only-denied",
			method:     "PUT",
			body:       `{"name":"other","path":"` + dir + `"}`,
			wantStatus: http.StatusForbidden,
			wantShares: []string{"docs"},
		},
		{
			desc:        "put-write-allowed",
			method:      "PUT",
			body:        `{"name":"other","path":"` + dir + `"}`,
			permitWrite: true,
			wantStatus:  http.StatusCreated,
			wantShares:  []string{"docs", "other"},
		},
		{
			desc:       "delete-read-only-denied",
			method:     "DELETE",
			body:       "docs",
			wantStatus: http.StatusForbidden,
			wantShares: []string{"docs"},
		},
		{
			desc:        "delete-write-allowed",
			method:      "DELETE",
			body:        "docs",
			permitWrite: true,
			wantStatus:  http.StatusNoContent,
		},
		{
			desc:       "rename-read-only-denied",
			method:     "POST",
			body:       `["docs","renamed"]`,
			wantStatus: http.StatusForbidden,
			wantShares: []string{"docs"},
		},
		{
			desc:        "rename-write-allowed",
			method:      "POST",
			body:        `["docs","renamed"]`,
			permitWrite: true,
			wantStatus:  http.StatusNoContent,
			wantShares:  []string{"renamed"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			lb := newDriveTestBackend(t, &fakeDriveForRemote{})
			h := handlerForTest(t, &Handler{
				PermitRead:  true,
				PermitWrite: tt.permitWrite,
				Actor:       &ipnauth.TestActor{Name: "user"},
				b:           lb,
			})
			req := httptest.NewRequest(tt.method, "http://local-tailscaled.sock/localapi/v0/drive/shares",
				strings.NewReader(tt.body))
			resp := httptest.NewRecorder()
			h.serveShares(resp, req)

			if resp.Code != tt.wantStatus {
				t.Errorf("status = %d, want %d; body: %s", resp.Code, tt.wantStatus, resp.Body.String())
			}
			var gotShares []string
			for _, s := range lb.DriveGetShares().All() {
				gotShares = append(gotShares, s.Name())
			}
			if !slices.Equal(gotShares, tt.wantShares) {
				t.Errorf("shares = %q, want %q", gotShares, tt.wantShares)
			}
		})
	}
}

func TestServeDriveServerAddrGate(t *testing.T) {
	t.Parallel()

	const addr = "token|127.0.0.1:12345"
	tests := []struct {
		desc        string
		permitWrite bool
		wantStatus  int
		wantAddr    string
	}{
		{
			desc:       "read-only-denied",
			wantStatus: http.StatusForbidden,
		},
		{
			desc:        "write-allowed",
			permitWrite: true,
			wantStatus:  http.StatusCreated,
			wantAddr:    addr,
		},
	}

	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			fs := &fakeDriveForRemote{}
			lb := newTestLocalBackend(t)
			lb.Sys().Set(fs)
			h := handlerForTest(t, &Handler{
				PermitRead:  true,
				PermitWrite: tt.permitWrite,
				b:           lb,
			})
			req := httptest.NewRequest("PUT", "http://local-tailscaled.sock/localapi/v0/drive/fileserver-address",
				strings.NewReader(addr))
			resp := httptest.NewRecorder()
			h.serveDriveServerAddr(resp, req)

			if resp.Code != tt.wantStatus {
				t.Errorf("status = %d, want %d; body: %s", resp.Code, tt.wantStatus, resp.Body.String())
			}
			if fs.addr != tt.wantAddr {
				t.Errorf("file server addr = %q, want %q", fs.addr, tt.wantAddr)
			}
		})
	}
}
