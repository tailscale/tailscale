// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ts_omit_drive && !ts_mac_gui

package cli

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/studio-b12/gowebdav"
	"github.com/tailscale/xnet/webdav"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/types/key"
)

func driveTestStatus() *ipnstate.Status {
	return &ipnstate.Status{
		CurrentTailnet: &ipnstate.TailnetStatus{Name: "example.com", MagicDNSSuffix: "example.ts.net"},
		Peer: map[key.NodePublic]*ipnstate.PeerStatus{
			{}: {DNSName: "pippo.example.ts.net.", HostName: "different-hostname", TailscaleIPs: []netip.Addr{netip.MustParseAddr("100.101.102.103")}},
		},
	}
}

func TestDriveDAVPath(t *testing.T) {
	for _, node := range []string{"pippo", "PIPPO", "pippo.example.ts.net", "pippo.example.ts.net.", "100.101.102.103"} {
		t.Run(node, func(t *testing.T) {
			got, err := driveDAVPath(driveTestStatus(), driveRemotePath{node, "shared", "subdirectory/"})
			if err != nil || got != "/example.com/pippo/shared/subdirectory" {
				t.Fatalf("driveDAVPath = %q, %v", got, err)
			}
		})
	}
	st := driveTestStatus()
	st.Peer[key.NodePublic{}].DNSName = "pippo.other.ts.net."
	got, err := driveDAVPath(st, driveRemotePath{"pippo.other.ts.net", "shared", ""})
	if err != nil || got != "/example.com/pippo.other.ts.net/shared" {
		t.Fatalf("shared-in peer path = %q, %v", got, err)
	}
	st.Peer[key.NodePublic{}].DNSName = ""
	got, err = driveDAVPath(st, driveRemotePath{"100.101.102.103", "shared", ""})
	if err != nil || got != "/example.com/different-hostname/shared" {
		t.Fatalf("peer without DNS path = %q, %v", got, err)
	}
	if _, err := driveDAVPath(st, driveRemotePath{node: "missing"}); err == nil || !strings.Contains(err.Error(), "not found") {
		t.Fatalf("missing node error = %v", err)
	}
	st.CurrentTailnet = nil
	if _, err := driveDAVPath(st, driveRemotePath{node: "100.101.102.103"}); err == nil {
		t.Fatal("missing tailnet succeeded")
	}
}

func TestListDriveDirectory(t *testing.T) {
	for _, tt := range []struct {
		name, arg, wantPath string
		empty               bool
	}{
		{"root", "pippo:shared", "/example.com/pippo/shared/", false},
		{"nested", "pippo:shared/subdirectory/", "/example.com/pippo/shared/subdirectory/", false},
		{"escaped", "pippo:my share/sp ace/日本語/%2e%2e/%/#/?/", "/example.com/pippo/my share/sp ace/日本語/%2e%2e/%/#/?/", false},
		{"empty", "pippo:shared/empty", "/example.com/pippo/shared/empty/", true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			mod := time.Date(2026, 9, 27, 14, 10, 0, 0, time.UTC)
			if !tt.empty {
				for _, name := range []string{"z documents", "a目录"} {
					if err := os.Mkdir(filepath.Join(dir, name), 0700); err != nil {
						t.Fatal(err)
					}
				}
				for _, name := range []string{"a file.txt", "日本語%#.txt"} {
					path := filepath.Join(dir, name)
					if err := os.WriteFile(path, []byte("hello"), 0600); err != nil {
						t.Fatal(err)
					}
					if err := os.Chtimes(path, mod, mod); err != nil {
						t.Fatal(err)
					}
				}
			}
			dav := &webdav.Handler{Prefix: strings.TrimSuffix(tt.wantPath, "/"), FileSystem: webdav.Dir(dir), LockSystem: webdav.NewMemLS()}
			requests := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests++
				wantURI := (&url.URL{Path: tt.wantPath}).EscapedPath()
				if r.Method != "PROPFIND" || r.Header.Get("Depth") != "1" || r.URL.Path != tt.wantPath || r.RequestURI != wantURI {
					t.Errorf("request = %s %s (path %q, depth %q); want PROPFIND %s", r.Method, r.RequestURI, r.URL.Path, r.Header.Get("Depth"), wantURI)
				}
				dav.ServeHTTP(w, r)
			}))
			defer server.Close()
			remote, err := parseDriveRemotePath(tt.arg)
			if err != nil {
				t.Fatal(err)
			}
			var out strings.Builder
			if err := listDriveDirectory(context.Background(), &out, driveTestStatus(), remote, server.URL); err != nil {
				t.Fatal(err)
			}
			// gowebdav first probes the authentication scheme, then repeats
			// the request with its no-auth authenticator.
			if requests != 2 {
				t.Errorf("requests = %d; want 2", requests)
			}
			lines := strings.Split(strings.TrimSpace(out.String()), "\n")
			if strings.Join(strings.Fields(lines[0]), " ") != "NAME SIZE MODIFIED" {
				t.Fatalf("header = %q", lines[0])
			}
			if tt.empty {
				if len(lines) != 1 {
					t.Fatalf("empty directory output = %q", out.String())
				}
				return
			}
			if len(lines) != 5 {
				t.Fatalf("output includes wrong number of children: %q", out.String())
			}
			for i, name := range []string{"a目录/", "z documents/", "a file.txt", "日本語%#.txt"} {
				if !strings.HasPrefix(lines[i+1], name) {
					t.Errorf("line %d = %q; want name %q", i+1, lines[i+1], name)
				}
				if i >= 2 && (!strings.Contains(lines[i+1], "5 B") || !strings.Contains(lines[i+1], mod.Local().Format("2006-01-02 15:04"))) {
					t.Errorf("missing size or modification time: %q", lines[i+1])
				}
			}
		})
	}
}

func TestListDriveDirectoryErrors(t *testing.T) {
	for _, tt := range []struct {
		name   string
		status int
		body   string
		want   string
	}{
		{"forbidden", 403, "<secret/>", "access denied"},
		{"not-found", 404, "<secret/>", "not found"},
		{"invalid-xml", 207, `<d:multistatus xmlns:d="DAV:"><secret>`, "protocol error"},
		{"wrong-envelope", 207, "<secret/>", "protocol error"},
		{"no-directory-entry", 207, `<d:multistatus xmlns:d="DAV:"/>`, "protocol error"},
		{"redirect", 302, "", "HTTP 302"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Location", "/outside-share")
				w.WriteHeader(tt.status)
				fmt.Fprint(w, tt.body)
			}))
			defer server.Close()
			var out strings.Builder
			err := listDriveDirectory(context.Background(), &out, driveTestStatus(), driveRemotePath{"pippo", "shared", ""}, server.URL)
			if err == nil || !strings.Contains(err.Error(), tt.want) || strings.Contains(err.Error(), "secret") {
				t.Fatalf("error = %v; want %q without XML", err, tt.want)
			}
			if errors.Unwrap(err) == nil || out.Len() != 0 {
				t.Fatalf("missing wrapped error or partial output: %v, %q", err, out.String())
			}
			if tt.status != 207 {
				var status gowebdav.StatusError
				if !errors.As(err, &status) || status.Status != tt.status {
					t.Fatalf("lost HTTP status: %v", err)
				}
			}
		})
	}
	server := httptest.NewServer(http.NotFoundHandler())
	server.Close()
	var out strings.Builder
	err := listDriveDirectory(context.Background(), &out, driveTestStatus(), driveRemotePath{"pippo", "shared", ""}, server.URL)
	if err == nil || !strings.Contains(err.Error(), "local service unavailable") {
		t.Fatalf("closed server error = %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err = listDriveDirectory(ctx, &out, driveTestStatus(), driveRemotePath{"pippo", "shared", ""}, server.URL)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled context error = %v", err)
	}
}
