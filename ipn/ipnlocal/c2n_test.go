// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package ipnlocal

import (
	"bytes"
	"cmp"
	"crypto/x509"
	"encoding/json"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"tailscale.com/ipn/store/mem"
	"tailscale.com/tailcfg"
	"tailscale.com/tstest"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
	"tailscale.com/types/netmap"
	"tailscale.com/types/views"
	"tailscale.com/util/must"

	gcmp "github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
)

func TestHandleC2NTLSCertStatus(t *testing.T) {
	b := &LocalBackend{
		store:   &mem.Store{},
		varRoot: t.TempDir(),
	}
	certDir, err := b.certDir()
	if err != nil {
		t.Fatalf("certDir error: %v", err)
	}
	if _, err := b.getCertStore(); err != nil {
		t.Fatalf("getCertStore error: %v", err)
	}

	testRoot, err := certTestFS.ReadFile("testdata/rootCA.pem")
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(testRoot) {
		t.Fatal("Unable to add test CA to the cert pool")
	}
	testX509Roots = roots
	defer func() { testX509Roots = nil }()

	tests := []struct {
		name       string
		domain     string
		copyFile   bool   // copy testdata/example.com.pem to the certDir
		wantStatus int    // 0 means 200
		wantError  string // wanted non-JSON non-200 error
		now        time.Time
		want       *tailcfg.C2NTLSCertInfo
	}{
		{
			name:       "no domain",
			wantStatus: 400,
			wantError:  "no 'domain'\n",
		},
		{
			name:   "missing",
			domain: "example.com",
			want: &tailcfg.C2NTLSCertInfo{
				Error:   "no certificate",
				Missing: true,
			},
		},
		{
			name:     "valid",
			domain:   "example.com",
			now:      time.Date(2023, time.February, 20, 0, 0, 0, 0, time.UTC),
			copyFile: true,
			want: &tailcfg.C2NTLSCertInfo{
				Valid:     true,
				NotBefore: "2023-02-07T20:34:18Z",
				NotAfter:  "2025-05-07T19:34:18Z",
			},
		},
		{
			name:     "expired",
			domain:   "example.com",
			now:      time.Date(2030, time.February, 20, 0, 0, 0, 0, time.UTC),
			copyFile: true,
			want: &tailcfg.C2NTLSCertInfo{
				Error:   "cert expired",
				Expired: true,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			os.RemoveAll(certDir) // reset per test
			if tt.copyFile {
				os.MkdirAll(certDir, 0755)
				if err := os.WriteFile(filepath.Join(certDir, "example.com.crt"),
					must.Get(os.ReadFile("testdata/example.com.pem")), 0644); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(certDir, "example.com.key"),
					must.Get(os.ReadFile("testdata/example.com-key.pem")), 0644); err != nil {
					t.Fatal(err)
				}
			}
			b.clock = tstest.NewClock(tstest.ClockOpts{
				Start: tt.now,
			})

			rec := httptest.NewRecorder()
			handleC2NTLSCertStatus(b, rec, httptest.NewRequest("GET", "/tls-cert-status?domain="+url.QueryEscape(tt.domain), nil))
			res := rec.Result()
			wantStatus := cmp.Or(tt.wantStatus, 200)
			if res.StatusCode != wantStatus {
				t.Fatalf("status code = %v; want %v. Body: %s", res.Status, wantStatus, rec.Body.Bytes())
			}
			if wantStatus == 200 {
				var got tailcfg.C2NTLSCertInfo
				if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
					t.Fatalf("bad JSON: %v", err)
				}
				if !reflect.DeepEqual(&got, tt.want) {
					t.Errorf("got %v; want %v", logger.AsJSON(got), logger.AsJSON(tt.want))
				}
			} else if tt.wantError != "" {
				if got := rec.Body.String(); got != tt.wantError {
					t.Errorf("body = %q; want %q", got, tt.wantError)
				}
			}
		})
	}

}

func TestHandleC2NDebugNetmap(t *testing.T) {
	nm := &netmap.NetworkMap{
		SelfNode: (&tailcfg.Node{
			ID:       100,
			Name:     "myhost",
			StableID: "deadbeef",
			Key:      key.NewNode().Public(),
			Hostinfo: (&tailcfg.Hostinfo{Hostname: "myhost"}).View(),
		}).View(),
		Peers: []tailcfg.NodeView{
			(&tailcfg.Node{
				ID:       101,
				Name:     "peer1",
				StableID: "deadbeef",
				Key:      key.NewNode().Public(),
				Hostinfo: (&tailcfg.Hostinfo{Hostname: "peer1"}).View(),
			}).View(),
		},
	}

	for _, tt := range []struct {
		name string
		req  *tailcfg.C2NDebugNetmapRequest
		want *netmap.NetworkMap
	}{
		{
			name: "simple_get",
			want: nm,
		},
		{
			name: "post_no_omit",
			req:  &tailcfg.C2NDebugNetmapRequest{},
			want: nm,
		},
		{
			name: "post_omit_peers_and_name",
			req:  &tailcfg.C2NDebugNetmapRequest{OmitFields: []string{"Peers", "Name"}},
			want: &netmap.NetworkMap{
				SelfNode: nm.SelfNode,
			},
		},
		{
			name: "post_omit_nonexistent_field",
			req:  &tailcfg.C2NDebugNetmapRequest{OmitFields: []string{"ThisFieldDoesNotExist"}},
			want: nm,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			b := newTestLocalBackend(t)
			b.currentNode().SetNetMap(nm)

			rec := httptest.NewRecorder()
			req := httptest.NewRequest("GET", "/debug/netmap", nil)
			if tt.req != nil {
				b, err := json.Marshal(tt.req)
				if err != nil {
					t.Fatalf("json.Marshal: %v", err)
				}
				req = httptest.NewRequest("POST", "/debug/netmap", bytes.NewReader(b))
			}
			handleC2NDebugNetMap(b, rec, req)
			res := rec.Result()
			wantStatus := 200
			if res.StatusCode != wantStatus {
				t.Fatalf("status code = %v; want %v. Body: %s", res.Status, wantStatus, rec.Body.Bytes())
			}
			var resp tailcfg.C2NDebugNetmapResponse
			if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
				t.Fatalf("bad JSON: %v", err)
			}
			got := &netmap.NetworkMap{}
			if err := json.Unmarshal(resp.Current, got); err != nil {
				t.Fatalf("bad JSON: %v", err)
			}

			if diff := gcmp.Diff(tt.want, got,
				gcmp.AllowUnexported(netmap.NetworkMap{}, key.NodePublic{}, views.Slice[tailcfg.FilterRule]{}),
				cmpopts.EquateComparable(key.MachinePublic{}),
			); diff != "" {
				t.Errorf("netmap mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
