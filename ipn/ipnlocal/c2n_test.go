// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package ipnlocal

import (
	"bytes"
	"cmp"
	"crypto/x509"
	"encoding/json"
	"fmt"
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
	"tailscale.com/types/opt"
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

// reflectNonzero returns a non-zero value for a given reflect.Value.
func reflectNonzero(t reflect.Type) reflect.Value {
	switch t.Kind() {
	case reflect.Bool:
		return reflect.ValueOf(true)
	case reflect.String:
		if reflect.TypeFor[opt.Bool]() == t {
			return reflect.ValueOf("true").Convert(t)
		}
		return reflect.ValueOf("foo").Convert(t)
	case reflect.Int64:
		return reflect.ValueOf(int64(1)).Convert(t)
	case reflect.Slice:
		return reflect.MakeSlice(t, 1, 1)
	case reflect.Ptr:
		return reflect.New(t.Elem())
	case reflect.Map:
		return reflect.MakeMap(t)
	case reflect.Struct:
		switch t {
		case reflect.TypeFor[key.NodePrivate]():
			return reflect.ValueOf(key.NewNode())
		}
	}
	panic(fmt.Sprintf("unhandled %v", t))
}

// setFieldsToRedact sets fields in the given netmap to non-zero values
// according to the fieldMap, which maps field names to whether they
// should be reset (true) or not (false).
func setFieldsToRedact(t *testing.T, nm *netmap.NetworkMap, fieldMap map[string]bool) {
	t.Helper()
	v := reflect.ValueOf(nm).Elem()
	for i := range v.NumField() {
		name := v.Type().Field(i).Name
		f := v.Field(i)
		if !f.CanSet() {
			continue
		}
		shouldReset, ok := fieldMap[name]
		if !ok {
			t.Errorf("fieldMap missing field %q", name)
		}
		if shouldReset {
			f.Set(reflectNonzero(f.Type()))
		}
	}
}

func TestRedactNetmapPrivateKeys(t *testing.T) {
	fieldMap := map[string]bool{
		// Private fields (should be redacted):
		"PrivateKey": true,

		// Public fields (should not be redacted):
		"AllCaps":           false,
		"CollectServices":   false,
		"DERPMap":           false,
		"DNS":               false,
		"DisplayMessages":   false,
		"Domain":            false,
		"DomainAuditLogID":  false,
		"Expiry":            false,
		"MachineKey":        false,
		"Name":              false,
		"NodeKey":           false,
		"PacketFilter":      false,
		"PacketFilterRules": false,
		"Peers":             false,
		"SSHPolicy":         false,
		"SelfNode":          false,
		"TKAEnabled":        false,
		"TKAHead":           false,
		"UserProfiles":      false,
	}

	nm := &netmap.NetworkMap{}
	setFieldsToRedact(t, nm, fieldMap)

	got, _ := redactNetmapPrivateKeys(nm)
	if !reflect.DeepEqual(got, &netmap.NetworkMap{}) {
		t.Errorf("redacted netmap is not empty: %+v", got)
	}
}

func TestHandleC2NDebugNetmap(t *testing.T) {
	nm := &netmap.NetworkMap{
		Name: "myhost",
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
		PrivateKey: key.NewNode(),
	}
	withoutPrivateKey := *nm
	withoutPrivateKey.PrivateKey = key.NodePrivate{}

	for _, tt := range []struct {
		name string
		req  *tailcfg.C2NDebugNetmapRequest
		want *netmap.NetworkMap
	}{
		{
			name: "simple_get",
			want: &withoutPrivateKey,
		},
		{
			name: "post_no_omit",
			req:  &tailcfg.C2NDebugNetmapRequest{},
			want: &withoutPrivateKey,
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
			want: &withoutPrivateKey,
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
