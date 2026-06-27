// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package ipnlocal

import (
	"bytes"
	"encoding/json"
	"net/http/httptest"
	"testing"

	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
	"tailscale.com/types/netmap"
	"tailscale.com/types/views"

	gcmp "github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
)

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
