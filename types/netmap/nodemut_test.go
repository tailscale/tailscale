// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package netmap

import (
	"fmt"
	"net/netip"
	"reflect"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"tailscale.com/tailcfg"
	"tailscale.com/types/logger"
	"tailscale.com/types/opt"
	"tailscale.com/types/ptr"
)

// tests mapResponseContainsNonPatchFields
func TestMapResponseContainsNonPatchFields(t *testing.T) {

	// reflectNonzero returns a non-zero value of the given type.
	reflectNonzero := func(t reflect.Type) reflect.Value {

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
		}
		panic(fmt.Sprintf("unhandled %v", t))
	}

	rt := reflect.TypeFor[tailcfg.MapResponse]()
	for i := range rt.NumField() {
		f := rt.Field(i)

		var want bool
		switch f.Name {
		case "MapSessionHandle", "Seq", "KeepAlive", "PingRequest", "PopBrowserURL", "ControlTime":
			// There are meta fields that apply to all MapResponse values.
			// They should be ignored.
			want = false
		case "PeersChangedPatch", "PeerSeenChange", "OnlineChange":
			// The actual three delta fields we care about handling.
			want = false
		default:
			// Everything else should be conseratively handled as a
			// non-delta field. We want it to return true so if
			// the field is not listed in the function being tested,
			// it'll return false and we'll fail this test.
			// This makes sure any new fields added to MapResponse
			// are accounted for here.
			want = true
		}

		var v tailcfg.MapResponse
		rv := reflect.ValueOf(&v).Elem()
		rv.FieldByName(f.Name).Set(reflectNonzero(f.Type))

		got := mapResponseContainsNonPatchFields(&v)
		if got != want {
			t.Errorf("field %q: got %v; want %v\nJSON: %v", f.Name, got, want, logger.AsJSON(v))
		}
	}
}

// tests MutationsFromMapResponse
func TestMutationsFromMapResponse(t *testing.T) {
	someTime := time.Unix(123, 0)
	fromChanges := func(changes ...*tailcfg.PeerChange) *tailcfg.MapResponse {
		return &tailcfg.MapResponse{
			PeersChangedPatch: changes,
		}
	}
	muts := func(muts ...NodeMutation) []NodeMutation { return muts }
	tests := []struct {
		name string
		mr   *tailcfg.MapResponse
		want []NodeMutation // nil means !ok, zero-length means none
	}{
		{
			name: "patch-ep",
			mr: fromChanges(&tailcfg.PeerChange{
				NodeID:    1,
				Endpoints: eps("1.2.3.4:567"),
			}, &tailcfg.PeerChange{
				NodeID:    2,
				Endpoints: eps("8.9.10.11:1234"),
			}),
			want: muts(
				NodeMutationEndpoints{1, []netip.AddrPort{netip.MustParseAddrPort("1.2.3.4:567")}},
				NodeMutationEndpoints{2, []netip.AddrPort{netip.MustParseAddrPort("8.9.10.11:1234")}},
			),
		},
		{
			name: "patch-derp",
			mr: fromChanges(&tailcfg.PeerChange{
				NodeID:     1,
				DERPRegion: 2,
			}),
			want: muts(NodeMutationDERPHome{1, 2}),
		},
		{
			name: "patch-online",
			mr: fromChanges(&tailcfg.PeerChange{
				NodeID: 1,
				Online: ptr.To(true),
			}),
			want: muts(NodeMutationOnline{1, true}),
		},
		{
			name: "patch-online-false",
			mr: fromChanges(&tailcfg.PeerChange{
				NodeID: 1,
				Online: ptr.To(false),
			}),
			want: muts(NodeMutationOnline{1, false}),
		},
		{
			name: "patch-lastseen",
			mr: fromChanges(&tailcfg.PeerChange{
				NodeID:   1,
				LastSeen: ptr.To(time.Unix(12345, 0)),
			}),
			want: muts(NodeMutationLastSeen{1, time.Unix(12345, 0)}),
		},
		{
			name: "legacy-online-change", // the old pre-Patch style
			mr: &tailcfg.MapResponse{
				OnlineChange: map[tailcfg.NodeID]bool{
					1: true,
					2: false,
				},
			},
			want: muts(
				NodeMutationOnline{1, true},
				NodeMutationOnline{2, false},
			),
		},
		{
			name: "legacy-lastseen-change", // the old pre-Patch style
			mr: &tailcfg.MapResponse{
				PeerSeenChange: map[tailcfg.NodeID]bool{
					1: true,
				},
			},
			want: muts(
				NodeMutationLastSeen{1, someTime},
			),
		},
		{
			name: "no-changes",
			mr:   fromChanges(),
			want: make([]NodeMutation, 0), // non-nil to mean want ok but no changes
		},
		{
			name: "not-okay-patch-node-change",
			mr: &tailcfg.MapResponse{
				Node: &tailcfg.Node{}, // non-nil
				PeersChangedPatch: []*tailcfg.PeerChange{{
					NodeID:     1,
					DERPRegion: 2,
				}},
			},
			want: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, gotOK := MutationsFromMapResponse(tt.mr, someTime)
			wantOK := tt.want != nil
			if gotOK != wantOK {
				t.Errorf("got ok=%v; want %v", gotOK, wantOK)
			} else if got == nil && gotOK {
				got = make([]NodeMutation, 0) // for cmd.Diff
			}
			if diff := cmp.Diff(tt.want, got,
				cmp.Comparer(func(a, b netip.Addr) bool { return a == b }),
				cmp.Comparer(func(a, b netip.AddrPort) bool { return a == b }),
				cmp.AllowUnexported(
					NodeMutationEndpoints{},
					NodeMutationDERPHome{},
					NodeMutationOnline{},
					NodeMutationLastSeen{},
				)); diff != "" {
				t.Errorf("wrong result (-want +got):\n%s", diff)
			}
		})
	}
}
