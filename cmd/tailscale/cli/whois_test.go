// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package cli

import (
	"encoding/json"
	"io"
	"reflect"
	"strings"
	"testing"

	"tailscale.com/client/tailscale/apitype"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/tailcfg"
	"tailscale.com/tstest"
)

func TestPrintWhoIsTailnet(t *testing.T) {
	who := &apitype.WhoIsResponse{
		Node:        &tailcfg.Node{Name: "node.example.ts.net.", StableID: "node-abcd"},
		UserProfile: &tailcfg.UserProfile{ID: 1, LoginName: "alice@example.com"},
	}
	for _, tt := range []struct {
		name        string
		tailnet     *ipnstate.TailnetStatus
		wantTailnet string
	}{
		{
			name: "with_id",
			tailnet: &ipnstate.TailnetStatus{
				Name: "example.com", StableID: "tailnet-abcd", MagicDNSSuffix: "example.ts.net",
			},
			wantTailnet: "Name: example.com ID: tailnet-abcd MagicDNS Suffix: example.ts.net",
		},
		{
			name: "without_id",
			tailnet: &ipnstate.TailnetStatus{
				Name: "example.com", MagicDNSSuffix: "example.ts.net",
			},
			wantTailnet: "Name: example.com MagicDNS Suffix: example.ts.net",
		},
		{name: "peer"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var out strings.Builder
			tstest.Replace[io.Writer](t, &Stdout, &out)
			if err := printWhoIs(who, tt.tailnet, false); err != nil {
				t.Fatal(err)
			}
			// Get everything after the section header
			_, tailnetOutput, hasTailnet := strings.Cut(out.String(), "Tailnet:\n")
			if want := tt.tailnet != nil; hasTailnet != want {
				t.Fatalf("Tailnet section present = %v; want %v", hasTailnet, want)
			}
			// Ignore tabwriter's spacing when comparing the contents.
			gotTailnet := strings.Join(strings.Fields(tailnetOutput), " ")
			if gotTailnet != tt.wantTailnet {
				t.Errorf("tailnet output = %q; want %q", gotTailnet, tt.wantTailnet)
			}

			out.Reset()
			if err := printWhoIs(who, tt.tailnet, true); err != nil {
				t.Fatal(err)
			}
			var got whoisAndTailnet
			if err := json.Unmarshal([]byte(out.String()), &got); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got.CurrentTailnet, tt.tailnet) {
				t.Errorf("JSON CurrentTailnet = %+v; want %+v", got.CurrentTailnet, tt.tailnet)
			}
		})
	}
}
