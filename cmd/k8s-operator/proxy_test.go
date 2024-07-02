// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

package main

import (
	"net/http"
	"net/netip"
	"reflect"
	"testing"

	"github.com/google/go-cmp/cmp"
	"go.uber.org/zap"
	"tailscale.com/client/tailscale/apitype"
	"tailscale.com/tailcfg"
	"tailscale.com/util/must"
)

func TestImpersonationHeaders(t *testing.T) {
	zl, err := zap.NewDevelopment()
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name     string
		emailish string
		tags     []string
		capMap   tailcfg.PeerCapMap

		wantHeaders http.Header
	}{
		{
			name:     "user",
			emailish: "foo@example.com",
			wantHeaders: http.Header{
				"Impersonate-User": {"foo@example.com"},
			},
		},
		{
			name:     "tagged",
			emailish: "tagged-device",
			tags:     []string{"tag:foo", "tag:bar"},
			wantHeaders: http.Header{
				"Impersonate-User":  {"node.ts.net"},
				"Impersonate-Group": {"tag:foo", "tag:bar"},
			},
		},
		{
			name:     "user-with-cap",
			emailish: "foo@example.com",
			capMap: tailcfg.PeerCapMap{
				tailcfg.PeerCapabilityKubernetes: {
					tailcfg.RawMessage(`{"impersonate":{"groups":["group1","group2"]}}`),
					tailcfg.RawMessage(`{"impersonate":{"groups":["group1","group3"]}}`), // One group is duplicated.
					tailcfg.RawMessage(`{"impersonate":{"groups":["group4"]}}`),
					tailcfg.RawMessage(`{"impersonate":{"groups":["group2"]}}`), // duplicate

					// These should be ignored, but should parse correctly.
					tailcfg.RawMessage(`{}`),
					tailcfg.RawMessage(`{"impersonate":{}}`),
					tailcfg.RawMessage(`{"impersonate":{"groups":[]}}`),
				},
			},
			wantHeaders: http.Header{
				"Impersonate-Group": {"group1", "group2", "group3", "group4"},
				"Impersonate-User":  {"foo@example.com"},
			},
		},
		{
			name:     "tagged-with-cap",
			emailish: "tagged-device",
			tags:     []string{"tag:foo", "tag:bar"},
			capMap: tailcfg.PeerCapMap{
				tailcfg.PeerCapabilityKubernetes: {
					tailcfg.RawMessage(`{"impersonate":{"groups":["group1"]}}`),
				},
			},
			wantHeaders: http.Header{
				"Impersonate-Group": {"group1"},
				"Impersonate-User":  {"node.ts.net"},
			},
		},
		{
			name:     "mix-of-caps",
			emailish: "tagged-device",
			tags:     []string{"tag:foo", "tag:bar"},
			capMap: tailcfg.PeerCapMap{
				tailcfg.PeerCapabilityKubernetes: {
					tailcfg.RawMessage(`{"impersonate":{"groups":["group1"]},"recorder":["tag:foo"],"enforceRecorder":true}`),
				},
			},
			wantHeaders: http.Header{
				"Impersonate-Group": {"group1"},
				"Impersonate-User":  {"node.ts.net"},
			},
		},
		{
			name:     "bad-cap",
			emailish: "tagged-device",
			tags:     []string{"tag:foo", "tag:bar"},
			capMap: tailcfg.PeerCapMap{
				tailcfg.PeerCapabilityKubernetes: {
					tailcfg.RawMessage(`[]`),
				},
			},
			wantHeaders: http.Header{},
		},
	}

	for _, tc := range tests {
		r := must.Get(http.NewRequest("GET", "https://op.ts.net/api/foo", nil))
		r = r.WithContext(whoIsKey.WithValue(r.Context(), &apitype.WhoIsResponse{
			Node: &tailcfg.Node{
				Name: "node.ts.net",
				Tags: tc.tags,
			},
			UserProfile: &tailcfg.UserProfile{
				LoginName: tc.emailish,
			},
			CapMap: tc.capMap,
		}))
		addImpersonationHeaders(r, zl.Sugar())

		if d := cmp.Diff(tc.wantHeaders, r.Header); d != "" {
			t.Errorf("unexpected header (-want +got):\n%s", d)
		}
	}
}

func Test_determineRecorderConfig(t *testing.T) {
	addr1, addr2 := netip.MustParseAddrPort("[fd7a:115c:a1e0:ab12:4843:cd96:626b:628b]:80"), netip.MustParseAddrPort("100.99.99.99:80")
	tests := []struct {
		name                  string
		wantFailOpen          bool
		wantRecorderAddresses []netip.AddrPort
		who                   *apitype.WhoIsResponse
	}{
		{
			name:                  "two_ips_fail_closed",
			who:                   whoResp(map[string][]string{string(tailcfg.PeerCapabilityKubernetes): {`{"recorderAddrs":["[fd7a:115c:a1e0:ab12:4843:cd96:626b:628b]:80","100.99.99.99:80"],"enforceRecorder":true}`}}),
			wantRecorderAddresses: []netip.AddrPort{addr1, addr2},
		},
		{
			name:                  "two_ips_fail_open",
			who:                   whoResp(map[string][]string{string(tailcfg.PeerCapabilityKubernetes): {`{"recorderAddrs":["[fd7a:115c:a1e0:ab12:4843:cd96:626b:628b]:80","100.99.99.99:80"]}`}}),
			wantRecorderAddresses: []netip.AddrPort{addr1, addr2},
			wantFailOpen:          true,
		},
		{
			name:                  "odd_rule_combination_fail_closed",
			who:                   whoResp(map[string][]string{string(tailcfg.PeerCapabilityKubernetes): {`{"recorderAddrs":["100.99.99.99:80"],"enforceRecorder":false}`, `{"recorderAddrs":["[fd7a:115c:a1e0:ab12:4843:cd96:626b:628b]:80"]}`, `{"enforceRecorder":true,"impersonate":{"groups":["system:masters"]}}`}}),
			wantRecorderAddresses: []netip.AddrPort{addr2, addr1},
		},
		{
			name:         "no_caps",
			who:          whoResp(map[string][]string{}),
			wantFailOpen: true,
		},
		{
			name:         "no_recorder_caps",
			who:          whoResp(map[string][]string{"foo": {`{"x":"y"}`}, string(tailcfg.PeerCapabilityKubernetes): {`{"impersonate":{"groups":["system:masters"]}}`}}),
			wantFailOpen: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotFailOpen, gotRecorderAddresses, err := determineRecorderConfig(tt.who)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if gotFailOpen != tt.wantFailOpen {
				t.Errorf("determineRecorderConfig() gotFailOpen = %v, want %v", gotFailOpen, tt.wantFailOpen)
			}
			if !reflect.DeepEqual(gotRecorderAddresses, tt.wantRecorderAddresses) {
				t.Errorf("determineRecorderConfig() gotRecorderAddresses = %v, want %v", gotRecorderAddresses, tt.wantRecorderAddresses)
			}
		})
	}
}

func whoResp(capMap map[string][]string) *apitype.WhoIsResponse {
	resp := &apitype.WhoIsResponse{
		CapMap: tailcfg.PeerCapMap{},
	}
	for cap, rules := range capMap {
		resp.CapMap[tailcfg.PeerCapability(cap)] = raw(rules...)
	}
	return resp
}

func raw(in ...string) []tailcfg.RawMessage {
	var out []tailcfg.RawMessage
	for _, i := range in {
		out = append(out, tailcfg.RawMessage(i))
	}
	return out
}
