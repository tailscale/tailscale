// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package endpoint

import (
	"encoding/json"
	"math"
	"net/netip"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"tailscale.com/tstime"
	"tailscale.com/types/key"
)

func TestServerEndpointJSONUnmarshal(t *testing.T) {
	tests := []struct {
		name    string
		json    []byte
		wantErr bool
	}{
		{
			name:    "valid",
			json:    []byte(`{"ServerDisco":"discokey:003cd7453e04a653eb0e7a18f206fc353180efadb2facfd05ebd6982a1392c7f","LamportID":18446744073709551615,"AddrPorts":["127.0.0.1:1","127.0.0.2:2"],"VNI":16777215,"BindLifetime":"30s","SteadyStateLifetime":"5m0s"}`),
			wantErr: false,
		},
		{
			name:    "invalid ServerDisco",
			json:    []byte(`{"ServerDisco":"1","LamportID":18446744073709551615,"AddrPorts":["127.0.0.1:1","127.0.0.2:2"],"VNI":16777215,"BindLifetime":"30s","SteadyStateLifetime":"5m0s"}`),
			wantErr: true,
		},
		{
			name:    "invalid LamportID",
			json:    []byte(`{"ServerDisco":"discokey:003cd7453e04a653eb0e7a18f206fc353180efadb2facfd05ebd6982a1392c7f","LamportID":1.1,"AddrPorts":["127.0.0.1:1","127.0.0.2:2"],"VNI":16777215,"BindLifetime":"30s","SteadyStateLifetime":"5m0s"}`),
			wantErr: true,
		},
		{
			name:    "invalid AddrPorts",
			json:    []byte(`{"ServerDisco":"discokey:003cd7453e04a653eb0e7a18f206fc353180efadb2facfd05ebd6982a1392c7f","LamportID":18446744073709551615,"AddrPorts":["127.0.0.1.1:1","127.0.0.2:2"],"VNI":16777215,"BindLifetime":"30s","SteadyStateLifetime":"5m0s"}`),
			wantErr: true,
		},
		{
			name:    "invalid VNI",
			json:    []byte(`{"ServerDisco":"discokey:003cd7453e04a653eb0e7a18f206fc353180efadb2facfd05ebd6982a1392c7f","LamportID":18446744073709551615,"AddrPorts":["127.0.0.1:1","127.0.0.2:2"],"VNI":18446744073709551615,"BindLifetime":"30s","SteadyStateLifetime":"5m0s"}`),
			wantErr: true,
		},
		{
			name:    "invalid BindLifetime",
			json:    []byte(`{"ServerDisco":"discokey:003cd7453e04a653eb0e7a18f206fc353180efadb2facfd05ebd6982a1392c7f","LamportID":18446744073709551615,"AddrPorts":["127.0.0.1:1","127.0.0.2:2"],"VNI":16777215,"BindLifetime":"5","SteadyStateLifetime":"5m0s"}`),
			wantErr: true,
		},
		{
			name:    "invalid SteadyStateLifetime",
			json:    []byte(`{"ServerDisco":"discokey:003cd7453e04a653eb0e7a18f206fc353180efadb2facfd05ebd6982a1392c7f","LamportID":18446744073709551615,"AddrPorts":["127.0.0.1:1","127.0.0.2:2"],"VNI":16777215,"BindLifetime":"30s","SteadyStateLifetime":"5"}`),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var out ServerEndpoint
			err := json.Unmarshal(tt.json, &out)
			if tt.wantErr != (err != nil) {
				t.Fatalf("wantErr: %v (err == nil): %v", tt.wantErr, err == nil)
			}
			if tt.wantErr {
				return
			}
		})
	}
}

func TestServerEndpointJSONMarshal(t *testing.T) {
	tests := []struct {
		name           string
		serverEndpoint ServerEndpoint
	}{
		{
			name: "valid roundtrip",
			serverEndpoint: ServerEndpoint{
				ServerDisco:         key.NewDisco().Public(),
				LamportID:           uint64(math.MaxUint64),
				AddrPorts:           []netip.AddrPort{netip.MustParseAddrPort("127.0.0.1:1"), netip.MustParseAddrPort("127.0.0.2:2")},
				VNI:                 1<<24 - 1,
				BindLifetime:        tstime.GoDuration{Duration: time.Second * 30},
				SteadyStateLifetime: tstime.GoDuration{Duration: time.Minute * 5},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b, err := json.Marshal(&tt.serverEndpoint)
			if err != nil {
				t.Fatal(err)
			}
			var got ServerEndpoint
			err = json.Unmarshal(b, &got)
			if err != nil {
				t.Fatal(err)
			}
			if diff := cmp.Diff(got, tt.serverEndpoint, cmpopts.EquateComparable(netip.AddrPort{}, key.DiscoPublic{})); diff != "" {
				t.Fatalf("ServerEndpoint unequal (-got +want)\n%s", diff)
			}
		})
	}
}
