// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package cli

import (
	"context"
	"strings"
	"testing"

	"tailscale.com/cmd/tailscale/tsdnsjsonv0"
)

func TestFormatDNSQueryResolvers(t *testing.T) {
	for _, tt := range []struct {
		name      string
		resolvers []tsdnsjsonv0.ResolverInfo
		want      string
	}{
		{name: "local", want: "No upstream resolvers used.\n"},
		{
			name:      "single",
			resolvers: []tsdnsjsonv0.ResolverInfo{{Addr: "192.0.2.53"}},
			want:      "Forwarding to resolver: 192.0.2.53\n",
		},
		{
			name:      "multiple",
			resolvers: []tsdnsjsonv0.ResolverInfo{{Addr: "192.0.2.53"}, {Addr: "192.0.2.54"}},
			want:      "Multiple resolvers available:\n  - 192.0.2.53\n  - 192.0.2.54\n",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got := formatDNSQueryText(&tsdnsjsonv0.QueryResponse{
				Name:         "node.tailnet.ts.net",
				QueryType:    "A",
				Resolvers:    tt.resolvers,
				ResponseCode: "RCodeSuccess",
			})
			if !strings.Contains(got, tt.want) {
				t.Errorf("output = %q, want it to contain %q", got, tt.want)
			}
		})
	}
}

func TestRunDNSQueryArgs(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		wantErr string
	}{
		{
			name:    "no_args",
			args:    []string{},
			wantErr: "missing required argument: name",
		},
		{
			name:    "flag_after_name",
			args:    []string{"example.com", "--json"},
			wantErr: "unexpected flags after query name: --json",
		},
		{
			name:    "flag_after_name_and_type",
			args:    []string{"example.com", "AAAA", "--json"},
			wantErr: "unexpected flags after query name: --json",
		},
		{
			name:    "extra_args_after_type",
			args:    []string{"example.com", "AAAA", "extra"},
			wantErr: "unexpected extra arguments: extra",
		},
		{
			name:    "multiple_extra_args",
			args:    []string{"example.com", "AAAA", "extra1", "extra2"},
			wantErr: "unexpected extra arguments: extra1 extra2",
		},
		{
			name:    "non_flag_then_flag",
			args:    []string{"example.com", "AAAA", "foo", "--json"},
			wantErr: "unexpected flags after query name: --json",
		},
		{
			name:    "multiple_misplaced_flags",
			args:    []string{"example.com", "--json", "--verbose"},
			wantErr: "unexpected flags after query name: --json, --verbose",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := runDNSQuery(context.Background(), tt.args)
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("error = %q, want it to contain %q", err.Error(), tt.wantErr)
			}
		})
	}
}
