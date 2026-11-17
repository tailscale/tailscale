// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package osuser

import (
	"context"
	"slices"
	"testing"
)

func TestParseGroupIds(t *testing.T) {
	tests := []struct {
		in       string
		expected []string
	}{
		{"5000\x005001\n", []string{"5000", "5001"}},
		{"5000\n", []string{"5000"}},
		{"\n", []string{}},
		{"5000 5001 5002\n", []string{"5000", "5001", "5002"}},
		{"5000\t5001\n", []string{"5000", "5001"}},
	}
	for _, test := range tests {
		actual := parseGroupIds([]byte(test.in))
		if !slices.Equal(actual, test.expected) {
			t.Errorf("parseGroupIds(%q) = %q, wanted %s", test.in, actual, test.expected)
		}
	}
}

func TestGetGroupIdsWithIdValidatesInput(t *testing.T) {
	origExecId := execId
	t.Cleanup(func() {
		execId = origExecId
	})

	tests := []struct {
		name        string
		username    string
		wantExec    bool
		wantExecArg string // the username argument passed to "id"
		wantErr     bool
	}{
		{
			name:        "valid-username",
			username:    "alice",
			wantExec:    true,
			wantExecArg: "alice",
		},
		{
			name:     "leading-dash",
			username: "-u",
			wantErr:  true,
		},
		{
			name:     "empty",
			username: "",
			wantErr:  true,
		},
		{
			name:     "control-character",
			username: "ali\x00ce",
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			execId = func(_ context.Context, args ...string) ([]byte, error) {
				if !tt.wantExec {
					t.Fatalf("exec 'id' called with %q; want it not to be called", args)
				}
				wantArg := tt.wantExecArg
				gotFlag := args[0]
				if gotFlag != "-Gz" && gotFlag != "-G" {
					t.Errorf("unexpected 'id' flag %q", gotFlag)
				}
				if got := args[len(args)-1]; got != wantArg {
					t.Errorf("id called with %q; want username %q", got, wantArg)
				}
				return []byte("1000\x001001\x00"), nil
			}
			ids, err := getGroupIdsWithId(tt.username)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("getGroupIdsWithId(%q) = %v; want error", tt.username, ids)
				}
				return
			}
			if err != nil {
				t.Fatalf("getGroupIdsWithId(%q) error: %v", tt.username, err)
			}
			if !slices.Equal(ids, []string{"1000", "1001"}) {
				t.Errorf("ids = %v; want [1000 1001]", ids)
			}
		})
	}
}
