// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package kubetypes

import (
	"encoding/json"
	"testing"
)

func TestUnmarshalAPIServerProxyMode(t *testing.T) {
	tests := []struct {
		data     string
		expected APIServerProxyMode
	}{
		{data: `{"mode":"auth"}`, expected: APIServerProxyModeAuth},
		{data: `{"mode":"noauth"}`, expected: APIServerProxyModeNoAuth},
		{data: `{"mode":""}`, expected: ""},
		{data: `{"mode":"Auth"}`, expected: ""},
		{data: `{"mode":"unknown"}`, expected: ""},
	}

	for _, tc := range tests {
		var s struct {
			Mode *APIServerProxyMode `json:",omitempty"`
		}
		err := json.Unmarshal([]byte(tc.data), &s)
		if tc.expected == "" {
			if err == nil {
				t.Errorf("expected error for %q, got none", tc.data)
			}
			continue
		}
		if err != nil {
			t.Errorf("unexpected error for %q: %v", tc.data, err)
			continue
		}
		if *s.Mode != tc.expected {
			t.Errorf("for %q expected %q, got %q", tc.data, tc.expected, *s.Mode)
		}
	}
}
