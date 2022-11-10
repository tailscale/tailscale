// Copyright (c) 2022 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ipnlocal

import "testing"

func TestExpandProxyArg(t *testing.T) {
	type res struct {
		target   string
		insecure bool
	}
	tests := []struct {
		in   string
		want res
	}{
		{"", res{}},
		{"3030", res{"http://127.0.0.1:3030", false}},
		{"localhost:3030", res{"http://localhost:3030", false}},
		{"10.2.3.5:3030", res{"http://10.2.3.5:3030", false}},
		{"http://foo.com", res{"http://foo.com", false}},
		{"https://foo.com", res{"https://foo.com", false}},
		{"https+insecure://10.2.3.4", res{"https://10.2.3.4", true}},
	}
	for _, tt := range tests {
		target, insecure := expandProxyArg(tt.in)
		got := res{target, insecure}
		if got != tt.want {
			t.Errorf("expandProxyArg(%q) = %v, want %v", tt.in, got, tt.want)
		}
	}
}
