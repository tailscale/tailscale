// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package portlist

import "testing"

func TestArgvSubject(t *testing.T) {
	tests := []struct {
		in   []string
		want string
	}{
		{
			in:   nil,
			want: "",
		},
		{
			in:   []string{"/usr/bin/sshd"},
			want: "sshd",
		},
		{
			in:   []string{"/bin/mono"},
			want: "mono",
		},
		{
			in:   []string{"/nix/store/x2cw2xjw98zdysf56bdlfzsr7cyxv0jf-mono-5.20.1.27/bin/mono", "/bin/exampleProgram.exe"},
			want: "exampleProgram",
		},
		{
			in:   []string{"/bin/mono", "/sbin/exampleProgram.bin"},
			want: "exampleProgram.bin",
		},
	}

	for _, test := range tests {
		got := argvSubject(test.in...)
		if got != test.want {
			t.Errorf("argvSubject(%v) = %q, want %q", test.in, got, test.want)
		}
	}
}
