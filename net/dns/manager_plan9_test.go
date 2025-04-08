// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build plan9

package dns

import "testing"

func TestNetNDBBytesWithoutTailscale(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want string
	}{
		{
			name: "empty",
			raw:  "",
			want: "",
		},
		{
			name: "no-tailscale",
			raw:  "# This is a comment\nip=10.0.2.15 ipmask=255.255.255.0 ipgw=10.0.2.2\n\tsys=gnot\n",
			want: "# This is a comment\nip=10.0.2.15 ipmask=255.255.255.0 ipgw=10.0.2.2\n\tsys=gnot\n",
		},
		{
			name: "remove-by-comments",
			raw:  "# This is a comment\n#tailscaled-added-line: dns=100.100.100.100\nip=10.0.2.15 ipmask=255.255.255.0 ipgw=10.0.2.2\n\tdns=100.100.100.100\n\tsys=gnot\n",
			want: "# This is a comment\nip=10.0.2.15 ipmask=255.255.255.0 ipgw=10.0.2.2\n\tsys=gnot\n",
		},
		{
			name: "remove-by-ts.net",
			raw:  "Some line\n\tdns=100.100.100.100 suffix=foo.ts.net\n\tfoo=bar\n",
			want: "Some line\n\tfoo=bar\n",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := netNDBBytesWithoutTailscale([]byte(tt.raw))
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != tt.want {
				t.Errorf("GOT:\n%s\n\nWANT:\n%s\n", string(got), tt.want)
			}
		})
	}
}

func TestSetNDBSuffix(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want string
	}{
		{
			name: "empty",
			raw:  "",
			want: "",
		},
		{
			name: "set",
			raw:  "ip=10.0.2.15 ipmask=255.255.255.0 ipgw=10.0.2.2\n\tsys=gnot\n\tdns=100.100.100.100\n\n# foo\n",
			want: `#tailscaled-added-line: dns=100.100.100.100 suffix=foo.ts.net
#tailscaled-added-line: dnsdomain=foo.ts.net

ip=10.0.2.15 ipmask=255.255.255.0 ipgw=10.0.2.2
	sys=gnot
	dns=100.100.100.100
	dns=100.100.100.100 suffix=foo.ts.net
	dnsdomain=foo.ts.net

# foo
`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := setNDBSuffix([]byte(tt.raw), "foo.ts.net")
			if string(got) != tt.want {
				t.Errorf("wrong value\n GOT %q:\n%s\n\nWANT %q:\n%s\n", got, got, tt.want, tt.want)
			}
		})
	}

}
