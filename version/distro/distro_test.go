// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package distro

import (
	"os"
	"path/filepath"
	"testing"
)

func BenchmarkGet(b *testing.B) {
	b.ReportAllocs()
	var d Distro
	for i := 0; i < b.N; i++ {
		d = Get()
	}
	_ = d
}

func TestParseLinuxOSRelease(t *testing.T) {
	tests := []struct {
		desc      string
		osRelease string
		want      Distro
	}{
		{
			desc: "regular",
			osRelease: `
NAME=Debian
ID=debian
`,
			want: Debian,
		},
		{
			desc: "id like",
			osRelease: `
NAME=Ubuntu
ID=ubuntu
ID_LIKE=debian
`,
			want: Debian,
		},
		{
			desc: "id like multiple",
			osRelease: `
NAME=AmazonLinux
ID=amzn
ID_LIKE="centos rhel fedora"
`,
			want: Fedora,
		},
		{
			desc: "id like empty",
			osRelease: `
NAME=Debian
ID=debian
ID_LIKE=
`,
			want: Debian,
		},
		{
			desc: "single quoted",
			osRelease: `
NAME=Debian
ID='debian'
`,
			want: Debian,
		},
		{
			desc: "double quoted",
			osRelease: `
NAME=Debian
ID="debian"
`,
			want: Debian,
		},
		{
			desc: "missing ID",
			osRelease: `
NAME=Debian
`,
			want: Unknown,
		},
		{
			desc:      "empty file",
			osRelease: "",
			want:      Unknown,
		},
		{
			desc: "all fields empty",
			osRelease: `
NAME=
ID=
`,
			want: Unknown,
		},
		{
			desc: "missing opening quotes",
			osRelease: `
NAME=Debian
ID=debian'
`,
			want: Debian,
		},
		{
			desc: "missing closing quotes",
			osRelease: `
NAME=Debian
ID='debian
`,
			want: Debian,
		},
		{
			desc: "invalid ID",
			osRelease: `
NAME=Ubuntu
ID=ubuntu
`,
			want: Unknown,
		},
		{
			desc: "invalid ID_LIKE",
			osRelease: `
NAME=LinuxMint
ID=linuxmint
ID_LIKE=ubuntu
`,
			want: Unknown,
		},
	}
	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "os-release")
			if err := os.WriteFile(path, []byte(tt.osRelease), 0600); err != nil {
				t.Fatal(err)
			}
			got, err := parseLinuxOSRelease(path)
			if err != nil {
				t.Fatal(err)
			}
			if got != tt.want {
				t.Errorf("got: %q, want: %q", got, tt.want)
			}
		})
	}
}
