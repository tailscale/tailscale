// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package portlist

import (
	"bufio"
	"bytes"
	"io"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestFieldIndex(t *testing.T) {
	tests := []struct {
		in    string
		field int
		want  int
	}{
		{"foo", 0, 0},
		{"  foo", 0, 2},
		{"foo  bar", 1, 5},
		{" foo  bar", 1, 6},
		{" foo  bar", 2, -1},
		{" foo  bar ", 2, -1},
		{" foo  bar x", 2, 10},
		{"  1: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 34062 1 0000000000000000 100 0 0 10 0",
			2, 19},
	}
	for _, tt := range tests {
		if got := fieldIndex([]byte(tt.in), tt.field); got != tt.want {
			t.Errorf("fieldIndex(%q, %v) = %v; want %v", tt.in, tt.field, got, tt.want)
		}
	}
}

func TestParsePorts(t *testing.T) {
	tests := []struct {
		name string
		in   string
		file string
		want []Port
	}{
		{
			name: "empty",
			in:   "header line (ignored)\n",
			want: nil,
		},
		{
			name: "ipv4",
			file: "tcp",
			in: `header line
  0: 0100007F:0277 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 22303 1 0000000000000000 100 0 0 10 0
  1: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 34062 1 0000000000000000 100 0 0 10 0
  2: 5501A8C0:ADD4 B25E9536:01BB 01 00000000:00000000 02:00000B2B 00000000  1000        0 155276677 2 0000000000000000 22 4 30 10 -1
`,
			want: []Port{
				{Proto: "tcp", Port: 22, inode: "socket:[34062]"},
			},
		},
		{
			name: "ipv6",
			file: "tcp6",
			in: `  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000000000000000000001000000:0277 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 35720 1 0000000000000000 100 0 0 10 0
   1: 00000000000000000000000000000000:1F91 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 142240557 1 0000000000000000 100 0 0 10 0
   2: 00000000000000000000000000000000:0016 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 34064 1 0000000000000000 100 0 0 10 0
   3: 69050120005716BC64906EBE009ECD4D:D506 0047062600000000000000006E171268:01BB 01 00000000:00000000 02:0000009E 00000000  1000        0 151042856 2 0000000000000000 21 4 28 10 -1
`,
			want: []Port{
				{Proto: "tcp", Port: 8081, inode: "socket:[142240557]"},
				{Proto: "tcp", Port: 22, inode: "socket:[34064]"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buf := bytes.NewBufferString(tt.in)
			r := bufio.NewReader(buf)
			file := "tcp"
			if tt.file != "" {
				file = tt.file
			}
			got, err := parsePorts(r, file)
			if err != nil {
				t.Fatal(err)
			}

			if diff := cmp.Diff(got, tt.want, cmp.AllowUnexported(Port{})); diff != "" {
				t.Errorf("unexpected parsed ports (-got+want):\n%s", diff)
			}
		})
	}
}

func BenchmarkParsePorts(b *testing.B) {
	b.ReportAllocs()

	var contents bytes.Buffer
	contents.WriteString(`  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000000000000000000001000000:0277 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 35720 1 0000000000000000 100 0 0 10 0
   1: 00000000000000000000000000000000:1F91 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 142240557 1 0000000000000000 100 0 0 10 0
   2: 00000000000000000000000000000000:0016 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 34064 1 0000000000000000 100 0 0 10 0
`)
	for i := 0; i < 50000; i++ {
		contents.WriteString("   3: 69050120005716BC64906EBE009ECD4D:D506 0047062600000000000000006E171268:01BB 01 00000000:00000000 02:0000009E 00000000  1000        0 151042856 2 0000000000000000 21 4 28 10 -1\n")
	}

	want := []Port{
		{Proto: "tcp", Port: 8081, inode: "socket:[142240557]"},
		{Proto: "tcp", Port: 22, inode: "socket:[34064]"},
	}

	r := bytes.NewReader(contents.Bytes())
	br := bufio.NewReader(&contents)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		r.Seek(0, io.SeekStart)
		br.Reset(r)
		got, err := parsePorts(br, "tcp6")
		if err != nil {
			b.Fatal(err)
		}
		if len(got) != 2 || got[0].Port != 8081 || got[1].Port != 22 {
			b.Fatalf("wrong result:\n got %+v\nwant %+v", got, want)
		}
	}
}

func BenchmarkListPorts(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, err := listPorts()
		if err != nil {
			b.Fatal(err)
		}
	}
}
