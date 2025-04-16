// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package tstest

import (
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestPrintGoroutines(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{
			name: "empty",
			in:   "goroutine profile: total 0\n",
			want: "goroutine profile: total 0",
		},
		{
			name: "single goroutine",
			in: `goroutine profile: total 1
1 @ 0x47bc0e 0x458e57 0x847587 0x483da1
#   0x847586    database/sql.(*DB).connectionOpener+0x86    database/sql/sql.go:1261
`,
			want: `goroutine profile: total 1

1 @ 0x47bc0e 0x458e57 0x847587 0x483da1
#   0x847586    database/sql.(*DB).connectionOpener+0x86    database/sql/sql.go:1261
`,
		},
		{
			name: "multiple goroutines sorted",
			in: `goroutine profile: total 14
7 @ 0x47bc0e 0x413705 0x4132b2 0x10fda4d 0x483da1
#   0x10fda4c   github.com/user/pkg.RoutineA+0x16c    pkg/a.go:443

7 @ 0x47bc0e 0x458e57 0x754927 0x483da1
#   0x754926    net/http.(*persistConn).writeLoop+0xe6  net/http/transport.go:2596
`,
			want: `goroutine profile: total 14

7 @ 0x47bc0e 0x413705 0x4132b2 0x10fda4d 0x483da1
#   0x10fda4c   github.com/user/pkg.RoutineA+0x16c    pkg/a.go:443

7 @ 0x47bc0e 0x458e57 0x754927 0x483da1
#   0x754926    net/http.(*persistConn).writeLoop+0xe6  net/http/transport.go:2596
`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := string(printGoroutines(parseGoroutines([]byte(tt.in))))
			if got != tt.want {
				t.Errorf("printGoroutines() = %q, want %q, diff:\n%s", got, tt.want, cmp.Diff(tt.want, got))
			}
		})
	}
}

func TestDiffPprofGoroutines(t *testing.T) {
	tests := []struct {
		name string
		x, y string
		want string
	}{
		{
			name: "no difference",
			x: `goroutine profile: total 1
1 @ 0x47bc0e 0x458e57 0x847587 0x483da1
#   0x847586    database/sql.(*DB).connectionOpener+0x86    database/sql/sql.go:1261`,
			y: `goroutine profile: total 1
1 @ 0x47bc0e 0x458e57 0x847587 0x483da1
#   0x847586    database/sql.(*DB).connectionOpener+0x86    database/sql/sql.go:1261
`,
			want: "",
		},
		{
			name: "different counts",
			x: `goroutine profile: total 1
1 @ 0x47bc0e 0x458e57 0x847587 0x483da1
#   0x847586    database/sql.(*DB).connectionOpener+0x86    database/sql/sql.go:1261
`,
			y: `goroutine profile: total 2
2 @ 0x47bc0e 0x458e57 0x847587 0x483da1
#   0x847586    database/sql.(*DB).connectionOpener+0x86    database/sql/sql.go:1261
`,
			want: `- goroutine profile: total 1
+ goroutine profile: total 2

- 1 @ 0x47bc0e 0x458e57 0x847587 0x483da1
+ 2 @ 0x47bc0e 0x458e57 0x847587 0x483da1
  #   0x847586    database/sql.(*DB).connectionOpener+0x86    database/sql/sql.go:1261
`,
		},
		{
			name: "new goroutine",
			x: `goroutine profile: total 1
1 @ 0x47bc0e 0x458e57 0x847587 0x483da1
#   0x847586    database/sql.(*DB).connectionOpener+0x86    database/sql/sql.go:1261
`,
			y: `goroutine profile: total 2
1 @ 0x47bc0e 0x458e57 0x847587 0x483da1
#   0x847586    database/sql.(*DB).connectionOpener+0x86    database/sql/sql.go:1261

1 @ 0x47bc0e 0x458e57 0x754927 0x483da1
#   0x754926    net/http.(*persistConn).writeLoop+0xe6  net/http/transport.go:2596
`,
			want: `- goroutine profile: total 1
+ goroutine profile: total 2

+ 1 @ 0x47bc0e 0x458e57 0x754927 0x483da1
+ #   0x754926    net/http.(*persistConn).writeLoop+0xe6  net/http/transport.go:2596
`,
		},
		{
			name: "removed goroutine",
			x: `goroutine profile: total 2
1 @ 0x47bc0e 0x458e57 0x847587 0x483da1
#   0x847586    database/sql.(*DB).connectionOpener+0x86    database/sql/sql.go:1261

1 @ 0x47bc0e 0x458e57 0x754927 0x483da1
#   0x754926    net/http.(*persistConn).writeLoop+0xe6  net/http/transport.go:2596
`,
			y: `goroutine profile: total 1
1 @ 0x47bc0e 0x458e57 0x847587 0x483da1
#   0x847586    database/sql.(*DB).connectionOpener+0x86    database/sql/sql.go:1261
`,
			want: `- goroutine profile: total 2
+ goroutine profile: total 1

- 1 @ 0x47bc0e 0x458e57 0x754927 0x483da1
- #   0x754926    net/http.(*persistConn).writeLoop+0xe6  net/http/transport.go:2596
`,
		},
		{
			name: "removed many goroutine",
			x: `goroutine profile: total 2
1 @ 0x47bc0e 0x458e57 0x847587 0x483da1
#   0x847586    database/sql.(*DB).connectionOpener+0x86    database/sql/sql.go:1261

1 @ 0x47bc0e 0x458e57 0x754927 0x483da1
#   0x754926    net/http.(*persistConn).writeLoop+0xe6  net/http/transport.go:2596
`,
			y: `goroutine profile: total 0`,
			want: `- goroutine profile: total 2
+ goroutine profile: total 0

- 1 @ 0x47bc0e 0x458e57 0x754927 0x483da1
- #   0x754926    net/http.(*persistConn).writeLoop+0xe6  net/http/transport.go:2596

- 1 @ 0x47bc0e 0x458e57 0x847587 0x483da1
- #   0x847586    database/sql.(*DB).connectionOpener+0x86    database/sql/sql.go:1261
`,
		},
		{
			name: "invalid input x",
			x:    "invalid",
			y:    "goroutine profile: total 0\n",
			want: "- invalid\n+ goroutine profile: total 0\n",
		},
		{
			name: "invalid input y",
			x:    "goroutine profile: total 0\n",
			y:    "invalid",
			want: "- goroutine profile: total 0\n+ invalid\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := diffGoroutines(
				parseGoroutines([]byte(tt.x)),
				parseGoroutines([]byte(tt.y)),
			)
			if got != tt.want {
				t.Errorf("diffPprofGoroutines() diff:\ngot:\n%s\nwant:\n%s\ndiff (-want +got):\n%s", got, tt.want, cmp.Diff(tt.want, got))
			}
		})
	}
}

func TestParseGoroutines(t *testing.T) {
	tests := []struct {
		name       string
		in         string
		wantHeader string
		wantCount  int
	}{
		{
			name:       "empty profile",
			in:         "goroutine profile: total 0\n",
			wantHeader: "goroutine profile: total 0",
			wantCount:  0,
		},
		{
			name: "single goroutine",
			in: `goroutine profile: total 1
1 @ 0x47bc0e 0x458e57 0x847587 0x483da1
#   0x847586    database/sql.(*DB).connectionOpener+0x86    database/sql/sql.go:1261
`,
			wantHeader: "goroutine profile: total 1",
			wantCount:  1,
		},
		{
			name: "multiple goroutines",
			in: `goroutine profile: total 14
7 @ 0x47bc0e 0x413705 0x4132b2 0x10fda4d 0x483da1
#   0x10fda4c   github.com/user/pkg.RoutineA+0x16c    pkg/a.go:443

7 @ 0x47bc0e 0x458e57 0x754927 0x483da1
#   0x754926    net/http.(*persistConn).writeLoop+0xe6  net/http/transport.go:2596
`,
			wantHeader: "goroutine profile: total 14",
			wantCount:  2,
		},
		{
			name:       "invalid format",
			in:         "invalid",
			wantHeader: "invalid",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := parseGoroutines([]byte(tt.in))

			if got := string(g.head); got != tt.wantHeader {
				t.Errorf("parseGoroutines() header = %q, want %q", got, tt.wantHeader)
			}
			if got := len(g.goroutines); got != tt.wantCount {
				t.Errorf("parseGoroutines() goroutine count = %d, want %d", got, tt.wantCount)
			}

			// Verify that the sort field is correctly reversed
			for _, g := range g.goroutines {
				original := strings.Fields(string(g.header))
				sorted := strings.Fields(string(g.sort))
				if len(original) != len(sorted) {
					t.Errorf("sort field has different number of words: got %d, want %d", len(sorted), len(original))
					continue
				}
				for i := 0; i < len(original); i++ {
					if original[i] != sorted[len(sorted)-1-i] {
						t.Errorf("sort field word mismatch at position %d: got %q, want %q", i, sorted[len(sorted)-1-i], original[i])
					}
				}
			}
		})
	}
}
