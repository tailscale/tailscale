// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package httphdr

import (
	"math"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func valOk[T any](v T, ok bool) (out struct {
	V  T
	Ok bool
}) {
	out.V = v
	out.Ok = ok
	return out
}

func TestRange(t *testing.T) {
	tests := []struct {
		in        string
		want      []Range
		wantOk    bool
		roundtrip bool
	}{
		{"", nil, false, false},
		{"1-3", nil, false, false},
		{"units=1-3", []Range{{1, 3}}, false, false},
		{"bytes=1-3", []Range{{1, 3}}, true, true},
		{"bytes=#-3", nil, false, false},
		{"bytes=#-", nil, false, false},
		{"bytes=13", nil, false, false},
		{"bytes=1-#", nil, false, false},
		{"bytes=-#", nil, false, false},
		{"bytes= , , , ,\t  , \t  1-3", []Range{{1, 3}}, true, false},
		{"bytes=1-1", []Range{{1, 1}}, true, true},
		{"bytes=01-01", []Range{{1, 1}}, true, false},
		{"bytes=1-0", nil, false, false},
		{"bytes=0-5,2-3", []Range{{0, 6}, {2, 2}}, true, true},
		{"bytes=2-3,0-5", []Range{{2, 2}, {0, 6}}, true, true},
		{"bytes=0-5,2-,-5", []Range{{0, 6}, {2, 0}, {0, -5}}, true, true},
		{"bytes=0-9223372036854775806", []Range{{0, math.MaxInt64}}, true, true},
		{"bytes=1-9223372036854775807", []Range{{1, math.MaxInt64}}, true, true},
		{"bytes=9223372036854775807-9223372036854775807", []Range{{math.MaxInt64, 1}}, true, true},
		{"bytes=0-9223372036854775807", nil, false, false},
	}

	for _, tt := range tests {
		got, gotOk := ParseRange(tt.in)
		if d := cmp.Diff(valOk(got, gotOk), valOk(tt.want, tt.wantOk)); d != "" {
			t.Errorf("ParseRange(%q) mismatch (-got +want):\n%s", tt.in, d)
		}
		if tt.roundtrip {
			got, gotOk := FormatRange(tt.want)
			if d := cmp.Diff(valOk(got, gotOk), valOk(tt.in, tt.wantOk)); d != "" {
				t.Errorf("FormatRange(%v) mismatch (-got +want):\n%s", tt.want, d)
			}
		}
	}
}

type contentRange struct{ Start, Length, CompleteLength int64 }

func TestContentRange(t *testing.T) {
	tests := []struct {
		in        string
		want      contentRange
		wantOk    bool
		roundtrip bool
	}{
		{"", contentRange{}, false, false},
		{"bytes 5-6/*", contentRange{5, 2, -1}, true, true},
		{"units 5-6/*", contentRange{}, false, false},
		{"bytes  5-6/*", contentRange{}, false, false},
		{"bytes 5-5/*", contentRange{5, 1, -1}, true, true},
		{"bytes 5-4/*", contentRange{}, false, false},
		{"bytes 5-5/6", contentRange{5, 1, 6}, true, true},
		{"bytes 05-005/0006", contentRange{5, 1, 6}, true, false},
		{"bytes 5-5/5", contentRange{}, false, false},
		{"bytes #-5/6", contentRange{}, false, false},
		{"bytes 5-#/6", contentRange{}, false, false},
		{"bytes 5-5/#", contentRange{}, false, false},
		{"bytes 0-9223372036854775806/*", contentRange{0, math.MaxInt64, -1}, true, true},
		{"bytes 1-9223372036854775807/*", contentRange{1, math.MaxInt64, -1}, true, true},
		{"bytes 9223372036854775807-9223372036854775807/*", contentRange{math.MaxInt64, 1, -1}, true, true},
		{"bytes 0-9223372036854775806/9223372036854775807", contentRange{0, math.MaxInt64, math.MaxInt64}, true, true},
		{"bytes 0-9223372036854775807/*", contentRange{}, false, false},
	}

	for _, tt := range tests {
		start, length, completeLength, gotOk := ParseContentRange(tt.in)
		got := contentRange{start, length, completeLength}
		if d := cmp.Diff(valOk(got, gotOk), valOk(tt.want, tt.wantOk)); d != "" {
			t.Errorf("ParseContentRange mismatch (-got +want):\n%s", d)
		}
		if tt.roundtrip {
			got, gotOk := FormatContentRange(tt.want.Start, tt.want.Length, tt.want.CompleteLength)
			if d := cmp.Diff(valOk(got, gotOk), valOk(tt.in, tt.wantOk)); d != "" {
				t.Errorf("FormatContentRange mismatch (-got +want):\n%s", d)
			}
		}
	}
}

func TestFormatRangeOverflow(t *testing.T) {
	for _, r := range []Range{
		{math.MaxInt64, 2},
		{2, math.MaxInt64},
		{math.MaxInt64, math.MaxInt64},
	} {
		if got, ok := FormatRange([]Range{r}); ok {
			t.Errorf("FormatRange(%v) = %q, true; want ok=false", r, got)
		}
	}
	if got, ok := FormatRange([]Range{{0, math.MinInt64}}); !ok || got != "bytes=-9223372036854775808" {
		t.Errorf("FormatRange with MinInt64 suffix = %q, %v", got, ok)
	}
}

func TestFormatContentRangeOverflow(t *testing.T) {
	for _, r := range []contentRange{
		{math.MaxInt64, 2, -1},
		{2, math.MaxInt64, -1},
		{math.MaxInt64, math.MaxInt64, -1},
		{math.MaxInt64, 2, math.MaxInt64},
		{2, math.MaxInt64, math.MaxInt64},
	} {
		if got, ok := FormatContentRange(r.Start, r.Length, r.CompleteLength); ok {
			t.Errorf("FormatContentRange(%v) = %q, true; want ok=false", r, got)
		}
	}
}
