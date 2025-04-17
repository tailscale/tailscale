// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package tstime

import (
	"encoding/json"
	"testing"
	"time"

	"tailscale.com/util/must"
)

func TestParseDuration(t *testing.T) {
	tests := []struct {
		in   string
		want time.Duration
	}{
		{"1h", time.Hour},
		{"1d", 24 * time.Hour},
		{"365d", 365 * 24 * time.Hour},
		{"12345d", 12345 * 24 * time.Hour},
		{"67890d", 67890 * 24 * time.Hour},
		{"100d", 100 * 24 * time.Hour},
		{"1d1d", 48 * time.Hour},
		{"1h1d", 25 * time.Hour},
		{"1d1h", 25 * time.Hour},
		{"1w", 7 * 24 * time.Hour},
		{"1w1d1h", 8*24*time.Hour + time.Hour},
		{"1w1d1h", 8*24*time.Hour + time.Hour},
		{"1y", 0},
		{"", 0},
	}
	for _, tt := range tests {
		if got, _ := ParseDuration(tt.in); got != tt.want {
			t.Errorf("ParseDuration(%q) = %d; want %d", tt.in, got, tt.want)
		}
	}
}

func TestGoDuration(t *testing.T) {
	wantDur := GoDuration{time.Hour + time.Minute + time.Second + time.Millisecond + time.Microsecond + time.Nanosecond}
	gotJSON := string(must.Get(json.Marshal(wantDur)))
	wantJSON := `"1h1m1.001001001s"`
	if gotJSON != wantJSON {
		t.Errorf("json.Marshal(%v) = %s, want %s", wantDur, gotJSON, wantJSON)
	}
	var gotDur GoDuration
	must.Do(json.Unmarshal([]byte(wantJSON), &gotDur))
	if gotDur != wantDur {
		t.Errorf("json.Unmarshal(%s) = %v, want %v", wantJSON, gotDur, wantDur)
	}
}
