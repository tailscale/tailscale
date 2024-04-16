// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package mono

import (
	"encoding/json"
	"testing"
	"time"
)

func TestNow(t *testing.T) {
	start := Now()
	time.Sleep(100 * time.Millisecond)
	if elapsed := Since(start); elapsed < 100*time.Millisecond {
		t.Errorf("short sleep: %v elapsed, want min %v", elapsed, 100*time.Millisecond)
	}
}

func TestUnmarshalZero(t *testing.T) {
	var tt time.Time
	buf, err := json.Marshal(tt)
	if err != nil {
		t.Fatal(err)
	}
	var m Time
	err = json.Unmarshal(buf, &m)
	if err != nil {
		t.Fatal(err)
	}
	if !m.IsZero() {
		t.Errorf("expected unmarshal of zero time to be 0, got %d (~=%v)", m, m)
	}
}

func TestJSONRoundtrip(t *testing.T) {
	want := Now()
	b, err := want.MarshalJSON()
	if err != nil {
		t.Errorf("MarshalJSON error: %v", err)
	}
	var got Time
	if err := got.UnmarshalJSON(b); err != nil {
		t.Errorf("UnmarshalJSON error: %v", err)
	}
	if got != want {
		t.Errorf("got %v, want %v", got, want)
	}
}

func BenchmarkMonoNow(b *testing.B) {
	b.ReportAllocs()
	for range b.N {
		Now()
	}
}

func BenchmarkTimeNow(b *testing.B) {
	b.ReportAllocs()
	for range b.N {
		time.Now()
	}
}
