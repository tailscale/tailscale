// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

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

func BenchmarkMonoNow(b *testing.B) {
	for i := 0; i < b.N; i++ {
		Now()
	}
}

func BenchmarkTimeNow(b *testing.B) {
	for i := 0; i < b.N; i++ {
		time.Now()
	}
}
