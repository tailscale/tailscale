// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package block

import (
	"testing"
)

func TestWatch(t *testing.T) {
	Watch(3, t.Logf)
}

func TestGoroutineMinutesBlocked(t *testing.T) {
	tests := []struct {
		stack   string
		wantMin int
		wantOK  bool
	}{
		{stack: "some junk"},
		{stack: "goroutine 0 [idle]:\nstack traces..."},
		{stack: "goroutine 1 [chan receive, 9 minutes]:\nstack traces...", wantMin: 9, wantOK: true},
	}

	for _, tt := range tests {
		gotMin, gotOK := goroutineMinutesBlocked([]byte(tt.stack))
		if tt.wantMin != gotMin || tt.wantOK != gotOK {
			t.Errorf("goroutineMinutesBlocked(%q) = (%v, %v) want (%v, %v)", tt.stack, gotMin, gotOK, tt.wantMin, tt.wantOK)
		}
	}
}
