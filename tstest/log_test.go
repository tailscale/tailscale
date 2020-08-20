// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tstest

import "testing"

func TestLogListener(t *testing.T) {
	var (
		l1 = "line 1: %s"
		l2 = "line 2: %s"
		l3 = "line 3: %s"

		lineList = []string{l1, l2}
	)

	ll := ListenFor(t.Logf, lineList)

	if len(ll.Check()) != len(lineList) {
		t.Errorf("expected %v, got %v", lineList, ll.Check())
	}

	ll.Logf(l3, "hi")

	if len(ll.Check()) != len(lineList) {
		t.Errorf("expected %v, got %v", lineList, ll.Check())
	}

	ll.Logf(l1, "hi")

	if len(ll.Check()) != len(lineList)-1 {
		t.Errorf("expected %v, got %v", lineList, ll.Check())
	}

	ll.Logf(l1, "bye")

	if len(ll.Check()) != len(lineList)-1 {
		t.Errorf("expected %v, got %v", lineList, ll.Check())
	}

	ll.Logf(l2, "hi")
	if ll.Check() != nil {
		t.Errorf("expected empty list, got ll.Check()")
	}
}
