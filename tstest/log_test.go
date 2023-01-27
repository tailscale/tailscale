// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package tstest

import (
	"reflect"
	"testing"
)

func TestLogLineTracker(t *testing.T) {
	const (
		l1 = "line 1: %s"
		l2 = "line 2: %s"
		l3 = "line 3: %s"
	)

	lt := NewLogLineTracker(t.Logf, []string{l1, l2})

	if got, want := lt.Check(), []string{l1, l2}; !reflect.DeepEqual(got, want) {
		t.Errorf("Check = %q; want %q", got, want)
	}

	lt.Logf(l3, "hi")

	if got, want := lt.Check(), []string{l1, l2}; !reflect.DeepEqual(got, want) {
		t.Errorf("Check = %q; want %q", got, want)
	}

	lt.Logf(l1, "hi")

	if got, want := lt.Check(), []string{l2}; !reflect.DeepEqual(got, want) {
		t.Errorf("Check = %q; want %q", got, want)
	}

	lt.Logf(l1, "bye")

	if got, want := lt.Check(), []string{l2}; !reflect.DeepEqual(got, want) {
		t.Errorf("Check = %q; want %q", got, want)
	}

	lt.Logf(l2, "hi")

	if got, want := lt.Check(), []string(nil); !reflect.DeepEqual(got, want) {
		t.Errorf("Check = %q; want %q", got, want)
	}
}
