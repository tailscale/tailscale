// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package health

import (
	"errors"
	"fmt"
	"reflect"
	"testing"

	"tailscale.com/util/set"
)

func TestAppendWarnableDebugFlags(t *testing.T) {
	resetWarnables()

	for i := range 10 {
		w := NewWarnable(WithMapDebugFlag(fmt.Sprint(i)))
		if i%2 == 0 {
			w.Set(errors.New("boom"))
		}
	}

	want := []string{"z", "y", "0", "2", "4", "6", "8"}

	var got []string
	for range 20 {
		got = append(got[:0], "z", "y")
		got = AppendWarnableDebugFlags(got)
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("AppendWarnableDebugFlags = %q; want %q", got, want)
		}
	}
}

func resetWarnables() {
	mu.Lock()
	defer mu.Unlock()
	warnables = set.Set[*Warnable]{}
}
