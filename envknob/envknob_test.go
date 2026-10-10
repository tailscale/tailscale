// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package envknob

import (
	"testing"
	"time"

	"tailscale.com/types/opt"
)

// TestSetenvUpdatesRegisteredKnobs verifies that Setenv updates the values
// returned by knobs registered before the call, for every Register function,
// and that SetenvForTest restores them afterwards.
func TestSetenvUpdatesRegisteredKnobs(t *testing.T) {
	str := RegisterString("TS_TEST_ENVKNOB_STRING")
	b := RegisterBool("TS_TEST_ENVKNOB_BOOL")
	ob := RegisterOptBool("TS_TEST_ENVKNOB_OPT_BOOL")
	d := RegisterDuration("TS_TEST_ENVKNOB_DURATION")
	n := RegisterInt("TS_TEST_ENVKNOB_INT")

	tests := []struct {
		envVar string
		val    string
		get    func() any
		want   any
	}{
		{"TS_TEST_ENVKNOB_STRING", "foo", func() any { return str() }, "foo"},
		{"TS_TEST_ENVKNOB_BOOL", "true", func() any { return b() }, true},
		{"TS_TEST_ENVKNOB_OPT_BOOL", "false", func() any { return ob() }, opt.False},
		{"TS_TEST_ENVKNOB_DURATION", "5s", func() any { return d() }, 5 * time.Second},
		{"TS_TEST_ENVKNOB_INT", "42", func() any { return n() }, 42},
	}
	for _, tt := range tests {
		orig := tt.get()
		t.Run(tt.envVar, func(t *testing.T) {
			SetenvForTest(t, tt.envVar, tt.val)
			if got := tt.get(); got != tt.want {
				t.Errorf("after Setenv(%q, %q), knob = %v; want %v", tt.envVar, tt.val, got, tt.want)
			}
		})
		if got := tt.get(); got != orig {
			t.Errorf("after SetenvForTest cleanup, %s knob = %v; want %v", tt.envVar, got, orig)
		}
	}
}
