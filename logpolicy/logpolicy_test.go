// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package logpolicy

import (
	"os"
	"reflect"
	"testing"

	"tailscale.com/logtail"
)

func TestLogHost(t *testing.T) {
	v := reflect.ValueOf(&getLogTargetOnce).Elem()
	reset := func() {
		v.Set(reflect.Zero(v.Type()))
	}
	defer reset()

	tests := []struct {
		env  string
		want string
	}{
		{"", logtail.DefaultHost},
		{"http://foo.com", "foo.com"},
		{"https://foo.com", "foo.com"},
		{"https://foo.com/", "foo.com"},
		{"https://foo.com:123/", "foo.com"},
	}
	for _, tt := range tests {
		reset()
		os.Setenv("TS_LOG_TARGET", tt.env)
		if got := LogHost(); got != tt.want {
			t.Errorf("for env %q, got %q, want %q", tt.env, got, tt.want)
		}
	}
}
