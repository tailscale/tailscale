// Copyright (c) 2022 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cli

import (
	"reflect"
	"runtime"
	"testing"

	"tailscale.com/ipn"
)

func TestServeConfigMutations(t *testing.T) {
	// Stateful mutations, starting from an empty config.
	type step struct {
		command []string // serve args
		reset   bool     // if true, reset all ServeConfig state
		want    *ipn.ServeConfig
		wantErr string
		line    int // line number of addStep call, for error messages
	}
	var steps []step
	add := func(s step) {
		_, _, s.line, _ = runtime.Caller(1)
		steps = append(steps, s)
	}
	add(step{reset: true})
	add(step{
		want: nil,
	})
	var current *ipn.ServeConfig
	for i, st := range steps {
		t.Logf("Executing step #%d (line %v) ... ", i, st.line)
		if st.reset {
			t.Logf("(resetting state)")
			current = nil
		}
		newState, err := applyServeMutation(current, st.command)
		var gotErr string
		if err != nil {
			gotErr = err.Error()
		}
		if gotErr != st.wantErr {
			t.Fatalf("[%d] %v: got error %q, want %q", i, st.command, gotErr, st.wantErr)
		}
		if !reflect.DeepEqual(newState, st.want) {
			t.Fatalf("[%d] %v: bad state. got:\n%s\n\nwant:\n%s\n",
				i, st.command, asJSON(newState), asJSON(st.want))
		}
	}
}
