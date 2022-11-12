// Copyright (c) 2022 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cli

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"tailscale.com/ipn"
)

func TestServeConfigMutations(t *testing.T) {
	// Stateful mutations, starting from an empty config.
	type step struct {
		command []string                       // serve args; nil means no command to run (only reset)
		reset   bool                           // if true, reset all ServeConfig state
		want    *ipn.ServeConfig               // non-nil means we want a save of this value
		wantErr func(error) (badErrMsg string) // nil means no error is wanted
		line    int                            // line number of addStep call, for error messages
	}
	var steps []step
	add := func(s step) {
		_, _, s.line, _ = runtime.Caller(1)
		steps = append(steps, s)
	}

	add(step{reset: true})
	add(step{
		command: cmd("ingress on"),
		want:    &ipn.ServeConfig{AllowIngress: map[ipn.HostPort]bool{"foo:123": true}},
	})
	add(step{
		command: cmd("ingress on"),
		want:    nil, // nothing to save
	})
	add(step{
		command: cmd("ingress off"),
		want:    &ipn.ServeConfig{AllowIngress: map[ipn.HostPort]bool{}},
	})
	add(step{
		command: cmd("ingress off"),
		want:    nil, // nothing to save
	})
	add(step{
		command: cmd("ingress"),
		wantErr: exactErr(flag.ErrHelp, "flag.ErrHelp"),
	})

	// And now run the steps above.
	var current *ipn.ServeConfig
	for i, st := range steps {
		if st.reset {
			t.Logf("Executing step #%d, line %v: [reset]", i, st.line)
			current = nil
		}
		if st.command == nil {
			continue
		}
		t.Logf("Executing step #%d, line %v: %q ... ", i, st.line, st.command)

		var stdout bytes.Buffer
		var flagOut bytes.Buffer
		var newState *ipn.ServeConfig
		e := &serveEnv{
			testFlagOut: &flagOut,
			testStdout:  &stdout,
			testGetServeConfig: func(context.Context) (*ipn.ServeConfig, error) {
				return current, nil
			},
			testSetServeConfig: func(_ context.Context, c *ipn.ServeConfig) error {
				newState = c
				return nil
			},
		}
		cmd := newServeCommand(e)
		err := cmd.ParseAndRun(context.Background(), st.command)
		if flagOut.Len() > 0 {
			t.Logf("flag package output: %q", flagOut.Bytes())
		}
		if err != nil {
			if st.wantErr == nil {
				t.Fatalf("step #%d, line %v: unexpected error: %v", i, st.line, err)
			}
			if bad := st.wantErr(err); bad != "" {
				t.Fatalf("step #%d, line %v: unexpected error: %v", i, st.line, bad)
			}
			continue
		}
		if st.wantErr != nil {
			t.Fatalf("step #%d, line %v: got success (saved=%v), but wanted an error", i, st.line, newState != nil)
		}
		if !reflect.DeepEqual(newState, st.want) {
			t.Fatalf("[%d] %v: bad state. got:\n%s\n\nwant:\n%s\n",
				i, st.command, asJSON(newState), asJSON(st.want))
		}
		if newState != nil {
			current = newState
		}
	}
}

// exactError returns an error checker that wants exactly the provided want error.
// If optName is non-empty, it's used in the error message.
func exactErr(want error, optName ...string) func(error) string {
	return func(got error) string {
		if got == want {
			return ""
		}
		if len(optName) > 0 {
			return fmt.Sprintf("got error %v, want %v", got, optName[0])
		}
		return fmt.Sprintf("got error %v, want %v", got, want)
	}
}

func cmd(s string) []string {
	return strings.Fields(s)
}
