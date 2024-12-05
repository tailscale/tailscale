// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestEnv(t *testing.T) {

	var (
		init = map[string]string{
			"FOO": "bar",
		}

		wasSet   = map[string]string{}
		wasUnset = map[string]bool{}

		setenv = func(k, v string) error {
			wasSet[k] = v
			return nil
		}
		unsetenv = func(k string) error {
			wasUnset[k] = true
			return nil
		}
	)

	env := newEnvironmentForTest(init, setenv, unsetenv)

	if got, want := env.Get("FOO", ""), "bar"; got != want {
		t.Errorf(`env.Get("FOO") = %q, want %q`, got, want)
	}
	if got, want := env.IsSet("FOO"), true; got != want {
		t.Errorf(`env.IsSet("FOO") = %v, want %v`, got, want)
	}

	if got, want := env.Get("BAR", "defaultVal"), "defaultVal"; got != want {
		t.Errorf(`env.Get("BAR") = %q, want %q`, got, want)
	}
	if got, want := env.IsSet("BAR"), false; got != want {
		t.Errorf(`env.IsSet("BAR") = %v, want %v`, got, want)
	}

	env.Set("BAR", "quux")
	if got, want := env.Get("BAR", ""), "quux"; got != want {
		t.Errorf(`env.Get("BAR") = %q, want %q`, got, want)
	}
	if got, want := env.IsSet("BAR"), true; got != want {
		t.Errorf(`env.IsSet("BAR") = %v, want %v`, got, want)
	}
	diff := "BAR=quux (was <nil>)"
	if got := env.Diff(); got != diff {
		t.Errorf("env.Diff() = %q, want %q", got, diff)
	}

	env.Set("FOO", "foo2")
	if got, want := env.Get("FOO", ""), "foo2"; got != want {
		t.Errorf(`env.Get("FOO") = %q, want %q`, got, want)
	}
	if got, want := env.IsSet("FOO"), true; got != want {
		t.Errorf(`env.IsSet("FOO") = %v, want %v`, got, want)
	}
	diff = `BAR=quux (was <nil>)
FOO=foo2 (was bar)`
	if got := env.Diff(); got != diff {
		t.Errorf("env.Diff() = %q, want %q", got, diff)
	}

	env.Unset("FOO")
	if got, want := env.Get("FOO", "default"), "default"; got != want {
		t.Errorf(`env.Get("FOO") = %q, want %q`, got, want)
	}
	if got, want := env.IsSet("FOO"), false; got != want {
		t.Errorf(`env.IsSet("FOO") = %v, want %v`, got, want)
	}
	diff = `BAR=quux (was <nil>)
FOO=<nil> (was bar)`
	if got := env.Diff(); got != diff {
		t.Errorf("env.Diff() = %q, want %q", got, diff)
	}

	if err := env.Apply(); err != nil {
		t.Fatalf("env.Apply() failed: %v", err)
	}

	wantSet := map[string]string{"BAR": "quux"}
	wantUnset := map[string]bool{"FOO": true}

	if diff := cmp.Diff(wasSet, wantSet); diff != "" {
		t.Errorf("env.Apply didn't set as expected (-got+want):\n%s", diff)
	}
	if diff := cmp.Diff(wasUnset, wantUnset); diff != "" {
		t.Errorf("env.Apply didn't unset as expected (-got+want):\n%s", diff)
	}
}
