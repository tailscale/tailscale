// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"fmt"
	"os"
	"sort"
	"strings"
)

// Environment starts from an initial set of environment variables, and tracks
// mutations to the environment. It can then apply those mutations to the
// environment, or produce debugging output that illustrates the changes it
// would make.
type Environment struct {
	init  map[string]string
	set   map[string]string
	unset map[string]bool

	setenv   func(string, string) error
	unsetenv func(string) error
}

// NewEnvironment returns an Environment initialized from os.Environ.
func NewEnvironment() *Environment {
	init := map[string]string{}
	for _, env := range os.Environ() {
		fs := strings.SplitN(env, "=", 2)
		if len(fs) != 2 {
			panic("bad environ provided")
		}
		init[fs[0]] = fs[1]
	}

	return newEnvironmentForTest(init, os.Setenv, os.Unsetenv)
}

func newEnvironmentForTest(init map[string]string, setenv func(string, string) error, unsetenv func(string) error) *Environment {
	return &Environment{
		init:     init,
		set:      map[string]string{},
		unset:    map[string]bool{},
		setenv:   setenv,
		unsetenv: unsetenv,
	}
}

// Set sets the environment variable k to v.
func (e *Environment) Set(k, v string) {
	e.set[k] = v
	delete(e.unset, k)
}

// Unset removes the environment variable k.
func (e *Environment) Unset(k string) {
	delete(e.set, k)
	e.unset[k] = true
}

// IsSet reports whether the environment variable k is set.
func (e *Environment) IsSet(k string) bool {
	if e.unset[k] {
		return false
	}
	if _, ok := e.init[k]; ok {
		return true
	}
	if _, ok := e.set[k]; ok {
		return true
	}
	return false
}

// Get returns the value of the environment variable k, or defaultVal if it is
// not set.
func (e *Environment) Get(k, defaultVal string) string {
	if e.unset[k] {
		return defaultVal
	}
	if v, ok := e.set[k]; ok {
		return v
	}
	if v, ok := e.init[k]; ok {
		return v
	}
	return defaultVal
}

// Apply applies all pending mutations to the environment.
func (e *Environment) Apply() error {
	for k, v := range e.set {
		if err := e.setenv(k, v); err != nil {
			return fmt.Errorf("setting %q: %v", k, err)
		}
		e.init[k] = v
		delete(e.set, k)
	}
	for k := range e.unset {
		if err := e.unsetenv(k); err != nil {
			return fmt.Errorf("unsetting %q: %v", k, err)
		}
		delete(e.init, k)
		delete(e.unset, k)
	}
	return nil
}

// Diff returns a string describing the pending mutations to the environment.
func (e *Environment) Diff() string {
	lines := make([]string, 0, len(e.set)+len(e.unset))
	for k, v := range e.set {
		old, ok := e.init[k]
		if ok {
			lines = append(lines, fmt.Sprintf("%s=%s (was %s)", k, v, old))
		} else {
			lines = append(lines, fmt.Sprintf("%s=%s (was <nil>)", k, v))
		}
	}
	for k := range e.unset {
		old, ok := e.init[k]
		if ok {
			lines = append(lines, fmt.Sprintf("%s=<nil> (was %s)", k, old))
		} else {
			lines = append(lines, fmt.Sprintf("%s=<nil> (was <nil>)", k))
		}
	}
	sort.Strings(lines)
	return strings.Join(lines, "\n")
}
