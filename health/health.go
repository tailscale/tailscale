// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package health is a registry for other packages to report & check
// overall health status of the node.
package health

import (
	"sync"
)

var (
	mu       sync.Mutex
	m        = map[string]error{}                     // error key => err (or nil for no error)
	watchers = map[*watchHandle]func(string, error){} // opt func to run if error state changes
)

type watchHandle byte

// RegisterWatcher adds a function that will be called if an
// error changes state either to unhealthy or from unhealthy. It is
// not called on transition from unknown to healthy. It must be non-nil
// and is run in its own goroutine. The returned func unregisters it.
func RegisterWatcher(cb func(errKey string, err error)) (unregister func()) {
	mu.Lock()
	defer mu.Unlock()
	handle := new(watchHandle)
	watchers[handle] = cb
	return func() {
		mu.Lock()
		defer mu.Unlock()
		delete(watchers, handle)
	}
}

// SetRouter sets the state of the wgengine/router.Router.
func SetRouterHealth(err error) { set("router", err) }

// RouterHealth returns the wgengine/router.Router error state.
func RouterHealth() error { return get("router") }

func get(key string) error {
	mu.Lock()
	defer mu.Unlock()
	return m[key]
}

func set(key string, err error) {
	mu.Lock()
	defer mu.Unlock()
	old, ok := m[key]
	if !ok && err == nil {
		// Initial happy path.
		m[key] = nil
		return
	}
	if ok && (old == nil) == (err == nil) {
		// No change in overall error status (nil-vs-not), so
		// don't run callbacks, but exact error might've
		// changed, so note it.
		if err != nil {
			m[key] = err
		}
		return
	}
	m[key] = err
	for _, cb := range watchers {
		go cb(key, err)
	}
}
