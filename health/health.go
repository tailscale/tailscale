// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package health is a registry for other packages to report & check
// overall health status of the node.
package health

import (
	"sync"
	"time"

	"tailscale.com/tailcfg"
)

var (
	// mu guards everything in this var block.
	mu sync.Mutex

	m        = map[string]error{}                     // error key => err (or nil for no error)
	watchers = map[*watchHandle]func(string, error){} // opt func to run if error state changes

	inMapPoll               bool
	inMapPollSince          time.Time
	lastMapPollEndedAt      time.Time
	lastStreamedMapResponse time.Time
	derpHomeRegion          int
	derpRegionConnected     = map[int]bool{}
	derpRegionLastFrame     = map[int]time.Time{}
	lastMapRequestHeard     time.Time // time we got a 200 from control for a MapRequest
	ipnState                string
	ipnWantRunning          bool
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
		selfCheckLocked()
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
	selfCheckLocked()
	for _, cb := range watchers {
		go cb(key, err)
	}
}

// GotStreamedMapResponse notes that we got a tailcfg.MapResponse
// message in streaming mode, even if it's just a keep-alive message.
func GotStreamedMapResponse() {
	mu.Lock()
	defer mu.Unlock()
	lastStreamedMapResponse = time.Now()
	selfCheckLocked()
}

// SetInPollNetMap records that we're in
func SetInPollNetMap(v bool) {
	mu.Lock()
	defer mu.Unlock()
	if v == inMapPoll {
		return
	}
	inMapPoll = v
	if v {
		inMapPollSince = time.Now()
	} else {
		lastMapPollEndedAt = time.Now()
	}
}

// SetMagicSockDERPHome notes what magicsock's view of its home DERP is.
func SetMagicSockDERPHome(region int) {
	mu.Lock()
	defer mu.Unlock()
	derpHomeRegion = region
	selfCheckLocked()
}

// NoteMapRequestHeard notes whenever we successfully sent a map request
// to control for which we received a 200 response.
func NoteMapRequestHeard(mr *tailcfg.MapRequest) {
	mu.Lock()
	defer mu.Unlock()
	// TODO: extract mr.HostInfo.NetInfo.PreferredDERP, compare
	// against SetMagicSockDERPHome and
	// SetDERPRegionConnectedState

	lastMapRequestHeard = time.Now()
	selfCheckLocked()
}

func SetDERPRegionConnectedState(region int, connected bool) {
	mu.Lock()
	defer mu.Unlock()
	derpRegionConnected[region] = connected
	selfCheckLocked()
}

func NoteDERPRegionReceivedFrame(region int) {
	mu.Lock()
	defer mu.Unlock()
	derpRegionLastFrame[region] = time.Now()
	selfCheckLocked()
}

// state is an ipn.State.String() value: "Running", "Stopped", "NeedsLogin", etc.
func SetIPNState(state string, wantRunning bool) {
	mu.Lock()
	defer mu.Unlock()
	ipnState = state
	ipnWantRunning = wantRunning
	selfCheckLocked()
}

func selfCheckLocked() {
	// TODO: check states against each other.
	// For staticcheck for now:
	_ = inMapPollSince
	_ = lastMapPollEndedAt
	_ = lastStreamedMapResponse
	_ = derpHomeRegion
	_ = lastMapRequestHeard
	_ = ipnState
	_ = ipnWantRunning
}
