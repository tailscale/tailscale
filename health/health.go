// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package health is a registry for other packages to report & check
// overall health status of the node.
package health

import (
	"errors"
	"fmt"
	"sync"
	"time"

	"tailscale.com/tailcfg"
)

var (
	// mu guards everything in this var block.
	mu sync.Mutex

	m        = map[ErrorKey]error{}                     // error key => err (or nil for no error)
	watchers = map[*watchHandle]func(ErrorKey, error){} // opt func to run if error state changes
	timer    *time.Timer

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

// ErrorKey is an overall category for which an error is being reported.
type ErrorKey string

const (
	KeyOverall = ErrorKey("overall")
)

type watchHandle byte

// RegisterWatcher adds a function that will be called if an
// error changes state either to unhealthy or from unhealthy. It is
// not called on transition from unknown to healthy. It must be non-nil
// and is run in its own goroutine. The returned func unregisters it.
func RegisterWatcher(cb func(key ErrorKey, err error)) (unregister func()) {
	mu.Lock()
	defer mu.Unlock()
	handle := new(watchHandle)
	watchers[handle] = cb
	if timer == nil {
		timer = time.AfterFunc(time.Minute, timerSelfCheck)
	}
	return func() {
		mu.Lock()
		defer mu.Unlock()
		delete(watchers, handle)
		if len(watchers) == 0 && timer != nil {
			timer.Stop()
			timer = nil
		}
	}
}

// SetRouter sets the state of the wgengine/router.Router.
func SetRouterHealth(err error) { set("router", err) }

// RouterHealth returns the wgengine/router.Router error state.
func RouterHealth() error { return get("router") }

// SetNetworkCategoryHealth sets the state of setting the network adaptor's category.
// This only applies on Windows.
func SetNetworkCategoryHealth(err error) { set("network-category", err) }

func NetworkCategoryHealth() error { return get("network-category") }

func get(key ErrorKey) error {
	mu.Lock()
	defer mu.Unlock()
	return m[key]
}

func set(key ErrorKey, err error) {
	mu.Lock()
	defer mu.Unlock()
	setLocked(key, err)
}

func setLocked(key ErrorKey, err error) {
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

func timerSelfCheck() {
	mu.Lock()
	defer mu.Unlock()
	selfCheckLocked()
	if timer != nil {
		timer.Reset(time.Minute)
	}
}

func selfCheckLocked() {
	if ipnState == "" {
		// Don't check yet.
		return
	}
	setLocked(KeyOverall, overallErrorLocked())
}

func overallErrorLocked() error {
	if ipnState != "Running" || !ipnWantRunning {
		return fmt.Errorf("state=%v, wantRunning=%v", ipnState, ipnWantRunning)
	}
	now := time.Now()
	if !inMapPoll && (lastMapPollEndedAt.IsZero() || now.Sub(lastMapPollEndedAt) > 10*time.Second) {
		return errors.New("not in map poll")
	}
	const tooIdle = 2*time.Minute + 5*time.Second
	if d := now.Sub(lastStreamedMapResponse).Round(time.Second); d > tooIdle {
		return fmt.Errorf("no map response in %v", d)
	}
	rid := derpHomeRegion
	if rid == 0 {
		return errors.New("no DERP home")
	}
	if !derpRegionConnected[rid] {
		return fmt.Errorf("not connected to home DERP region %v", rid)
	}
	if d := now.Sub(derpRegionLastFrame[rid]).Round(time.Second); d > tooIdle {
		return fmt.Errorf("haven't heard from home DERP region %v in %v", rid, d)
	}

	// TODO: use
	_ = inMapPollSince
	_ = lastMapPollEndedAt
	_ = lastStreamedMapResponse
	_ = lastMapRequestHeard

	return nil
}
