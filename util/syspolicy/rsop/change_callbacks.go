// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package rsop

import (
	"reflect"
	"slices"
	"sync"
	"time"

	"tailscale.com/syncs"
	"tailscale.com/util/execqueue"
	"tailscale.com/util/set"
	"tailscale.com/util/syspolicy/internal/loggerx"
	"tailscale.com/util/syspolicy/pkey"
	"tailscale.com/util/syspolicy/policyclient"
	"tailscale.com/util/syspolicy/ptype"
	"tailscale.com/util/syspolicy/setting"
)

// Change represents a change from the Old to the New value of type T.
type Change[T any] struct {
	New, Old T
}

// PolicyChangeCallback is a function called whenever a policy changes.
type PolicyChangeCallback func(policyclient.PolicyChange)

// PolicyChange describes a policy change.
type PolicyChange struct {
	snapshots Change[*setting.Snapshot]
}

// New returns the [setting.Snapshot] after the change.
func (c PolicyChange) New() *setting.Snapshot {
	return c.snapshots.New
}

// Old returns the [setting.Snapshot] before the change.
func (c PolicyChange) Old() *setting.Snapshot {
	return c.snapshots.Old
}

// HasChanged reports whether a policy setting with the specified [pkey.Key], has changed.
func (c PolicyChange) HasChanged(key pkey.Key) bool {
	new, newErr := c.snapshots.New.GetErr(key)
	old, oldErr := c.snapshots.Old.GetErr(key)
	if newErr != nil && oldErr != nil {
		return false
	}
	if newErr != nil || oldErr != nil {
		return true
	}
	switch newVal := new.(type) {
	case bool, uint64, string, ptype.Visibility, ptype.PreferenceOption, time.Duration:
		return newVal != old
	case []string:
		oldVal, ok := old.([]string)
		return !ok || !slices.Equal(newVal, oldVal)
	default:
		loggerx.Errorf("[unexpected] %q has an unsupported value type: %T", key, newVal)
		return !reflect.DeepEqual(new, old)
	}
}

// HasChangedAnyOf reports whether any of the specified policy settings has changed.
func (c PolicyChange) HasChangedAnyOf(keys ...pkey.Key) bool {
	return slices.ContainsFunc(keys, c.HasChanged)
}

// policyChangeCallbacks are the callbacks to invoke when the effective policy changes.
// It is safe for concurrent use.
type policyChangeCallbacks struct {
	mu  syncs.Mutex
	cbs set.HandleSet[PolicyChangeCallback]
	q   execqueue.ExecQueue // invokes cbs, one policy change at a time
}

// Register adds the specified callback to be invoked whenever the policy changes.
func (c *policyChangeCallbacks) Register(callback PolicyChangeCallback) (unregister func()) {
	c.mu.Lock()
	handle := c.cbs.Add(callback)
	c.mu.Unlock()
	return func() {
		c.mu.Lock()
		delete(c.cbs, handle)
		c.mu.Unlock()
	}
}

// Invoke schedules the registered callback functions to be called with the
// specified policy change info. It does not wait for them to return, so it
// can be called while holding locks that the callbacks acquire. The callbacks
// for one policy change return before those for the next one are called.
func (c *policyChangeCallbacks) Invoke(snapshots Change[*setting.Snapshot]) {
	c.q.Add(func() { c.invoke(snapshots) })
}

func (c *policyChangeCallbacks) invoke(snapshots Change[*setting.Snapshot]) {
	var wg sync.WaitGroup
	defer wg.Wait()

	c.mu.Lock()
	defer c.mu.Unlock()

	wg.Add(len(c.cbs))
	change := &PolicyChange{snapshots: snapshots}
	for _, cb := range c.cbs {
		go func() {
			defer wg.Done()
			cb(change)
		}()
	}
}

// Close prevents any further invocations.
func (c *policyChangeCallbacks) Close() {
	c.q.Shutdown()
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.cbs != nil {
		clear(c.cbs)
		c.cbs = nil
	}
}
