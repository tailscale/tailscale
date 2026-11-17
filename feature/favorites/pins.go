// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package favorites

import (
	"encoding/json"
	"errors"

	"tailscale.com/feature/favorites/pintype"
	"tailscale.com/ipn"
)

// currentPins returns the saved pinned favorites for the current profile, or a zero [pintype.Set]
// when none are saved or there's no current profile.
func (e *extension) currentPins() (pintype.Set, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.loadLocked()
}

// setPins replaces the categories in req whose Set field is true, leaves the rest untouched, and
// returns the full updated [pintype.Set].
func (e *extension) setPins(req pintype.SetRequest) (pintype.Set, error) {
	// Hold mu across the whole read-modify-write; each write persists the full value, so
	// concurrent writers would otherwise clobber each other.
	e.mu.Lock()
	defer e.mu.Unlock()

	cur, err := e.loadLocked()
	if err != nil {
		return pintype.Set{}, err
	}

	if req.DevicesSet {
		cur.Devices = req.Pins.Devices
	}
	if req.ExitNodesSet {
		cur.ExitNodes = req.Pins.ExitNodes
	}
	if req.ServicesSet {
		cur.Services = req.Pins.Services
	}

	if err := e.saveLocked(cur); err != nil {
		return pintype.Set{}, err
	}
	return cur, nil
}

// loadLocked reads the current profile's pins, returning a zero [pintype.Set] when there's no store or
// nothing saved yet. The caller must hold e.mu.
func (e *extension) loadLocked() (pintype.Set, error) {
	if e.store == nil {
		return pintype.Set{}, nil
	}
	data, err := e.store.ReadState(featureName)
	if errors.Is(err, ipn.ErrStateNotExist) {
		return pintype.Set{}, nil
	}
	if err != nil {
		return pintype.Set{}, err
	}
	var set pintype.Set
	if err := json.Unmarshal(data, &set); err != nil {
		return pintype.Set{}, err
	}
	return set, nil
}

// saveLocked writes set to the current profile's store, erroring when there's no store to persist
// to. The caller must hold e.mu.
func (e *extension) saveLocked(set pintype.Set) error {
	if e.store == nil {
		return errors.New("no store available to persist pinned favorites")
	}
	data, err := json.Marshal(set)
	if err != nil {
		return err
	}
	return e.store.WriteState(featureName, data)
}
