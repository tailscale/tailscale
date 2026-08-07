// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package pinnedprefs

import (
	"encoding/json"
	"errors"

	"tailscale.com/ipn"
)

// pinnedPrefs returns the saved pinned favorites for the current profile, or a zero
// [ipn.PinnedPrefs] when none are saved or there's no current profile.
func (e *extension) pinnedPrefs() (ipn.PinnedPrefs, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.loadLocked()
}

// setPinnedPrefs replaces the categories in req whose Set field is true, leaves the rest untouched,
// and returns the full updated [ipn.PinnedPrefs].
func (e *extension) setPinnedPrefs(req ipn.PinnedPrefsRequest) (ipn.PinnedPrefs, error) {
	// Hold mu across the whole read-modify-write; each write persists the full value, so
	// concurrent writers would otherwise clobber each other.
	e.mu.Lock()
	defer e.mu.Unlock()

	prefs, err := e.loadLocked()
	if err != nil {
		return ipn.PinnedPrefs{}, err
	}

	if req.DevicesSet {
		prefs.Devices = req.Pinned.Devices
	}
	if req.ExitNodesSet {
		prefs.ExitNodes = req.Pinned.ExitNodes
	}
	if req.ServicesSet {
		prefs.Services = req.Pinned.Services
	}

	if err := e.saveLocked(prefs); err != nil {
		return ipn.PinnedPrefs{}, err
	}
	return prefs, nil
}

// loadLocked reads the current profile's pins, returning a zero [ipn.PinnedPrefs] when there's no
// store or nothing saved yet. The caller must hold e.mu.
func (e *extension) loadLocked() (ipn.PinnedPrefs, error) {
	if e.store == nil {
		return ipn.PinnedPrefs{}, nil
	}
	data, err := e.store.ReadState(storeKey)
	if errors.Is(err, ipn.ErrStateNotExist) {
		return ipn.PinnedPrefs{}, nil
	}
	if err != nil {
		return ipn.PinnedPrefs{}, err
	}
	var prefs ipn.PinnedPrefs
	if err := json.Unmarshal(data, &prefs); err != nil {
		return ipn.PinnedPrefs{}, err
	}
	return prefs, nil
}

// saveLocked writes prefs to the current profile's store, erroring when there's no store to
// persist to. The caller must hold e.mu.
func (e *extension) saveLocked(prefs ipn.PinnedPrefs) error {
	if e.store == nil {
		return errors.New("no store available to persist pinned favorites")
	}
	data, err := json.Marshal(prefs)
	if err != nil {
		return err
	}
	return e.store.WriteState(storeKey, data)
}
