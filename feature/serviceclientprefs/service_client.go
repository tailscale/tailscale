// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package serviceclientprefs

import (
	"encoding/json"
	"errors"

	"tailscale.com/client/tailscale/apitype"
	"tailscale.com/feature/serviceclientprefs/serviceclient"
	"tailscale.com/ipn"
)

// errInvalidServiceClientPref is returned by [extension.setServiceClientPref] for a request that
// fails validation, such as a missing key. The handler maps it to a 400, unlike backend failures.
var errInvalidServiceClientPref = errors.New("service client pref key is required")

// serviceClientPrefs returns the saved service client prefs for the current profile. It returns an
// empty, non-nil map when nothing has been saved yet, or when there's no current profile (a logged
// out node simply has no service client prefs).
func (e *extension) serviceClientPrefs() (serviceclient.Prefs, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.loadLocked()
}

// setServiceClientPref merges the non-empty fields from [apitype.ServiceClientPrefRequest] into the
// saved pref for its key, stamps [serviceclient.Pref.LastUsed] with the current time, and returns
// the full updated service client prefs for the current profile.
func (e *extension) setServiceClientPref(req apitype.ServiceClientPrefRequest) (serviceclient.Prefs, error) {
	if req.Key == "" {
		return nil, errInvalidServiceClientPref
	}

	// Hold mu across the whole read, change, and write so two writers can't clobber each other,
	// since each writes back the full prefs map.
	e.mu.Lock()
	defer e.mu.Unlock()

	prefs, err := e.loadLocked()
	if err != nil {
		return nil, err
	}
	pref := prefs[req.Key]
	if req.Client != "" {
		pref.Client = req.Client
	}
	if req.Username != "" {
		pref.Username = req.Username
	}
	if req.DatabaseName != "" {
		pref.DatabaseName = req.DatabaseName
	}
	pref.LastUsed = e.sb.Clock().Now()
	prefs[req.Key] = pref

	if err := e.saveLocked(prefs); err != nil {
		return nil, err
	}
	return prefs, nil
}

// loadLocked reads the current profile's prefs, returning an empty map when there's no store (no
// current profile) or nothing saved yet. The caller must hold e.mu.
func (e *extension) loadLocked() (serviceclient.Prefs, error) {
	if e.store == nil {
		return serviceclient.Prefs{}, nil
	}
	data, err := e.store.ReadState(storeKey)
	if errors.Is(err, ipn.ErrStateNotExist) {
		return serviceclient.Prefs{}, nil
	}
	if err != nil {
		return nil, err
	}
	var prefs serviceclient.Prefs
	if err := json.Unmarshal(data, &prefs); err != nil {
		return nil, err
	}
	if prefs == nil {
		prefs = serviceclient.Prefs{}
	}
	return prefs, nil
}

// saveLocked writes prefs to the current profile's store. It returns an error when there's no
// store to persist to (no current profile, or the store failed to build). The caller must hold e.mu.
func (e *extension) saveLocked(prefs serviceclient.Prefs) error {
	if e.store == nil {
		return errors.New("no store available to persist service client prefs")
	}
	data, err := json.Marshal(prefs)
	if err != nil {
		return err
	}
	return e.store.WriteState(storeKey, data)
}
