// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ipn

import (
	"errors"
	"fmt"
	"strconv"
)

// ErrStateNotExist is returned by StateStore.ReadState when the
// requested state ID doesn't exist.
var ErrStateNotExist = errors.New("no state with given ID")

const (
	// MachineKeyStateKey is the key under which we store the machine key,
	// in its key.NodePrivate.MarshalText representation.
	MachineKeyStateKey = StateKey("_machinekey")

	// GlobalDaemonStateKey is the ipn.StateKey that tailscaled
	// loads on startup.
	//
	// We have to support multiple state keys for other OSes (Windows in
	// particular), but right now Unix daemons run with a single
	// node-global state. To keep open the option of having per-user state
	// later, the global state key doesn't look like a username.
	GlobalDaemonStateKey = StateKey("_daemon")

	// ServerModeStartKey's value, if non-empty, is the value of a
	// StateKey containing the prefs to start with which to start the
	// server.
	//
	// For example, the value might be "user-1234", meaning the
	// the server should start with the Prefs JSON loaded from
	// StateKey "user-1234".
	ServerModeStartKey = StateKey("server-mode-start-key")

	// NLKeyStateKey is the key under which we store the node's
	// network-lock node key, in its key.NLPrivate.MarshalText representation.
	NLKeyStateKey = StateKey("_nl-node-key")
)

// StateStore persists state, and produces it back on request.
type StateStore interface {
	// ReadState returns the bytes associated with ID. Returns (nil,
	// ErrStateNotExist) if the ID doesn't have associated state.
	ReadState(id StateKey) ([]byte, error)
	// WriteState saves bs as the state associated with ID.
	WriteState(id StateKey, bs []byte) error
}

// ReadStoreInt reads an integer from a StateStore.
func ReadStoreInt(store StateStore, id StateKey) (int64, error) {
	v, err := store.ReadState(id)
	if err != nil {
		return 0, err
	}
	return strconv.ParseInt(string(v), 10, 64)
}

// PutStoreInt puts an integer into a StateStore.
func PutStoreInt(store StateStore, id StateKey, val int64) error {
	return store.WriteState(id, fmt.Appendf(nil, "%d", val))
}
