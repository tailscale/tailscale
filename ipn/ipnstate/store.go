// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ipnstate

import (
	"errors"
)

// ErrStateNotExist is returned by Store.ReadState when the
// requested state ID doesn't exist.
var ErrStateNotExist = errors.New("no state with given ID")

const (
	// MachineKeyKey is the key under which we store the machine key,
	// in its wgkey.Private.MarshalText representation.
	MachineKeyKey = Key("_machinekey")

	// GlobalDaemonKey is the Key that tailscaled
	// loads on startup.
	//
	// We have to support multiple state keys for other OSes (Windows in
	// particular), but right now Unix daemons run with a single
	// node-global state. To keep open the option of having per-user state
	// later, the global state key doesn't look like a username.
	GlobalDaemonKey = Key("_daemon")

	// ServerModeStartKey's value, if non-empty, is the value of a
	// StateKey containing the prefs to start with which to start the
	// server.
	//
	// For example, the value might be "user-1234", meaning the
	// the server should start with the Prefs JSON loaded from
	// StateKey "user-1234".
	ServerModeStartKey = Key("server-mode-start-key")
)

// Store persists state, and produces it back on request.
type Store interface {
	// ReadState returns the bytes associated with ID. Returns (nil,
	// ErrStateNotExist) if the ID doesn't have associated state.
	ReadState(id Key) ([]byte, error)

	// WriteState saves bs as the state associated with ID.
	WriteState(id Key, bs []byte) error
}
