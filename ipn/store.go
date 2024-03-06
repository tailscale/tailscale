// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package ipn

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
)

// ErrStateNotExist is returned by StateStore.ReadState when the
// requested state ID doesn't exist.
var ErrStateNotExist = errors.New("no state with given ID")

const (
	// MachineKeyStateKey is the key under which we store the machine key,
	// in its key.NodePrivate.MarshalText representation.
	MachineKeyStateKey = StateKey("_machinekey")

	// LegacyGlobalDaemonStateKey is the ipn.StateKey that tailscaled
	// loads on startup.
	//
	// We have to support multiple state keys for other OSes (Windows in
	// particular), but right now Unix daemons run with a single
	// node-global state. To keep open the option of having per-user state
	// later, the global state key doesn't look like a username.
	//
	// As of 2022-10-21, it has been superseded by profiles and is no longer
	// written to disk. It is only read at startup when there are no profiles,
	// to migrate the state to the "default" profile.
	// The existing state is left on disk in case the user downgrades to an
	// older version of Tailscale that doesn't support profiles. We can
	// remove this in a future release.
	LegacyGlobalDaemonStateKey = StateKey("_daemon")

	// ServerModeStartKey's value, if non-empty, is the value of a
	// StateKey containing the prefs to start with which to start the
	// server.
	//
	// For example, the value might be "user-1234", meaning the
	// the server should start with the Prefs JSON loaded from
	// StateKey "user-1234".
	ServerModeStartKey = StateKey("server-mode-start-key")

	// KnownProfilesStateKey is the key under which we store the list of
	// known profiles. The value is a JSON-encoded []LoginProfile.
	KnownProfilesStateKey = StateKey("_profiles")

	// CurrentProfileStateKey is the key under which we store the current
	// profile.
	CurrentProfileStateKey = StateKey("_current-profile")

	// TaildropReceivedKey is the key to indicate whether any taildrop file
	// has ever been received (even if partially).
	// Any non-empty value indicates that at least one file has been received.
	TaildropReceivedKey = StateKey("_taildrop-received")
)

// CurrentProfileID returns the StateKey that stores the
// current profile ID. The value is a JSON-encoded LoginProfile.
// If the userID is empty, the key returned is CurrentProfileStateKey,
// otherwise it is "_current/"+userID.
func CurrentProfileKey(userID string) StateKey {
	if userID == "" {
		return CurrentProfileStateKey
	}
	return StateKey("_current/" + userID)
}

// StateStore persists state, and produces it back on request.
// Implementations of StateStore are expected to be safe for concurrent use.
type StateStore interface {
	// ReadState returns the bytes associated with ID. Returns (nil,
	// ErrStateNotExist) if the ID doesn't have associated state.
	ReadState(id StateKey) ([]byte, error)
	// WriteState saves bs as the state associated with ID.
	//
	// Callers should generally use the ipn.WriteState wrapper func
	// instead, which only writes if the value is different from what's
	// already in the store.
	WriteState(id StateKey, bs []byte) error
}

// WriteState is a wrapper around store.WriteState that only writes if
// the value is different from what's already in the store.
func WriteState(store StateStore, id StateKey, v []byte) error {
	if was, err := store.ReadState(id); err == nil && bytes.Equal(was, v) {
		return nil
	}
	return store.WriteState(id, v)
}

// StateStoreDialerSetter is an optional interface that StateStores
// can implement to allow the caller to set a custom dialer.
type StateStoreDialerSetter interface {
	SetDialer(d func(ctx context.Context, network, address string) (net.Conn, error))
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
	return WriteState(store, id, fmt.Appendf(nil, "%d", val))
}
