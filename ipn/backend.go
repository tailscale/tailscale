// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ipn

import (
	"net/http"
	"time"

	"tailscale.com/control/controlclient"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/tailcfg"
	"tailscale.com/types/empty"
	"tailscale.com/types/structs"
	"tailscale.com/wgengine"
)

type State int

const (
	NoState = State(iota)
	NeedsLogin
	NeedsMachineAuth
	Stopped
	Starting
	Running
)

func (s State) String() string {
	return [...]string{"NoState", "NeedsLogin", "NeedsMachineAuth",
		"Stopped", "Starting", "Running"}[s]
}

// EngineStatus contains WireGuard engine stats.
type EngineStatus struct {
	RBytes, WBytes wgengine.ByteCount
	NumLive        int
	LiveDERPs      int // number of active DERP connections
	LivePeers      map[tailcfg.NodeKey]wgengine.PeerStatus
}

// Notify is a communication from a backend (e.g. tailscaled) to a frontend
// (cmd/tailscale, iOS, macOS, Win Tasktray).
// In any given notification, any or all of these may be nil, meaning
// that they have not changed.
// They are JSON-encoded on the wire, despite the lack of struct tags.
type Notify struct {
	_             structs.Incomparable
	Version       string                    // version number of IPN backend
	ErrMessage    *string                   // critical error message, if any
	LoginFinished *empty.Message            // event: non-nil when login process succeeded
	State         *State                    // current IPN state has changed
	Prefs         *Prefs                    // preferences were changed
	NetMap        *controlclient.NetworkMap // new netmap received
	Engine        *EngineStatus             // wireguard engine stats
	Status        *ipnstate.Status          // full status
	BrowseToURL   *string                   // UI should open a browser right now
	BackendLogID  *string                   // public logtail id used by backend

	// type is mirrored in xcode/Shared/IPN.swift
}

// StateKey is an opaque identifier for a set of LocalBackend state
// (preferences, private keys, etc.).
//
// The reason we need this is that the Tailscale agent may be running
// on a multi-user machine, in a context where a single daemon is
// shared by several consecutive users. Ideally we would just use the
// username of the connected frontend as the StateKey.
//
// However, on Windows, there seems to be no safe way to figure out
// the owning user of a process connected over IPC mechanisms
// (sockets, named pipes). So instead, on Windows, we use a
// capability-oriented system where the frontend generates a random
// identifier for itself, and uses that as the StateKey when talking
// to the backend. That way, while we can't identify an OS user by
// name, we can tell two different users apart, because they'll have
// different opaque state keys (and no access to each others's keys).
type StateKey string

type Options struct {
	// FrontendLogID is the public logtail id used by the frontend.
	FrontendLogID string
	// StateKey and Prefs together define the state the backend should
	// use:
	//  - StateKey=="" && Prefs!=nil: use Prefs for internal state,
	//    don't persist changes in the backend.
	//  - StateKey!="" && Prefs==nil: load the given backend-side
	//    state and use/update that.
	//  - StateKey!="" && Prefs!=nil: like the previous case, but do
	//    an initial overwrite of backend state with Prefs.
	StateKey StateKey
	Prefs    *Prefs
	// AuthKey is an optional node auth key used to authorize a
	// new node key without user interaction.
	AuthKey string
	// LegacyConfigPath optionally specifies the old-style relaynode
	// relay.conf location. If both LegacyConfigPath and StateKey are
	// specified and the requested state doesn't exist in the backend
	// store, the backend migrates the config from LegacyConfigPath.
	//
	// TODO(danderson): remove some time after the transition to
	// tailscaled is done.
	LegacyConfigPath string
	// Notify is called when backend events happen.
	Notify func(Notify) `json:"-"`
	// HTTPTestClient is an optional HTTP client to pass to controlclient
	// (for tests only).
	HTTPTestClient *http.Client
}

// Backend is the interface between Tailscale frontends
// (e.g. cmd/tailscale, iOS/MacOS/Windows GUIs) and the tailscale
// backend (e.g. cmd/tailscaled) running on the same machine.
// (It has nothing to do with the interface between the backends
// and the cloud control plane.)
type Backend interface {
	// Start starts or restarts the backend, typically when a
	// frontend client connects.
	Start(Options) error
	// StartLoginInteractive requests to start a new interactive login
	// flow. This should trigger a new BrowseToURL notification
	// eventually.
	StartLoginInteractive()
	// Logout terminates the current login session and stops the
	// wireguard engine.
	Logout()
	// SetPrefs installs a new set of user preferences, including
	// WantRunning. This may cause the wireguard engine to
	// reconfigure or stop.
	SetPrefs(*Prefs)
	// RequestEngineStatus polls for an update from the wireguard
	// engine. Only needed if you want to display byte
	// counts. Connection events are emitted automatically without
	// polling.
	RequestEngineStatus()
	// RequestStatus requests that a full Status update
	// notification is sent.
	RequestStatus()
	// FakeExpireAfter pretends that the current key is going to
	// expire after duration x. This is useful for testing GUIs to
	// make sure they react properly with keys that are going to
	// expire.
	FakeExpireAfter(x time.Duration)
}
