// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ipn

import (
	"net/http"
	"time"

	"tailscale.com/ipn/ipnstate"
	"tailscale.com/tailcfg"
	"tailscale.com/types/empty"
	"tailscale.com/types/netmap"
	"tailscale.com/types/structs"
)

type State int

const (
	NoState = State(iota)
	InUseOtherUser
	NeedsLogin
	NeedsMachineAuth
	Stopped
	Starting
	Running
)

// GoogleIDToken Type is the tailcfg.Oauth2Token.TokenType for the Google
// ID tokens used by the Android client.
const GoogleIDTokenType = "ts_android_google_login"

func (s State) String() string {
	return [...]string{
		"NoState",
		"InUseOtherUser",
		"NeedsLogin",
		"NeedsMachineAuth",
		"Stopped",
		"Starting",
		"Running"}[s]
}

// EngineStatus contains WireGuard engine stats.
type EngineStatus struct {
	RBytes, WBytes int64
	NumLive        int
	LiveDERPs      int // number of active DERP connections
	LivePeers      map[tailcfg.NodeKey]ipnstate.PeerStatusLite
}

// Notify is a communication from a backend (e.g. tailscaled) to a frontend
// (cmd/tailscale, iOS, macOS, Win Tasktray).
// In any given notification, any or all of these may be nil, meaning
// that they have not changed.
// They are JSON-encoded on the wire, despite the lack of struct tags.
type Notify struct {
	_             structs.Incomparable
	Version       string             // version number of IPN backend
	ErrMessage    *string            // critical error message, if any; for InUseOtherUser, the details
	LoginFinished *empty.Message     // event: non-nil when login process succeeded
	State         *State             // current IPN state has changed
	Prefs         *Prefs             // preferences were changed
	NetMap        *netmap.NetworkMap // new netmap received
	Engine        *EngineStatus      // wireguard engine stats
	BrowseToURL   *string            // UI should open a browser right now
	BackendLogID  *string            // public logtail id used by backend
	PingResult    *ipnstate.PingResult

	FilesWaiting *empty.Message `json:",omitempty"`

	// LocalTCPPort, if non-nil, informs the UI frontend which
	// (non-zero) localhost TCP port it's listening on.
	// This is currently only used by Tailscale when run in the
	// macOS Network Extension.
	LocalTCPPort *uint16 `json:",omitempty"`

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
// Various platforms currently set StateKey in different ways:
//
// * the macOS/iOS GUI apps set it to "ipn-go-bridge"
// * the Android app sets it to "ipn-android"
// * on Windows, it's the empty string (in client mode) or, via
//   LocalBackend.userID, a string like "user-$USER_ID" (used in
//   server mode).
// * on Linux/etc, it's always "_daemon" (ipn.GlobalDaemonStateKey)
type StateKey string

type Options struct {
	// FrontendLogID is the public logtail id used by the frontend.
	FrontendLogID string
	// StateKey and Prefs together define the state the backend should
	// use:
	//  - StateKey=="" && Prefs!=nil: use Prefs for internal state,
	//    don't persist changes in the backend, except for the machine key
	//    for migration purposes.
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
	// Login logs in with an OAuth2 token.
	Login(token *tailcfg.Oauth2Token)
	// Logout terminates the current login session and stops the
	// wireguard engine.
	Logout()
	// SetPrefs installs a new set of user preferences, including
	// WantRunning. This may cause the wireguard engine to
	// reconfigure or stop.
	SetPrefs(*Prefs)
	// EditPrefs is like SetPrefs but only sets the specified fields.
	EditPrefs(*MaskedPrefs)
	// RequestEngineStatus polls for an update from the wireguard
	// engine. Only needed if you want to display byte
	// counts. Connection events are emitted automatically without
	// polling.
	RequestEngineStatus()
	// FakeExpireAfter pretends that the current key is going to
	// expire after duration x. This is useful for testing GUIs to
	// make sure they react properly with keys that are going to
	// expire.
	FakeExpireAfter(x time.Duration)
	// Ping attempts to start connecting to the given IP and sends a Notify
	// with its PingResult. If the host is down, there might never
	// be a PingResult sent. The cmd/tailscale CLI client adds a timeout.
	Ping(ip string, useTSMP bool)
}
