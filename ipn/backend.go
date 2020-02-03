// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ipn

import (
	"time"

	"tailscale.com/control/controlclient"
	"tailscale.com/tailcfg"
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

type EngineStatus struct {
	RBytes, WBytes wgengine.ByteCount
	NumLive        int
	LivePeers      map[tailcfg.NodeKey]wgengine.PeerStatus
}

type NetworkMap = controlclient.NetworkMap

// In any given notification, any or all of these may be nil, meaning
// that they have not changed.
type Notify struct {
	Version       string        // version number of IPN backend
	ErrMessage    *string       // critical error message, if any
	LoginFinished *struct{}     // event: login process succeeded
	State         *State        // current IPN state has changed
	Prefs         *Prefs        // preferences were changed
	NetMap        *NetworkMap   // new netmap received
	Engine        *EngineStatus // wireguard engine stats
	BrowseToURL   *string       // UI should open a browser right now
	BackendLogID  *string       // public logtail id used by backend
}

type Options struct {
	FrontendLogID string // public logtail id used by frontend
	ServerURL     string
	Prefs         *Prefs
	Notify        func(n Notify) `json:"-"`
}

type Backend interface {
	// Start or restart the backend, because a new Handle has connected.
	Start(opts Options) error
	// Start a new interactive login. This should trigger a new
	// BrowseToURL notification eventually.
	StartLoginInteractive()
	// Terminate the current login session and stop the wireguard engine.
	Logout()
	// Install a new set of user preferences, including WantRunning.
	// This may cause the wireguard engine to reconfigure or stop.
	SetPrefs(new Prefs)
	// Poll for an update from the wireguard engine. Only needed if
	// you want to display byte counts. Connection events are emitted
	// automatically without polling.
	RequestEngineStatus()
	// Pretend the current key is going to expire after duration x.
	// This is useful for testing GUIs to make sure they react properly
	// with keys that are going to expire.
	FakeExpireAfter(x time.Duration)
}
