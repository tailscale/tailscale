// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ipn

import (
	"fmt"
	"strings"
	"time"

	"tailscale.com/ipn/ipnstate"
	"tailscale.com/tailcfg"
	"tailscale.com/types/empty"
	"tailscale.com/types/key"
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
	LivePeers      map[key.NodePublic]ipnstate.PeerStatusLite
}

// Notify is a communication from a backend (e.g. tailscaled) to a frontend
// (cmd/tailscale, iOS, macOS, Win Tasktray).
// In any given notification, any or all of these may be nil, meaning
// that they have not changed.
// They are JSON-encoded on the wire, despite the lack of struct tags.
type Notify struct {
	_       structs.Incomparable
	Version string // version number of IPN backend

	// ErrMessage, if non-nil, contains a critical error message.
	// For State InUseOtherUser, ErrMessage is not critical and just contains the details.
	ErrMessage *string

	LoginFinished *empty.Message     // non-nil when/if the login process succeeded
	State         *State             // if non-nil, the new or current IPN state
	Prefs         *Prefs             // if non-nil, the new or current preferences
	NetMap        *netmap.NetworkMap // if non-nil, the new or current netmap
	Engine        *EngineStatus      // if non-nil, the new or current wireguard stats
	BrowseToURL   *string            // if non-nil, UI should open a browser right now
	BackendLogID  *string            // if non-nil, the public logtail ID used by backend

	// FilesWaiting if non-nil means that files are buffered in
	// the Tailscale daemon and ready for local transfer to the
	// user's preferred storage location.
	FilesWaiting *empty.Message `json:",omitempty"`

	// IncomingFiles, if non-nil, specifies which files are in the
	// process of being received. A nil IncomingFiles means this
	// Notify should not update the state of file transfers. A non-nil
	// but empty IncomingFiles means that no files are in the middle
	// of being transferred.
	IncomingFiles []PartialFile `json:",omitempty"`

	// LocalTCPPort, if non-nil, informs the UI frontend which
	// (non-zero) localhost TCP port it's listening on.
	// This is currently only used by Tailscale when run in the
	// macOS Network Extension.
	LocalTCPPort *uint16 `json:",omitempty"`

	// type is mirrored in xcode/Shared/IPN.swift
}

func (n Notify) String() string {
	var sb strings.Builder
	sb.WriteString("Notify{")
	if n.ErrMessage != nil {
		fmt.Fprintf(&sb, "err=%q ", *n.ErrMessage)
	}
	if n.LoginFinished != nil {
		sb.WriteString("LoginFinished ")
	}
	if n.State != nil {
		fmt.Fprintf(&sb, "state=%v ", *n.State)
	}
	if n.Prefs != nil {
		fmt.Fprintf(&sb, "%v ", n.Prefs.Pretty())
	}
	if n.NetMap != nil {
		sb.WriteString("NetMap{...} ")
	}
	if n.Engine != nil {
		fmt.Fprintf(&sb, "wg=%v ", *n.Engine)
	}
	if n.BrowseToURL != nil {
		sb.WriteString("URL=<...> ")
	}
	if n.BackendLogID != nil {
		sb.WriteString("BackendLogID ")
	}
	if n.FilesWaiting != nil {
		sb.WriteString("FilesWaiting ")
	}
	if len(n.IncomingFiles) != 0 {
		sb.WriteString("IncomingFiles ")
	}
	if n.LocalTCPPort != nil {
		fmt.Fprintf(&sb, "tcpport=%v ", n.LocalTCPPort)
	}
	s := sb.String()
	return s[0:len(s)-1] + "}"
}

// PartialFile represents an in-progress file transfer.
type PartialFile struct {
	Name         string    // e.g. "foo.jpg"
	Started      time.Time // time transfer started
	DeclaredSize int64     // or -1 if unknown
	Received     int64     // bytes copied thus far

	// PartialPath is set non-empty in "direct" file mode to the
	// in-progress '*.partial' file's path when the peerapi isn't
	// being used; see LocalBackend.SetDirectFileRoot.
	PartialPath string `json:",omitempty"`

	// Done is set in "direct" mode when the partial file has been
	// closed and is ready for the caller to rename away the
	// ".partial" suffix.
	Done bool `json:",omitempty"`
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
//   - the macOS/iOS GUI apps set it to "ipn-go-bridge"
//   - the Android app sets it to "ipn-android"
//   - on Windows, it's the empty string (in client mode) or, via
//     LocalBackend.userID, a string like "user-$USER_ID" (used in
//     server mode).
//   - on Linux/etc, it's always "_daemon" (ipn.GlobalDaemonStateKey)
//
// Additionally, the StateKey can be debug setting name:
//
//   - "_debug_magicsock_until" with value being a unix timestamp stringified
//   - "_debug_<component>_until" with value being a unix timestamp stringified
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
	//
	// NOTE(apenwarr): The above means that this Prefs field does not do
	// what you probably think it does. It will overwrite your encryption
	// keys. Do not use unless you know what you're doing.
	StateKey StateKey
	Prefs    *Prefs
	// UpdatePrefs, if provided, overrides Options.Prefs *and* the Prefs
	// already stored in the backend state, *except* for the Persist
	// Persist member. If you just want to provide prefs, this is
	// probably what you want.
	//
	// UpdatePrefs.Persist is always ignored. Prefs.Persist will still
	// be used even if UpdatePrefs is provided. Other than Persist,
	// UpdatePrefs takes precedence over Prefs.
	//
	// This is intended as a purely temporary workaround for the
	// currently unexpected behaviour of Options.Prefs.
	//
	// TODO(apenwarr): Remove this, or rename Prefs to something else
	//   and rename this to Prefs. Or, move Prefs.Persist elsewhere
	//   entirely (as it always should have been), and then we wouldn't
	//   need two separate fields at all. Or, move the fancy state
	//   migration stuff out of Start().
	UpdatePrefs *Prefs
	// AuthKey is an optional node auth key used to authorize a
	// new node key without user interaction.
	AuthKey string
}

// Backend is the interface between Tailscale frontends
// (e.g. cmd/tailscale, iOS/MacOS/Windows GUIs) and the tailscale
// backend (e.g. cmd/tailscaled) running on the same machine.
// (It has nothing to do with the interface between the backends
// and the cloud control plane.)
type Backend interface {
	// SetNotifyCallback sets the callback to be called on updates
	// from the backend to the client.
	SetNotifyCallback(func(Notify))
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
	// RequestEngineStatus polls for an update from the wireguard
	// engine. Only needed if you want to display byte
	// counts. Connection events are emitted automatically without
	// polling.
	RequestEngineStatus()
}
