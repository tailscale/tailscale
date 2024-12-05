// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package controlclient

import (
	"encoding/json"
	"fmt"
	"reflect"

	"tailscale.com/types/netmap"
	"tailscale.com/types/persist"
	"tailscale.com/types/structs"
)

// State is the high-level state of the client. It is used only in
// unit tests for proper sequencing, don't depend on it anywhere else.
//
// TODO(apenwarr): eliminate the state, as it's now obsolete.
//
// apenwarr: Historical note: controlclient.Auto was originally
// intended to be the state machine for the whole tailscale client, but that
// turned out to not be the right abstraction layer, and it moved to
// ipn.Backend. Since ipn.Backend now has a state machine, it would be
// much better if controlclient could be a simple stateless API. But the
// current server-side API (two interlocking polling https calls) makes that
// very hard to implement. A server side API change could untangle this and
// remove all the statefulness.
type State int

const (
	StateNew = State(iota)
	StateNotAuthenticated
	StateAuthenticating
	StateURLVisitRequired
	StateAuthenticated
	StateSynchronized // connected and received map update
)

func (s State) AppendText(b []byte) ([]byte, error) {
	return append(b, s.String()...), nil
}

func (s State) MarshalText() ([]byte, error) {
	return []byte(s.String()), nil
}

func (s State) String() string {
	switch s {
	case StateNew:
		return "state:new"
	case StateNotAuthenticated:
		return "state:not-authenticated"
	case StateAuthenticating:
		return "state:authenticating"
	case StateURLVisitRequired:
		return "state:url-visit-required"
	case StateAuthenticated:
		return "state:authenticated"
	case StateSynchronized:
		return "state:synchronized"
	default:
		return fmt.Sprintf("state:unknown:%d", int(s))
	}
}

type Status struct {
	_ structs.Incomparable

	// Err, if non-nil, is an error that occurred while logging in.
	//
	// If it's of type UserVisibleError then it's meant to be shown to users in
	// their Tailscale client. Otherwise it's just logged to tailscaled's logs.
	Err error

	// URL, if non-empty, is the interactive URL to visit to finish logging in.
	URL string

	// NetMap is the latest server-pushed state of the tailnet network.
	NetMap *netmap.NetworkMap

	// Persist, when Valid, is the locally persisted configuration.
	//
	// TODO(bradfitz,maisem): clarify this.
	Persist persist.PersistView

	// state is the internal state. It should not be exposed outside this
	// package, but we have some automated tests elsewhere that need to
	// use it via the StateForTest accessor.
	// TODO(apenwarr): Unexport or remove these.
	state State
}

// LoginFinished reports whether the controlclient is in its "StateAuthenticated"
// state where it's in a happy register state but not yet in a map poll.
//
// TODO(bradfitz): delete this and everything around Status.state.
func (s *Status) LoginFinished() bool { return s.state == StateAuthenticated }

// StateForTest returns the internal state of s for tests only.
func (s *Status) StateForTest() State { return s.state }

// SetStateForTest sets the internal state of s for tests only.
func (s *Status) SetStateForTest(state State) { s.state = state }

// Equal reports whether s and s2 are equal.
func (s *Status) Equal(s2 *Status) bool {
	if s == nil && s2 == nil {
		return true
	}
	return s != nil && s2 != nil &&
		s.Err == s2.Err &&
		s.URL == s2.URL &&
		s.state == s2.state &&
		reflect.DeepEqual(s.Persist, s2.Persist) &&
		reflect.DeepEqual(s.NetMap, s2.NetMap)
}

func (s Status) String() string {
	b, err := json.MarshalIndent(s, "", "\t")
	if err != nil {
		panic(err)
	}
	return s.state.String() + " " + string(b)
}
