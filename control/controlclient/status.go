// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package controlclient

import (
	"encoding/json"
	"fmt"
	"reflect"

	"tailscale.com/types/empty"
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
	_              structs.Incomparable
	LoginFinished  *empty.Message // nonempty when login finishes
	LogoutFinished *empty.Message // nonempty when logout finishes
	Err            error
	URL            string             // interactive URL to visit to finish logging in
	NetMap         *netmap.NetworkMap // server-pushed configuration

	// The internal state should not be exposed outside this
	// package, but we have some automated tests elsewhere that need to
	// use them. Please don't use these fields.
	// TODO(apenwarr): Unexport or remove these.
	State   State
	Persist *persist.PersistView // locally persisted configuration
}

// Equal reports whether s and s2 are equal.
func (s *Status) Equal(s2 *Status) bool {
	if s == nil && s2 == nil {
		return true
	}
	return s != nil && s2 != nil &&
		(s.LoginFinished == nil) == (s2.LoginFinished == nil) &&
		(s.LogoutFinished == nil) == (s2.LogoutFinished == nil) &&
		s.Err == s2.Err &&
		s.URL == s2.URL &&
		reflect.DeepEqual(s.Persist, s2.Persist) &&
		reflect.DeepEqual(s.NetMap, s2.NetMap) &&
		s.State == s2.State
}

func (s Status) String() string {
	b, err := json.MarshalIndent(s, "", "\t")
	if err != nil {
		panic(err)
	}
	return s.State.String() + " " + string(b)
}
