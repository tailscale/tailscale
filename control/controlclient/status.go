// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package controlclient

import (
	"encoding/json"
	"fmt"
	"reflect"

	"tailscale.com/tailcfg"
	"tailscale.com/types/empty"
	"tailscale.com/types/netmap"
	"tailscale.com/types/persist"
	"tailscale.com/types/structs"
)

// State is the high-level state of the client. It is used only in
// unit tests for proper sequencing, don't depend on it anywhere else.
// TODO(apenwarr): eliminate 'state', as it's now obsolete.
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
	_             structs.Incomparable
	LoginFinished *empty.Message
	Err           string
	URL           string
	Persist       *persist.Persist   // locally persisted configuration
	NetMap        *netmap.NetworkMap // server-pushed configuration
	Hostinfo      *tailcfg.Hostinfo  // current Hostinfo data
	State         State
}

// Equal reports whether s and s2 are equal.
func (s *Status) Equal(s2 *Status) bool {
	if s == nil && s2 == nil {
		return true
	}
	return s != nil && s2 != nil &&
		(s.LoginFinished == nil) == (s2.LoginFinished == nil) &&
		s.Err == s2.Err &&
		s.URL == s2.URL &&
		reflect.DeepEqual(s.Persist, s2.Persist) &&
		reflect.DeepEqual(s.NetMap, s2.NetMap) &&
		reflect.DeepEqual(s.Hostinfo, s2.Hostinfo) &&
		s.State == s2.State
}

func (s Status) String() string {
	b, err := json.MarshalIndent(s, "", "\t")
	if err != nil {
		panic(err)
	}
	return s.State.String() + " " + string(b)
}
