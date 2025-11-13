// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package controlclient

import (
	"reflect"

	"tailscale.com/types/netmap"
	"tailscale.com/types/persist"
	"tailscale.com/types/structs"
)

type Status struct {
	_ structs.Incomparable

	// Err, if non-nil, is an error that occurred while logging in.
	//
	// If it's of type UserVisibleError then it's meant to be shown to users in
	// their Tailscale client. Otherwise it's just logged to tailscaled's logs.
	Err error

	// URL, if non-empty, is the interactive URL to visit to finish logging in.
	URL string

	// LoggedIn, if true, indicates that serveRegister has completed and no
	// other login change is in progress.
	LoggedIn bool

	// InMapPoll, if true, indicates that we've received at least one netmap
	// and are connected to receive updates.
	InMapPoll bool

	// NetMap is the latest server-pushed state of the tailnet network.
	NetMap *netmap.NetworkMap

	// Persist, when Valid, is the locally persisted configuration.
	//
	// TODO(bradfitz,maisem): clarify this.
	Persist persist.PersistView
}

// Equal reports whether s and s2 are equal.
func (s *Status) Equal(s2 *Status) bool {
	if s == nil && s2 == nil {
		return true
	}
	return s != nil && s2 != nil &&
		s.Err == s2.Err &&
		s.URL == s2.URL &&
		s.LoggedIn == s2.LoggedIn &&
		s.InMapPoll == s2.InMapPoll &&
		reflect.DeepEqual(s.Persist, s2.Persist) &&
		reflect.DeepEqual(s.NetMap, s2.NetMap)
}
