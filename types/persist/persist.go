// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package persist contains the Persist type.
package persist

import (
	"fmt"

	"tailscale.com/types/key"
	"tailscale.com/types/structs"
)

//go:generate go run tailscale.com/cmd/cloner -type=Persist

// Persist is the JSON type stored on disk on nodes to remember their
// settings between runs.
type Persist struct {
	_ structs.Incomparable

	// LegacyFrontendPrivateMachineKey is here temporarily
	// (starting 2020-09-28) during migration of Windows users'
	// machine keys from frontend storage to the backend. On the
	// first LocalBackend.Start call, the backend will initialize
	// the real (backend-owned) machine key from the frontend's
	// provided value (if non-zero), picking a new random one if
	// needed. This field should be considered read-only from GUI
	// frontends. The real value should not be written back in
	// this field, lest the frontend persist it to disk.
	LegacyFrontendPrivateMachineKey key.MachinePrivate `json:"PrivateMachineKey"`

	PrivateNodeKey    key.NodePrivate
	OldPrivateNodeKey key.NodePrivate // needed to request key rotation
	Provider          string
	LoginName         string
}

func (p *Persist) Equals(p2 *Persist) bool {
	if p == nil && p2 == nil {
		return true
	}
	if p == nil || p2 == nil {
		return false
	}

	return p.LegacyFrontendPrivateMachineKey.Equal(p2.LegacyFrontendPrivateMachineKey) &&
		p.PrivateNodeKey.Equal(p2.PrivateNodeKey) &&
		p.OldPrivateNodeKey.Equal(p2.OldPrivateNodeKey) &&
		p.Provider == p2.Provider &&
		p.LoginName == p2.LoginName
}

func (p *Persist) Pretty() string {
	var (
		mk     key.MachinePublic
		ok, nk key.NodePublic
	)
	if !p.LegacyFrontendPrivateMachineKey.IsZero() {
		mk = p.LegacyFrontendPrivateMachineKey.Public()
	}
	if !p.OldPrivateNodeKey.IsZero() {
		ok = p.OldPrivateNodeKey.Public()
	}
	if !p.PrivateNodeKey.IsZero() {
		nk = p.PrivateNodeKey.Public()
	}
	return fmt.Sprintf("Persist{lm=%v, o=%v, n=%v u=%#v}",
		mk.ShortString(), ok.ShortString(), nk.ShortString(), p.LoginName)
}
