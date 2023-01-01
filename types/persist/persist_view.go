// Copyright (c) Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Code generated by tailscale/cmd/viewer; DO NOT EDIT.

package persist

import (
	"encoding/json"
	"errors"

	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
	"tailscale.com/types/structs"
	"tailscale.com/types/views"
)

//go:generate go run tailscale.com/cmd/cloner  -clonefunc=false -type=Persist

// View returns a readonly view of Persist.
func (p *Persist) View() PersistView {
	return PersistView{ж: p}
}

// PersistView provides a read-only view over Persist.
//
// Its methods should only be called if `Valid()` returns true.
type PersistView struct {
	// ж is the underlying mutable value, named with a hard-to-type
	// character that looks pointy like a pointer.
	// It is named distinctively to make you think of how dangerous it is to escape
	// to callers. You must not let callers be able to mutate it.
	ж *Persist
}

// Valid reports whether underlying value is non-nil.
func (v PersistView) Valid() bool { return v.ж != nil }

// AsStruct returns a clone of the underlying value which aliases no memory with
// the original.
func (v PersistView) AsStruct() *Persist {
	if v.ж == nil {
		return nil
	}
	return v.ж.Clone()
}

func (v PersistView) MarshalJSON() ([]byte, error) { return json.Marshal(v.ж) }

func (v *PersistView) UnmarshalJSON(b []byte) error {
	if v.ж != nil {
		return errors.New("already initialized")
	}
	if len(b) == 0 {
		return nil
	}
	var x Persist
	if err := json.Unmarshal(b, &x); err != nil {
		return err
	}
	v.ж = &x
	return nil
}

func (v PersistView) LegacyFrontendPrivateMachineKey() key.MachinePrivate {
	return v.ж.LegacyFrontendPrivateMachineKey
}
func (v PersistView) PrivateNodeKey() key.NodePrivate    { return v.ж.PrivateNodeKey }
func (v PersistView) OldPrivateNodeKey() key.NodePrivate { return v.ж.OldPrivateNodeKey }
func (v PersistView) Provider() string                   { return v.ж.Provider }
func (v PersistView) LoginName() string                  { return v.ж.LoginName }
func (v PersistView) UserProfile() tailcfg.UserProfile   { return v.ж.UserProfile }
func (v PersistView) NetworkLockKey() key.NLPrivate      { return v.ж.NetworkLockKey }
func (v PersistView) NodeID() tailcfg.StableNodeID       { return v.ж.NodeID }
func (v PersistView) DisallowedTKAStateIDs() views.Slice[string] {
	return views.SliceOf(v.ж.DisallowedTKAStateIDs)
}

// A compilation failure here means this code must be regenerated, with the command at the top of this file.
var _PersistViewNeedsRegeneration = Persist(struct {
	_                               structs.Incomparable
	LegacyFrontendPrivateMachineKey key.MachinePrivate
	PrivateNodeKey                  key.NodePrivate
	OldPrivateNodeKey               key.NodePrivate
	Provider                        string
	LoginName                       string
	UserProfile                     tailcfg.UserProfile
	NetworkLockKey                  key.NLPrivate
	NodeID                          tailcfg.StableNodeID
	DisallowedTKAStateIDs           []string
}{})
