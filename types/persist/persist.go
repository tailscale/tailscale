// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package persist contains the Persist type.
package persist

import (
	"fmt"
	"reflect"

	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
	"tailscale.com/types/structs"
)

//go:generate go run tailscale.com/cmd/viewer -type=Persist

// Persist is the JSON type stored on disk on nodes to remember their
// settings between runs. This is stored as part of ipn.Prefs and is
// persisted per ipn.LoginProfile.
type Persist struct {
	_ structs.Incomparable

	PrivateNodeKey    key.NodePrivate
	OldPrivateNodeKey key.NodePrivate // needed to request key rotation
	UserProfile       tailcfg.UserProfile
	NetworkLockKey    key.NLPrivate
	NodeID            tailcfg.StableNodeID
	AttestationKey    key.HardwareAttestationKey `json:",omitempty"`

	// DisallowedTKAStateIDs stores the tka.State.StateID values which
	// this node will not operate network lock on. This is used to
	// prevent bootstrapping TKA onto a key authority which was forcibly
	// disabled.
	DisallowedTKAStateIDs []string `json:",omitempty"`
}

// PublicNodeKey returns the public key for the node key.
func (p *Persist) PublicNodeKey() key.NodePublic {
	return p.PrivateNodeKey.Public()
}

// PublicNodeKeyOK returns the public key for the node key.
//
// Unlike PublicNodeKey, it returns ok=false if there is no node private key
// instead of panicking.
func (p *Persist) PublicNodeKeyOK() (pub key.NodePublic, ok bool) {
	if p.PrivateNodeKey.IsZero() {
		return
	}
	return p.PrivateNodeKey.Public(), true
}

// PublicNodeKey returns the public key for the node key.
//
// It panics if there is no node private key. See PublicNodeKeyOK.
func (p PersistView) PublicNodeKey() key.NodePublic {
	return p.ж.PublicNodeKey()
}

// PublicNodeKeyOK returns the public key for the node key.
//
// Unlike PublicNodeKey, it returns ok=false if there is no node private key
// instead of panicking.
func (p PersistView) PublicNodeKeyOK() (_ key.NodePublic, ok bool) {
	return p.ж.PublicNodeKeyOK()
}

func (p PersistView) Equals(p2 PersistView) bool {
	return p.ж.Equals(p2.ж)
}

func nilIfEmpty[E any](s []E) []E {
	if len(s) == 0 {
		return nil
	}
	return s
}

func (p *Persist) Equals(p2 *Persist) bool {
	if p == nil && p2 == nil {
		return true
	}
	if p == nil || p2 == nil {
		return false
	}

	var pub, p2Pub key.HardwareAttestationPublic
	if p.AttestationKey != nil && !p.AttestationKey.IsZero() {
		pub = key.HardwareAttestationPublicFromPlatformKey(p.AttestationKey)
	}
	if p2.AttestationKey != nil && !p2.AttestationKey.IsZero() {
		p2Pub = key.HardwareAttestationPublicFromPlatformKey(p2.AttestationKey)
	}

	return p.PrivateNodeKey.Equal(p2.PrivateNodeKey) &&
		p.OldPrivateNodeKey.Equal(p2.OldPrivateNodeKey) &&
		p.UserProfile.Equal(&p2.UserProfile) &&
		p.NetworkLockKey.Equal(p2.NetworkLockKey) &&
		p.NodeID == p2.NodeID &&
		pub.Equal(p2Pub) &&
		reflect.DeepEqual(nilIfEmpty(p.DisallowedTKAStateIDs), nilIfEmpty(p2.DisallowedTKAStateIDs))
}

func (p *Persist) Pretty() string {
	var (
		ok, nk key.NodePublic
	)
	akString := "-"
	if !p.OldPrivateNodeKey.IsZero() {
		ok = p.OldPrivateNodeKey.Public()
	}
	if !p.PrivateNodeKey.IsZero() {
		nk = p.PublicNodeKey()
	}
	if p.AttestationKey != nil && !p.AttestationKey.IsZero() {
		akString = fmt.Sprintf("%v", p.AttestationKey.Public())
	}
	return fmt.Sprintf("Persist{o=%v, n=%v u=%#v ak=%s}",
		ok.ShortString(), nk.ShortString(), p.UserProfile.LoginName, akString)
}
