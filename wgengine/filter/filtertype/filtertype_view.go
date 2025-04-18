// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Code generated by tailscale/cmd/viewer; DO NOT EDIT.

package filtertype

import (
	"encoding/json"
	"errors"
	"net/netip"

	"tailscale.com/tailcfg"
	"tailscale.com/types/ipproto"
	"tailscale.com/types/views"
)

//go:generate go run tailscale.com/cmd/cloner  -clonefunc=false -type=Match,CapMatch

// View returns a read-only view of Match.
func (p *Match) View() MatchView {
	return MatchView{ж: p}
}

// MatchView provides a read-only view over Match.
//
// Its methods should only be called if `Valid()` returns true.
type MatchView struct {
	// ж is the underlying mutable value, named with a hard-to-type
	// character that looks pointy like a pointer.
	// It is named distinctively to make you think of how dangerous it is to escape
	// to callers. You must not let callers be able to mutate it.
	ж *Match
}

// Valid reports whether v's underlying value is non-nil.
func (v MatchView) Valid() bool { return v.ж != nil }

// AsStruct returns a clone of the underlying value which aliases no memory with
// the original.
func (v MatchView) AsStruct() *Match {
	if v.ж == nil {
		return nil
	}
	return v.ж.Clone()
}

func (v MatchView) MarshalJSON() ([]byte, error) { return json.Marshal(v.ж) }

func (v *MatchView) UnmarshalJSON(b []byte) error {
	if v.ж != nil {
		return errors.New("already initialized")
	}
	if len(b) == 0 {
		return nil
	}
	var x Match
	if err := json.Unmarshal(b, &x); err != nil {
		return err
	}
	v.ж = &x
	return nil
}

func (v MatchView) IPProto() views.Slice[ipproto.Proto]          { return v.ж.IPProto }
func (v MatchView) Srcs() views.Slice[netip.Prefix]              { return views.SliceOf(v.ж.Srcs) }
func (v MatchView) SrcsContains() func(netip.Addr) bool          { return v.ж.SrcsContains }
func (v MatchView) SrcCaps() views.Slice[tailcfg.NodeCapability] { return views.SliceOf(v.ж.SrcCaps) }
func (v MatchView) Dsts() views.Slice[NetPortRange]              { return views.SliceOf(v.ж.Dsts) }
func (v MatchView) Caps() views.ValueSliceView[CapMatch, *CapMatch, CapMatchView] {
	return views.SliceOfValueViews[CapMatch, *CapMatch](v.ж.Caps)
}
func (v MatchView) String() string { return v.ж.String() }

// A compilation failure here means this code must be regenerated, with the command at the top of this file.
var _MatchViewNeedsRegeneration = Match(struct {
	IPProto      views.Slice[ipproto.Proto]
	Srcs         []netip.Prefix
	SrcsContains func(netip.Addr) bool
	SrcCaps      []tailcfg.NodeCapability
	Dsts         []NetPortRange
	Caps         []CapMatch
}{})

// View returns a read-only view of CapMatch.
func (p *CapMatch) View() CapMatchView {
	return CapMatchView{ж: p}
}

// CapMatchView provides a read-only view over CapMatch.
//
// Its methods should only be called if `Valid()` returns true.
type CapMatchView struct {
	// ж is the underlying mutable value, named with a hard-to-type
	// character that looks pointy like a pointer.
	// It is named distinctively to make you think of how dangerous it is to escape
	// to callers. You must not let callers be able to mutate it.
	ж *CapMatch
}

// Valid reports whether v's underlying value is non-nil.
func (v CapMatchView) Valid() bool { return v.ж != nil }

// AsStruct returns a clone of the underlying value which aliases no memory with
// the original.
func (v CapMatchView) AsStruct() *CapMatch {
	if v.ж == nil {
		return nil
	}
	return v.ж.Clone()
}

func (v CapMatchView) MarshalJSON() ([]byte, error) { return json.Marshal(v.ж) }

func (v *CapMatchView) UnmarshalJSON(b []byte) error {
	if v.ж != nil {
		return errors.New("already initialized")
	}
	if len(b) == 0 {
		return nil
	}
	var x CapMatch
	if err := json.Unmarshal(b, &x); err != nil {
		return err
	}
	v.ж = &x
	return nil
}

func (v CapMatchView) Dst() netip.Prefix                       { return v.ж.Dst }
func (v CapMatchView) Cap() tailcfg.PeerCapability             { return v.ж.Cap }
func (v CapMatchView) Values() views.Slice[tailcfg.RawMessage] { return views.SliceOf(v.ж.Values) }

// A compilation failure here means this code must be regenerated, with the command at the top of this file.
var _CapMatchViewNeedsRegeneration = CapMatch(struct {
	Dst    netip.Prefix
	Cap    tailcfg.PeerCapability
	Values []tailcfg.RawMessage
}{})
