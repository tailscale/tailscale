// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package prefs_example contains a [Prefs] type, which is like [tailscale.com/ipn.Prefs],
// but uses the [prefs] package to enhance individual preferences with state and metadata.
//
// It also includes testable examples utilizing the [Prefs] type.
// We made it a separate package to avoid circular dependencies
// and due to limitations in [tailscale.com/cmd/viewer] when
// generating code for test packages.
package prefs_example

import (
	"net/netip"

	jsonv2 "github.com/go-json-experiment/json"
	"github.com/go-json-experiment/json/jsontext"
	"tailscale.com/drive"
	"tailscale.com/tailcfg"
	"tailscale.com/types/opt"
	"tailscale.com/types/persist"
	"tailscale.com/types/prefs"
	"tailscale.com/types/preftype"
)

//go:generate go run tailscale.com/cmd/viewer --type=Prefs,AutoUpdatePrefs,AppConnectorPrefs

// Prefs is like [tailscale.com/ipn.Prefs], but with individual preferences wrapped in
// [prefs.Item], [prefs.List], and [prefs.StructList] to include preference
// state and metadata. Related preferences can be grouped together in a nested
// struct (e.g., [AutoUpdatePrefs] or [AppConnectorPrefs]), whereas each
// individual preference that can be configured by a user or managed via
// syspolicy is wrapped.
//
// Non-preference fields, such as ExitNodePrior and Persist, can be included as-is.
//
// Just like [tailscale.com/ipn.Prefs], [Prefs] is a mutable struct. It should
// only be used in well-defined contexts where mutability is expected and desired,
// such as when the LocalBackend receives a request from the GUI/CLI to change a
// preference, when a preference is managed via syspolicy and needs to be
// configured with an admin-provided value, or when the internal state (e.g.,
// [persist.Persist]) has changed and needs to be preserved.
// In other contexts, a [PrefsView] should be used to provide a read-only view
// of the preferences.
//
// It is recommended to use [jsonv2] for [Prefs] marshaling and unmarshalling to
// improve performance and enable the omission of unconfigured preferences with
// the `omitzero` JSON tag option. This option is not supported by the
// [encoding/json] package as of 2024-08-21; see golang/go#45669.
// It is recommended that a prefs type implements both
// [jsonv2.MarshalerV2]/[jsonv2.UnmarshalerV2] and [json.Marshaler]/[json.Unmarshaler]
// to ensure consistent and more performant marshaling, regardless of the JSON package
// used at the call sites; the standard marshalers can be implemented via [jsonv2].
// See [Prefs.MarshalJSONV2], [Prefs.UnmarshalJSONV2], [Prefs.MarshalJSON],
// and [Prefs.UnmarshalJSON] for an example implementation.
type Prefs struct {
	ControlURL prefs.Item[string]               `json:",omitzero"`
	RouteAll   prefs.Item[bool]                 `json:",omitzero"`
	ExitNodeID prefs.Item[tailcfg.StableNodeID] `json:",omitzero"`
	ExitNodeIP prefs.Item[netip.Addr]           `json:",omitzero"`

	// ExitNodePrior is an internal state rather than a preference.
	// It can be kept in the Prefs structure but should not be wrapped
	// and is ignored by the [prefs] package.
	ExitNodePrior tailcfg.StableNodeID

	ExitNodeAllowLANAccess prefs.Item[bool] `json:",omitzero"`
	CorpDNS                prefs.Item[bool] `json:",omitzero"`
	RunSSH                 prefs.Item[bool] `json:",omitzero"`
	RunWebClient           prefs.Item[bool] `json:",omitzero"`
	WantRunning            prefs.Item[bool] `json:",omitzero"`
	LoggedOut              prefs.Item[bool] `json:",omitzero"`
	ShieldsUp              prefs.Item[bool] `json:",omitzero"`
	// AdvertiseTags is a preference whose value is a slice of strings.
	// The value is atomic, and individual items in the slice should
	// not be modified after the preference is set.
	// Since the item type (string) is immutable, we can use [prefs.List].
	AdvertiseTags prefs.List[string] `json:",omitzero"`
	Hostname      prefs.Item[string] `json:",omitzero"`
	NotepadURLs   prefs.Item[bool]   `json:",omitzero"`
	ForceDaemon   prefs.Item[bool]   `json:",omitzero"`
	Egg           prefs.Item[bool]   `json:",omitzero"`
	// AdvertiseRoutes is a preference whose value is a slice of netip.Prefix.
	// The value is atomic, and individual items in the slice should
	// not be modified after the preference is set.
	// Since the item type (netip.Prefix) is immutable, we can use [prefs.List].
	AdvertiseRoutes     prefs.List[netip.Prefix]           `json:",omitzero"`
	NoSNAT              prefs.Item[bool]                   `json:",omitzero"`
	NoStatefulFiltering prefs.Item[opt.Bool]               `json:",omitzero"`
	NetfilterMode       prefs.Item[preftype.NetfilterMode] `json:",omitzero"`
	OperatorUser        prefs.Item[string]                 `json:",omitzero"`
	ProfileName         prefs.Item[string]                 `json:",omitzero"`

	// AutoUpdate contains auto-update preferences.
	// Each preference in the group can be configured and managed individually.
	AutoUpdate AutoUpdatePrefs `json:",omitzero"`

	// AppConnector contains app connector-related preferences.
	// Each preference in the group can be configured and managed individually.
	AppConnector AppConnectorPrefs `json:",omitzero"`

	PostureChecking prefs.Item[bool]   `json:",omitzero"`
	NetfilterKind   prefs.Item[string] `json:",omitzero"`
	// DriveShares is a preference whose value is a slice of *[drive.Share].
	// The value is atomic, and individual items in the slice should
	// not be modified after the preference is set.
	// Since the item type (*drive.Share) is mutable and implements [views.ViewCloner],
	// we need to use [prefs.StructList] instead of [prefs.List].
	DriveShares      prefs.StructList[*drive.Share]  `json:",omitzero"`
	AllowSingleHosts prefs.Item[marshalAsTrueInJSON] `json:",omitzero"`

	// Persist is an internal state rather than a preference.
	// It can be kept in the Prefs structure but should not be wrapped
	// and is ignored by the [prefs] package.
	Persist *persist.Persist `json:"Config"`
}

// AutoUpdatePrefs is like [ipn.AutoUpdatePrefs], but it wraps individual preferences with [prefs.Item].
// It groups related preferences together while allowing each to be configured individually.
type AutoUpdatePrefs struct {
	Check prefs.Item[bool]     `json:",omitzero"`
	Apply prefs.Item[opt.Bool] `json:",omitzero"`
}

// AppConnectorPrefs is like [ipn.AppConnectorPrefs], but it wraps individual preferences with [prefs.Item].
// It groups related preferences together while allowing each to be configured individually.
type AppConnectorPrefs struct {
	Advertise prefs.Item[bool] `json:",omitzero"`
}

// MarshalJSONV2 implements [jsonv2.MarshalerV2].
// It is implemented as a performance improvement and to enable omission of
// unconfigured preferences from the JSON output. See the [Prefs] doc for details.
func (p Prefs) MarshalJSONV2(out *jsontext.Encoder, opts jsonv2.Options) error {
	// The prefs type shadows the Prefs's method set,
	// causing [jsonv2] to use the default marshaler and avoiding
	// infinite recursion.
	type prefs Prefs
	return jsonv2.MarshalEncode(out, (*prefs)(&p), opts)
}

// UnmarshalJSONV2 implements [jsonv2.UnmarshalerV2].
func (p *Prefs) UnmarshalJSONV2(in *jsontext.Decoder, opts jsonv2.Options) error {
	// The prefs type shadows the Prefs's method set,
	// causing [jsonv2] to use the default unmarshaler and avoiding
	// infinite recursion.
	type prefs Prefs
	return jsonv2.UnmarshalDecode(in, (*prefs)(p), opts)
}

// MarshalJSON implements [json.Marshaler].
func (p Prefs) MarshalJSON() ([]byte, error) {
	return jsonv2.Marshal(p) // uses MarshalJSONV2
}

// UnmarshalJSON implements [json.Unmarshaler].
func (p *Prefs) UnmarshalJSON(b []byte) error {
	return jsonv2.Unmarshal(b, p) // uses UnmarshalJSONV2
}

type marshalAsTrueInJSON struct{}

var trueJSON = []byte("true")

func (marshalAsTrueInJSON) MarshalJSON() ([]byte, error) { return trueJSON, nil }
func (*marshalAsTrueInJSON) UnmarshalJSON([]byte) error  { return nil }
