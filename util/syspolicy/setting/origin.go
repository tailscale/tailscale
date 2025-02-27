// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package setting

import (
	"fmt"

	jsonv2 "github.com/go-json-experiment/json"
	"github.com/go-json-experiment/json/jsontext"
)

// Origin describes where a policy or a policy setting is configured.
type Origin struct {
	data settingOrigin
}

// settingOrigin is the marshallable data of an [Origin].
type settingOrigin struct {
	Name  string `json:",omitzero"`
	Scope PolicyScope
}

// NewOrigin returns a new [Origin] with the specified scope.
func NewOrigin(scope PolicyScope) *Origin {
	return NewNamedOrigin("", scope)
}

// NewNamedOrigin returns a new [Origin] with the specified scope and name.
func NewNamedOrigin(name string, scope PolicyScope) *Origin {
	return &Origin{settingOrigin{name, scope}}
}

// Scope reports the policy [PolicyScope] where the setting is configured.
func (s Origin) Scope() PolicyScope {
	return s.data.Scope
}

// Name returns the name of the policy source where the setting is configured,
// or "" if not available.
func (s Origin) Name() string {
	return s.data.Name
}

// String implements [fmt.Stringer].
func (s Origin) String() string {
	if s.Name() != "" {
		return fmt.Sprintf("%s (%v)", s.Name(), s.Scope())
	}
	return s.Scope().String()
}

var (
	_ jsonv2.MarshalerTo     = (*Origin)(nil)
	_ jsonv2.UnmarshalerFrom = (*Origin)(nil)
)

// MarshalJSONTo implements [jsonv2.MarshalerTo].
func (s Origin) MarshalJSONTo(out *jsontext.Encoder) error {
	return jsonv2.MarshalEncode(out, &s.data)
}

// UnmarshalJSONFrom implements [jsonv2.UnmarshalerFrom].
func (s *Origin) UnmarshalJSONFrom(in *jsontext.Decoder) error {
	return jsonv2.UnmarshalDecode(in, &s.data)
}

// MarshalJSON implements [json.Marshaler].
func (s Origin) MarshalJSON() ([]byte, error) {
	return jsonv2.Marshal(s) // uses MarshalJSONTo
}

// UnmarshalJSON implements [json.Unmarshaler].
func (s *Origin) UnmarshalJSON(b []byte) error {
	return jsonv2.Unmarshal(b, s) // uses UnmarshalJSONFrom
}
