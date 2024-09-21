// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package setting

import (
	"encoding"
)

// PreferenceOption is a policy that governs whether a boolean variable
// is forcibly assigned an administrator-defined value, or allowed to receive
// a user-defined value.
type PreferenceOption byte

const (
	ShowChoiceByPolicy PreferenceOption = iota
	NeverByPolicy
	AlwaysByPolicy
)

// Show returns if the UI option that controls the choice administered by this
// policy should be shown. Currently this is true if and only if the policy is
// [ShowChoiceByPolicy].
func (p PreferenceOption) Show() bool {
	return p == ShowChoiceByPolicy
}

// ShouldEnable checks if the choice administered by this policy should be
// enabled. If the administrator has chosen a setting, the administrator's
// setting is returned, otherwise userChoice is returned.
func (p PreferenceOption) ShouldEnable(userChoice bool) bool {
	switch p {
	case NeverByPolicy:
		return false
	case AlwaysByPolicy:
		return true
	default:
		return userChoice
	}
}

// IsAlways reports whether the preference should always be enabled.
func (p PreferenceOption) IsAlways() bool {
	return p == AlwaysByPolicy
}

// IsNever reports whether the preference should always be disabled.
func (p PreferenceOption) IsNever() bool {
	return p == NeverByPolicy
}

// WillOverride checks if the choice administered by the policy is different
// from the user's choice.
func (p PreferenceOption) WillOverride(userChoice bool) bool {
	return p.ShouldEnable(userChoice) != userChoice
}

// String returns a string representation of p.
func (p PreferenceOption) String() string {
	switch p {
	case AlwaysByPolicy:
		return "always"
	case NeverByPolicy:
		return "never"
	default:
		return "user-decides"
	}
}

// MarshalText implements [encoding.TextMarshaler].
func (p *PreferenceOption) MarshalText() (text []byte, err error) {
	return []byte(p.String()), nil
}

// UnmarshalText implements [encoding.TextUnmarshaler].
// It never fails and sets p to [ShowChoiceByPolicy] if the specified text
// does not represent a valid [PreferenceOption].
func (p *PreferenceOption) UnmarshalText(text []byte) error {
	switch string(text) {
	case "always":
		*p = AlwaysByPolicy
	case "never":
		*p = NeverByPolicy
	default:
		*p = ShowChoiceByPolicy
	}
	return nil
}

// Visibility is a policy that controls whether or not a particular
// component of a user interface is to be shown.
type Visibility byte

var (
	_ encoding.TextMarshaler   = (*Visibility)(nil)
	_ encoding.TextUnmarshaler = (*Visibility)(nil)
)

const (
	VisibleByPolicy Visibility = 'v'
	HiddenByPolicy  Visibility = 'h'
)

// Show reports whether the UI option administered by this policy should be shown.
// Currently this is true if the policy is not [hiddenByPolicy].
func (v Visibility) Show() bool {
	return v != HiddenByPolicy
}

// String returns a string representation of v.
func (v Visibility) String() string {
	switch v {
	case 'h':
		return "hide"
	default:
		return "show"
	}
}

// MarshalText implements [encoding.TextMarshaler].
func (v Visibility) MarshalText() (text []byte, err error) {
	return []byte(v.String()), nil
}

// UnmarshalText implements [encoding.TextUnmarshaler].
// It never fails and sets v to [VisibleByPolicy] if the specified text
// does not represent a valid [Visibility].
func (v *Visibility) UnmarshalText(text []byte) error {
	switch string(text) {
	case "hide":
		*v = HiddenByPolicy
	default:
		*v = VisibleByPolicy
	}
	return nil
}
