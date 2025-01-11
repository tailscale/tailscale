// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package setting contains types for defining and representing policy settings.
// It facilitates the registration of setting definitions using [Register] and [RegisterDefinition],
// and the retrieval of registered setting definitions via [Definitions] and [DefinitionOf].
// This package is intended for use primarily within the syspolicy package hierarchy.
package setting

import (
	"fmt"
	"strings"
)

// Scope indicates the broadest scope at which a policy setting may apply,
// and the narrowest scope at which it may be configured.
type Scope int8

const (
	// DeviceSetting indicates a policy setting that applies to a device, regardless of
	// which OS user or Tailscale profile is currently active, if any.
	// It can only be configured at a [DeviceScope].
	DeviceSetting Scope = iota
	// ProfileSetting indicates a policy setting that applies to a Tailscale profile.
	// It can only be configured for a specific profile or at a [DeviceScope],
	// in which case it applies to all profiles on the device.
	ProfileSetting
	// UserSetting indicates a policy setting that applies to users.
	// It can be configured for a user, profile, or the entire device.
	UserSetting

	// NumScopes is the number of possible [Scope] values.
	NumScopes int = iota // must be the last value in the const block.
)

// String implements [fmt.Stringer].
func (s Scope) String() string {
	switch s {
	case DeviceSetting:
		return "Device"
	case ProfileSetting:
		return "Profile"
	case UserSetting:
		return "User"
	default:
		panic("unreachable")
	}
}

// MarshalText implements [encoding.TextMarshaler].
func (s Scope) MarshalText() (text []byte, err error) {
	return []byte(s.String()), nil
}

// UnmarshalText implements [encoding.TextUnmarshaler].
func (s *Scope) UnmarshalText(text []byte) error {
	switch strings.ToLower(string(text)) {
	case "device":
		*s = DeviceSetting
	case "profile":
		*s = ProfileSetting
	case "user":
		*s = UserSetting
	default:
		return fmt.Errorf("%q is not a valid scope", string(text))
	}
	return nil
}

// Type is a policy setting value type.
// Except for [InvalidValue], which represents an invalid policy setting type,
// and [PreferenceOptionValue], [VisibilityValue], and [DurationValue],
// which have special handling due to their legacy status in the package,
// SettingTypes represent the raw value types readable from policy stores.
type Type int

const (
	// InvalidValue indicates an invalid policy setting value type.
	InvalidValue Type = iota
	// BooleanValue indicates a policy setting whose underlying type is a bool.
	BooleanValue
	// IntegerValue indicates a policy setting whose underlying type is a uint64.
	IntegerValue
	// StringValue indicates a policy setting whose underlying type is a string.
	StringValue
	// StringListValue indicates a policy setting whose underlying type is a []string.
	StringListValue
	// PreferenceOptionValue indicates a three-state policy setting whose
	// underlying type is a string, but the actual value is a [PreferenceOption].
	PreferenceOptionValue
	// VisibilityValue indicates a two-state boolean-like policy setting whose
	// underlying type is a string, but the actual value is a [Visibility].
	VisibilityValue
	// DurationValue indicates an interval/period/duration policy setting whose
	// underlying type is a string, but the actual value is a [time.Duration].
	DurationValue
)

// String returns a string representation of t.
func (t Type) String() string {
	switch t {
	case InvalidValue:
		return "Invalid"
	case BooleanValue:
		return "Boolean"
	case IntegerValue:
		return "Integer"
	case StringValue:
		return "String"
	case StringListValue:
		return "StringList"
	case PreferenceOptionValue:
		return "PreferenceOption"
	case VisibilityValue:
		return "Visibility"
	case DurationValue:
		return "Duration"
	default:
		panic("unreachable")
	}
}
