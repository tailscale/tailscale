// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package setting contains types for defining and representing policy settings.
// It facilitates the registration of setting definitions using [Register] and [RegisterDefinition],
// and the retrieval of registered setting definitions via [Definitions] and [DefinitionOf].
// This package is intended for use primarily within the syspolicy package hierarchy.
package setting

import (
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	"tailscale.com/types/lazy"
	"tailscale.com/util/syspolicy/internal"
	"tailscale.com/util/syspolicy/pkey"
	"tailscale.com/util/syspolicy/ptype"
	"tailscale.com/util/testenv"
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

// ValueType is a constraint that allows Go types corresponding to [Type].
type ValueType interface {
	bool | uint64 | string | []string | ptype.Visibility | ptype.PreferenceOption | time.Duration
}

// Definition defines policy key, scope and value type.
type Definition struct {
	key       pkey.Key
	scope     Scope
	typ       Type
	platforms PlatformList
}

// NewDefinition returns a new [Definition] with the specified
// key, scope, type and supported platforms (see [PlatformList]).
func NewDefinition(k pkey.Key, s Scope, t Type, platforms ...string) *Definition {
	return &Definition{key: k, scope: s, typ: t, platforms: platforms}
}

// Key returns a policy setting's identifier.
func (d *Definition) Key() pkey.Key {
	if d == nil {
		return ""
	}
	return d.key
}

// Scope reports the broadest [Scope] the policy setting may apply to.
func (d *Definition) Scope() Scope {
	if d == nil {
		return 0
	}
	return d.scope
}

// Type reports the underlying value type of the policy setting.
func (d *Definition) Type() Type {
	if d == nil {
		return InvalidValue
	}
	return d.typ
}

// IsSupported reports whether the policy setting is supported on the current OS.
func (d *Definition) IsSupported() bool {
	if d == nil {
		return false
	}
	return d.platforms.HasCurrent()
}

// SupportedPlatforms reports platforms on which the policy setting is supported.
// An empty [PlatformList] indicates that s is available on all platforms.
func (d *Definition) SupportedPlatforms() PlatformList {
	if d == nil {
		return nil
	}
	return d.platforms
}

// String implements [fmt.Stringer].
func (d *Definition) String() string {
	if d == nil {
		return "(nil)"
	}
	return fmt.Sprintf("%v(%q, %v)", d.scope, d.key, d.typ)
}

// Equal reports whether d and d2 have the same key, type and scope.
// It does not check whether both s and s2 are supported on the same platforms.
func (d *Definition) Equal(d2 *Definition) bool {
	if d == d2 {
		return true
	}
	if d == nil || d2 == nil {
		return false
	}
	return d.key == d2.key && d.typ == d2.typ && d.scope == d2.scope
}

// DefinitionMap is a map of setting [Definition] by [Key].
type DefinitionMap map[pkey.Key]*Definition

var (
	definitions lazy.SyncValue[DefinitionMap]

	definitionsMu   sync.Mutex
	definitionsList []*Definition
	definitionsUsed bool
)

// Register registers a policy setting with the specified key, scope, value type,
// and an optional list of supported platforms. All policy settings must be
// registered before any of them can be used. Register panics if called after
// invoking any functions that use the registered policy definitions. This
// includes calling [Definitions] or [DefinitionOf] directly, or reading any
// policy settings via syspolicy.
func Register(k pkey.Key, s Scope, t Type, platforms ...string) {
	RegisterDefinition(NewDefinition(k, s, t, platforms...))
}

// RegisterDefinition is like [Register], but accepts a [Definition].
func RegisterDefinition(d *Definition) {
	definitionsMu.Lock()
	defer definitionsMu.Unlock()
	registerLocked(d)
}

func registerLocked(d *Definition) {
	if definitionsUsed {
		panic("policy definitions are already in use")
	}
	definitionsList = append(definitionsList, d)
}

func settingDefinitions() (DefinitionMap, error) {
	return definitions.GetErr(func() (DefinitionMap, error) {
		if err := internal.Init.Do(); err != nil {
			return nil, err
		}
		definitionsMu.Lock()
		defer definitionsMu.Unlock()
		definitionsUsed = true
		return DefinitionMapOf(definitionsList)
	})
}

// DefinitionMapOf returns a [DefinitionMap] with the specified settings,
// or an error if any settings have the same key but different type or scope.
func DefinitionMapOf(settings []*Definition) (DefinitionMap, error) {
	m := make(DefinitionMap, len(settings))
	for _, s := range settings {
		if existing, exists := m[s.key]; exists {
			if existing.Equal(s) {
				// Ignore duplicate setting definitions if they match. It is acceptable
				// if the same policy setting was registered more than once
				// (e.g. by the syspolicy package itself and by iOS/Android code).
				existing.platforms.mergeFrom(s.platforms)
				continue
			}
			return nil, fmt.Errorf("duplicate policy definition: %q", s.key)
		}
		m[s.key] = s
	}
	return m, nil
}

// SetDefinitionsForTest allows to register the specified setting definitions
// for the test duration. It is not concurrency-safe, but unlike [Register],
// it does not panic and can be called anytime.
// It returns an error if ds contains two different settings with the same [Key].
func SetDefinitionsForTest(tb testenv.TB, ds ...*Definition) error {
	m, err := DefinitionMapOf(ds)
	if err != nil {
		return err
	}
	definitions.SetForTest(tb, m, err)
	return nil
}

// DefinitionOf returns a setting definition by key,
// or [ErrNoSuchKey] if the specified key does not exist,
// or an error if there are conflicting policy definitions.
func DefinitionOf(k pkey.Key) (*Definition, error) {
	ds, err := settingDefinitions()
	if err != nil {
		return nil, err
	}
	if d, ok := ds[k]; ok {
		return d, nil
	}
	return nil, ErrNoSuchKey
}

// Definitions returns all registered setting definitions,
// or an error if different policies were registered under the same name.
func Definitions() ([]*Definition, error) {
	ds, err := settingDefinitions()
	if err != nil {
		return nil, err
	}
	res := make([]*Definition, 0, len(ds))
	for _, d := range ds {
		res = append(res, d)
	}
	return res, nil
}

// PlatformList is a list of OSes.
// An empty list indicates that all possible platforms are supported.
type PlatformList []string

// Has reports whether l contains the target platform.
func (l PlatformList) Has(target string) bool {
	if len(l) == 0 {
		return true
	}
	return slices.ContainsFunc(l, func(os string) bool {
		return strings.EqualFold(os, target)
	})
}

// HasCurrent is like Has, but for the current platform.
func (l PlatformList) HasCurrent() bool {
	return l.Has(internal.OS())
}

// mergeFrom merges l2 into l. Since an empty list indicates no platform restrictions,
// if either l or l2 is empty, the merged result in l will also be empty.
func (l *PlatformList) mergeFrom(l2 PlatformList) {
	switch {
	case len(*l) == 0:
		// No-op. An empty list indicates no platform restrictions.
	case len(l2) == 0:
		// Merging with an empty list results in an empty list.
		*l = l2
	default:
		// Append, sort and dedup.
		*l = append(*l, l2...)
		slices.Sort(*l)
		*l = slices.Compact(*l)
	}
}
