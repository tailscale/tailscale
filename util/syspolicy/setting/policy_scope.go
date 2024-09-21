// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package setting

import (
	"fmt"
	"strings"

	"tailscale.com/types/lazy"
)

var (
	lazyDefaultScope lazy.SyncValue[PolicyScope]

	// DeviceScope indicates a scope containing device-global policies.
	DeviceScope = PolicyScope{kind: DeviceSetting}
	// CurrentProfileScope indicates a scope containing policies that apply to the
	// currently active Tailscale profile.
	CurrentProfileScope = PolicyScope{kind: ProfileSetting}
	// CurrentUserScope indicates a scope containing policies that apply to the
	// current user, for whatever that means on the current platform and
	// in the current application context.
	CurrentUserScope = PolicyScope{kind: UserSetting}
)

// PolicyScope is a management scope.
type PolicyScope struct {
	kind      Scope
	userID    string
	profileID string
}

// DefaultScope returns the default [PolicyScope] to be used by a program
// when querying policy settings.
// It returns [DeviceScope], unless explicitly changed with [SetDefaultScope].
func DefaultScope() PolicyScope {
	return lazyDefaultScope.Get(func() PolicyScope { return DeviceScope })
}

// SetDefaultScope attempts to set the specified scope as the default scope
// to be used by a program when querying policy settings.
// It fails and returns false if called more than once, or if the [DefaultScope]
// has already been used.
func SetDefaultScope(scope PolicyScope) bool {
	return lazyDefaultScope.Set(scope)
}

// UserScopeOf returns a policy [PolicyScope] of the user with the specified id.
func UserScopeOf(uid string) PolicyScope {
	return PolicyScope{kind: UserSetting, userID: uid}
}

// Kind reports the scope kind of s.
func (s PolicyScope) Kind() Scope {
	return s.kind
}

// IsApplicableSetting reports whether the specified setting applies to
// and can be retrieved for this scope. Policy settings are applicable
// to their own scopes as well as more specific scopes. For example,
// device settings are applicable to device, profile and user scopes,
// but user settings are only applicable to user scopes.
// For instance, a menu visibility setting is inherently a user setting
// and only makes sense in the context of a specific user.
func (s PolicyScope) IsApplicableSetting(setting *Definition) bool {
	return setting != nil && setting.Scope() <= s.Kind()
}

// IsConfigurableSetting reports whether the specified setting can be configured
// by a policy at this scope. Policy settings are configurable at their own scopes
// as well as broader scopes. For example, [UserSetting]s are configurable in
// user, profile, and device scopes, but [DeviceSetting]s are only configurable
// in the [DeviceScope]. For instance, the InstallUpdates policy setting
// can only be configured in the device scope, as it controls whether updates
// will be installed automatically on the device, rather than for specific users.
func (s PolicyScope) IsConfigurableSetting(setting *Definition) bool {
	return setting != nil && setting.Scope() >= s.Kind()
}

// Contains reports whether policy settings that apply to s also apply to s2.
// For example, policy settings that apply to the [DeviceScope] also apply to
// the [CurrentUserScope].
func (s PolicyScope) Contains(s2 PolicyScope) bool {
	if s.Kind() > s2.Kind() {
		return false
	}
	switch s.Kind() {
	case DeviceSetting:
		return true
	case ProfileSetting:
		return s.profileID == s2.profileID
	case UserSetting:
		return s.userID == s2.userID
	default:
		panic("unreachable")
	}
}

// StrictlyContains is like [PolicyScope.Contains], but returns false
// when s and s2 is the same scope.
func (s PolicyScope) StrictlyContains(s2 PolicyScope) bool {
	return s != s2 && s.Contains(s2)
}

// String implements [fmt.Stringer].
func (s PolicyScope) String() string {
	if s.profileID == "" && s.userID == "" {
		return s.kind.String()
	}
	return s.stringSlow()
}

// MarshalText implements [encoding.TextMarshaler].
func (s PolicyScope) MarshalText() ([]byte, error) {
	return []byte(s.String()), nil
}

// MarshalText implements [encoding.TextUnmarshaler].
func (s *PolicyScope) UnmarshalText(b []byte) error {
	*s = PolicyScope{}
	parts := strings.SplitN(string(b), "/", 2)
	for i, part := range parts {
		kind, id, err := parseScopeAndID(part)
		if err != nil {
			return err
		}
		if i > 0 && kind <= s.kind {
			return fmt.Errorf("invalid scope hierarchy: %s", b)
		}
		s.kind = kind
		switch kind {
		case DeviceSetting:
			if id != "" {
				return fmt.Errorf("the device scope must not have an ID: %s", b)
			}
		case ProfileSetting:
			s.profileID = id
		case UserSetting:
			s.userID = id
		}
	}
	return nil
}

func (s PolicyScope) stringSlow() string {
	var sb strings.Builder
	writeScopeWithID := func(s Scope, id string) {
		sb.WriteString(s.String())
		if id != "" {
			sb.WriteRune('(')
			sb.WriteString(id)
			sb.WriteRune(')')
		}
	}
	if s.kind == ProfileSetting || s.profileID != "" {
		writeScopeWithID(ProfileSetting, s.profileID)
		if s.kind != ProfileSetting {
			sb.WriteRune('/')
		}
	}
	if s.kind == UserSetting {
		writeScopeWithID(UserSetting, s.userID)
	}
	return sb.String()
}

func parseScopeAndID(s string) (scope Scope, id string, err error) {
	name, params, ok := extractScopeAndParams(s)
	if !ok {
		return 0, "", fmt.Errorf("%q is not a valid scope string", s)
	}
	if err := scope.UnmarshalText([]byte(name)); err != nil {
		return 0, "", err
	}
	return scope, params, nil
}

func extractScopeAndParams(s string) (name, params string, ok bool) {
	paramsStart := strings.Index(s, "(")
	if paramsStart == -1 {
		return s, "", true
	}
	paramsEnd := strings.LastIndex(s, ")")
	if paramsEnd < paramsStart {
		return "", "", false
	}
	return s[0:paramsStart], s[paramsStart+1 : paramsEnd], true
}
