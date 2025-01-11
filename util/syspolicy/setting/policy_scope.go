// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package setting

var (
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
