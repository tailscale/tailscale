// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package ipnauth

import (
	"reflect"
	"testing"

	"tailscale.com/ipn"
	"tailscale.com/tailcfg"
)

func TestAccessCheckResult(t *testing.T) {
	tests := []struct {
		name          string
		res           AccessCheckResult
		wantStr       string
		wantHasResult bool
		wantAllow     bool
		wantDeny      bool
		wantErr       bool
	}{
		{
			name:          "zero-value-implicit-deny",
			res:           AccessCheckResult{},
			wantStr:       "Implicit Deny",
			wantHasResult: false,
			wantAllow:     false,
			wantDeny:      true,
			wantErr:       true,
		},
		{
			name:          "continue-implicit-deny",
			res:           ContinueCheck(),
			wantStr:       "Implicit Deny",
			wantHasResult: false,
			wantAllow:     false,
			wantDeny:      true,
			wantErr:       true,
		},
		{
			name:          "explicit-deny",
			res:           DenyAccess(errNotAllowed),
			wantStr:       "Deny: " + errNotAllowed.Error(),
			wantHasResult: true,
			wantAllow:     false,
			wantDeny:      true,
			wantErr:       true,
		},
		{
			name:          "explicit-allow",
			res:           AllowAccess(),
			wantStr:       "Allow",
			wantHasResult: true,
			wantAllow:     true,
			wantDeny:      false,
			wantErr:       false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if gotStr := tt.res.String(); gotStr != tt.wantStr {
				t.Errorf("got: %q, want: %q", gotStr, tt.wantStr)
			}
			if gotHasResult := tt.res.HasResult(); gotHasResult != tt.wantHasResult {
				t.Errorf("gotHasResult: %v, wantHasResult: %v", gotHasResult, tt.wantHasResult)
			}
			if gotAllow := tt.res.Allowed(); gotAllow != tt.wantAllow {
				t.Errorf("gotAllow: %v, wantAllow: %v", gotAllow, tt.wantAllow)
			}
			if gotDeny := tt.res.Denied(); gotDeny != tt.wantDeny {
				t.Errorf("gotDeny: %v, wantDeny: %v", gotDeny, tt.wantDeny)
			}

			if gotErr := tt.res.Error(); tt.wantErr {
				if _, isAccessDenied := gotErr.(*ipn.AccessDeniedError); !isAccessDenied {
					t.Errorf("err: %v, wantErr: %v", gotErr, tt.wantErr)
				}
			} else if gotErr != nil {
				t.Errorf("err: %v, wantErr: %v", gotErr, tt.wantErr)
			}
		})
	}
}

func TestAccessCheckerGrant(t *testing.T) {
	tests := []struct {
		name          string
		requested     ProfileAccess
		grant         []ProfileAccess
		wantRemaining ProfileAccess
		wantHasResult bool
		wantAllow     bool
		wantDeny      bool
	}{
		{
			name:          "grant-none",
			requested:     ReadProfileInfo,
			grant:         []ProfileAccess{},
			wantRemaining: ReadProfileInfo,
			wantHasResult: false,
			wantAllow:     false,
			wantDeny:      true,
		},
		{
			name:          "grant-single",
			requested:     ReadProfileInfo,
			grant:         []ProfileAccess{ReadProfileInfo},
			wantRemaining: 0,
			wantHasResult: true,
			wantAllow:     true,
			wantDeny:      false,
		},
		{
			name:          "grant-other",
			requested:     ReadProfileInfo,
			grant:         []ProfileAccess{Connect},
			wantRemaining: ReadProfileInfo,
			wantHasResult: false,
			wantAllow:     false,
			wantDeny:      true,
		},
		{
			name:          "grant-some",
			requested:     ReadProfileInfo | Connect,
			grant:         []ProfileAccess{ReadProfileInfo},
			wantRemaining: Connect,
			wantHasResult: false,
			wantAllow:     false,
			wantDeny:      true,
		},
		{
			name:          "grant-all",
			requested:     ReadProfileInfo | Connect | Disconnect | ReadPrefs,
			grant:         []ProfileAccess{ReadProfileInfo, Connect | Disconnect, ReadPrefs},
			wantRemaining: 0,
			wantHasResult: true,
			wantAllow:     true,
			wantDeny:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			checker := newAccessChecker(tt.requested)
			for _, grant := range tt.grant {
				checker.grant(grant)
			}
			if gotRemaining := checker.remaining(); gotRemaining != tt.wantRemaining {
				t.Errorf("gotRemaining: %v, wantRemaining: %v", gotRemaining, tt.wantRemaining)
			}
			res := checker.result()
			if gotHasResult := res.HasResult(); gotHasResult != tt.wantHasResult {
				t.Errorf("gotHasResult: %v, wantHasResult: %v", gotHasResult, tt.wantHasResult)
			}
			if gotAllow := res.Allowed(); gotAllow != tt.wantAllow {
				t.Errorf("gotAllow: %v, wantAllow: %v", gotAllow, tt.wantAllow)
			}
			if gotDeny := res.Denied(); gotDeny != tt.wantDeny {
				t.Errorf("gotDeny: %v, wantDeny: %v", gotDeny, tt.wantDeny)
			}
		})
	}
}

func TestAccessCheckerConditionalGrant(t *testing.T) {
	tests := []struct {
		name          string
		requested     ProfileAccess
		mustGrant     bool
		grant         ProfileAccess
		predicate     func() error
		wantRemaining ProfileAccess
		wantHasResult bool
		wantAllow     bool
		wantDeny      bool
	}{
		{
			name:          "try-grant",
			requested:     ReadProfileInfo,
			grant:         ReadProfileInfo,
			predicate:     func() error { return nil },
			wantRemaining: 0,
			wantHasResult: true,
			wantAllow:     true,
			wantDeny:      false,
		},
		{
			name:          "try-grant-err",
			requested:     ReadProfileInfo,
			grant:         ReadProfileInfo,
			predicate:     func() error { return errNotAllowed },
			wantRemaining: ReadProfileInfo,
			wantHasResult: false,
			wantAllow:     false,
			wantDeny:      true,
		},
		{
			name:          "must-grant",
			requested:     ReadProfileInfo,
			mustGrant:     true,
			grant:         ReadProfileInfo,
			predicate:     func() error { return nil },
			wantRemaining: 0,
			wantHasResult: true,
			wantAllow:     true,
			wantDeny:      false,
		},
		{
			name:          "must-grant-err",
			requested:     ReadProfileInfo,
			mustGrant:     true,
			grant:         ReadProfileInfo,
			predicate:     func() error { return errNotAllowed },
			wantRemaining: ReadProfileInfo,
			wantHasResult: true,
			wantAllow:     false,
			wantDeny:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			checker := newAccessChecker(tt.requested)

			var res AccessCheckResult
			if tt.mustGrant {
				res = checker.mustGrant(tt.grant, tt.predicate)
			} else {
				res = checker.tryGrant(tt.grant, tt.predicate)
			}

			if gotRemaining := checker.remaining(); gotRemaining != tt.wantRemaining {
				t.Errorf("gotRemaining: %v, wantRemaining: %v", gotRemaining, tt.wantRemaining)
			}
			if gotHasResult := res.HasResult(); gotHasResult != tt.wantHasResult {
				t.Errorf("gotHasResult: %v, wantHasResult: %v", gotHasResult, tt.wantHasResult)
			}
			if gotAllow := res.Allowed(); gotAllow != tt.wantAllow {
				t.Errorf("gotAllow: %v, wantAllow: %v", gotAllow, tt.wantAllow)
			}
			if gotDeny := res.Denied(); gotDeny != tt.wantDeny {
				t.Errorf("gotDeny: %v, wantDeny: %v", gotDeny, tt.wantDeny)
			}
		})
	}
}

func TestAccessCheckerDeny(t *testing.T) {
	tests := []struct {
		name          string
		requested     ProfileAccess
		grant         ProfileAccess
		deny          ProfileAccess
		wantHasResult bool
		wantAllow     bool
		wantDeny      bool
	}{
		{
			name:          "deny-single",
			requested:     ReadProfileInfo,
			deny:          ReadProfileInfo,
			wantHasResult: true,
			wantAllow:     false,
			wantDeny:      true,
		},
		{
			name:          "deny-other",
			requested:     ReadProfileInfo,
			deny:          Connect,
			wantHasResult: false,
			wantAllow:     false,
			wantDeny:      true,
		},
		{
			name:          "grant-some-then-deny",
			requested:     ReadProfileInfo | Connect,
			grant:         ReadProfileInfo,
			deny:          Connect,
			wantHasResult: true,
			wantAllow:     false,
			wantDeny:      true,
		},
		{
			name:          "deny-some",
			requested:     ReadProfileInfo | Connect | Disconnect | ReadPrefs,
			deny:          Connect,
			wantHasResult: true,
			wantAllow:     false,
			wantDeny:      true,
		},
		{
			name:          "deny-all",
			requested:     ReadProfileInfo | Connect | Disconnect | ReadPrefs,
			deny:          ReadProfileInfo | Connect | Disconnect | ReadPrefs,
			wantHasResult: true,
			wantAllow:     false,
			wantDeny:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			checker := newAccessChecker(tt.requested)
			res := checker.grant(tt.grant)
			if res.HasResult() {
				t.Fatalf("the result must not be ready yet")
			}
			res = checker.deny(tt.deny, errNotAllowed)
			if gotHasResult := res.HasResult(); gotHasResult != tt.wantHasResult {
				t.Errorf("gotHasResult: %v, wantHasResult: %v", gotHasResult, tt.wantHasResult)
			}
			if gotAllow := res.Allowed(); gotAllow != tt.wantAllow {
				t.Errorf("gotAllow: %v, wantAllow: %v", gotAllow, tt.wantAllow)
			}
			if gotDeny := res.Denied(); gotDeny != tt.wantDeny {
				t.Errorf("gotDeny: %v, wantDeny: %v", gotDeny, tt.wantDeny)
			}
		})
	}
}

func TestFilterProfile(t *testing.T) {
	profile := &ipn.LoginProfile{
		ID:   "TEST",
		Key:  "profile-TEST",
		Name: "user@example.com",
		NetworkProfile: ipn.NetworkProfile{
			MagicDNSName: "example.ts.net",
			DomainName:   "example.ts.net",
		},
		UserProfile: tailcfg.UserProfile{
			ID:            123456789,
			LoginName:     "user@example.com",
			DisplayName:   "User",
			ProfilePicURL: "https://example.com/profile.png",
		},
		NodeID:      "TEST-NODE-ID",
		LocalUserID: "S-1-5-21-1234567890-1234567890-1234567890-1001",
		ControlURL:  "https://controlplane.tailscale.com",
	}

	tests := []struct {
		name        string
		user        Identity
		profile     *ipn.LoginProfile
		wantProfile *ipn.LoginProfile
	}{
		{
			name:    "filter-unreadable",
			user:    &TestIdentity{ProfileAccess: 0},
			profile: profile,
			wantProfile: &ipn.LoginProfile{
				ID:          profile.ID,
				Name:        "Other User's Account",
				Key:         profile.Key,
				LocalUserID: profile.LocalUserID,
				UserProfile: tailcfg.UserProfile{
					LoginName:   "Other User's Account",
					DisplayName: "Other User",
				},
			},
		},
		{
			name:        "do-not-filter-readable",
			user:        &TestIdentity{UID: string(profile.LocalUserID), ProfileAccess: ReadProfileInfo},
			profile:     profile,
			wantProfile: profile,
		},
		{
			name:        "do-not-filter-for-self",
			user:        Self,
			profile:     profile,
			wantProfile: profile,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			profile := FilterProfile(tt.user, tt.profile.View(), ipn.PrefsGetterFor(ipn.PrefsView{})).AsStruct()
			if !reflect.DeepEqual(profile, tt.wantProfile) {
				t.Errorf("got: %+v, want: %+v", profile, tt.wantProfile)
			}
		})
	}
}

func TestPrefsChangeRequiredAccess(t *testing.T) {
	tests := []struct {
		name               string
		prefs              ipn.MaskedPrefs
		wantRequiredAccess ProfileAccess
	}{
		{
			name:               "no-changes",
			prefs:              ipn.MaskedPrefs{},
			wantRequiredAccess: 0,
		},
		{
			name: "connect",
			prefs: ipn.MaskedPrefs{
				Prefs:          ipn.Prefs{WantRunning: true},
				WantRunningSet: true,
			},
			wantRequiredAccess: Connect,
		},
		{
			name: "disconnect",
			prefs: ipn.MaskedPrefs{
				Prefs:          ipn.Prefs{WantRunning: false},
				WantRunningSet: true,
			},
			wantRequiredAccess: Disconnect,
		},
		{
			name: "change-exit-node-id",
			prefs: ipn.MaskedPrefs{
				ExitNodeIDSet: true,
			},
			wantRequiredAccess: ChangeExitNode,
		},
		{
			name: "change-exit-node-ip",
			prefs: ipn.MaskedPrefs{
				ExitNodeIPSet: true,
			},
			wantRequiredAccess: ChangeExitNode,
		},
		{
			name: "change-exit-node-lan-access",
			prefs: ipn.MaskedPrefs{
				ExitNodeAllowLANAccessSet: true,
			},
			wantRequiredAccess: ChangeExitNode,
		},
		{
			name: "change-multiple",
			prefs: ipn.MaskedPrefs{
				Prefs:          ipn.Prefs{WantRunning: true},
				ExitNodeIDSet:  true,
				WantRunningSet: true,
			},
			wantRequiredAccess: Connect | ChangeExitNode,
		},
		{
			name: "change-other-single",
			prefs: ipn.MaskedPrefs{
				ForceDaemonSet: true,
			},
			wantRequiredAccess: ChangePrefs,
		},
		{
			name: "change-other-multiple",
			prefs: ipn.MaskedPrefs{
				ForceDaemonSet: true,
				RunSSHSet:      true,
			},
			wantRequiredAccess: ChangePrefs,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotRequiredAccess := PrefsChangeRequiredAccess(&tt.prefs)
			if gotRequiredAccess != tt.wantRequiredAccess {
				t.Errorf("got: %v, want: %v", gotRequiredAccess, tt.wantRequiredAccess)
			}
		})
	}
}

func TestCheckEditProfile(t *testing.T) {
	tests := []struct {
		name      string
		prefs     ipn.MaskedPrefs
		user      Identity
		wantAllow bool
	}{
		{
			name: "allow-connect",
			prefs: ipn.MaskedPrefs{
				Prefs:          ipn.Prefs{WantRunning: true},
				WantRunningSet: true,
			},
			user:      &TestIdentity{ProfileAccess: Connect},
			wantAllow: true,
		},
		{
			name: "deny-connect",
			prefs: ipn.MaskedPrefs{
				Prefs:          ipn.Prefs{WantRunning: true},
				WantRunningSet: true,
			},
			user:      &TestIdentity{ProfileAccess: ReadProfileInfo},
			wantAllow: false,
		},
		{
			name: "allow-change-exit-node",
			prefs: ipn.MaskedPrefs{
				ExitNodeIDSet: true,
			},
			user:      &TestIdentity{ProfileAccess: ChangeExitNode},
			wantAllow: true,
		},
		{
			name: "allow-change-prefs",
			prefs: ipn.MaskedPrefs{
				ForceDaemonSet: true,
				RunSSHSet:      true,
			},
			user:      &TestIdentity{ProfileAccess: ChangePrefs},
			wantAllow: true,
		},
		{
			name: "deny-change-prefs",
			prefs: ipn.MaskedPrefs{
				ForceDaemonSet: true,
				RunSSHSet:      true,
			},
			user:      &TestIdentity{ProfileAccess: ChangeExitNode},
			wantAllow: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			profile, prefs := ipn.LoginProfile{}, ipn.NewPrefs()
			res := CheckEditProfile(tt.user, profile.View(), ipn.PrefsGetterFor(prefs.View()), &tt.prefs)
			if gotAllow := res.Allowed(); gotAllow != tt.wantAllow {
				t.Errorf("gotAllow: %v, wantAllow: %v", gotAllow, tt.wantAllow)
			}
		})
	}
}

func TestDenyAccessWithNilError(t *testing.T) {
	res := DenyAccess(nil)
	if gotHasResult := res.HasResult(); !gotHasResult {
		t.Errorf("gotHasResult: %v, wantHasResult: true", gotHasResult)
	}
	if gotAllow := res.Allowed(); gotAllow {
		t.Errorf("gotAllow: %v, wantAllow: false", gotAllow)
	}
	if gotDeny := res.Denied(); !gotDeny {
		t.Errorf("gotDeny: %v, wantDeny: true", gotDeny)
	}
	gotErr := res.Error()
	if _, isInternalError := gotErr.(*ipn.InternalServerError); !isInternalError {
		t.Errorf("got %T: %v, want: *ipn.InternalServerError", gotErr, gotErr)
	}
}
