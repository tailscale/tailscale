// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package ipnauth

import (
	"testing"

	"tailscale.com/ipn"
)

var allGOOSes = []string{"linux", "darwin", "windows", "freebsd"}

type accessTest[Access ~uint32] struct {
	name          string
	geese         []string
	requestAccess []Access
	isLocalAdmin  bool
	wantAllow     bool
}

func TestServeAccess(t *testing.T) {
	tests := []accessTest[ProfileAccess]{
		{
			name:          "read-serve-not-admin",
			geese:         allGOOSes,
			requestAccess: []ProfileAccess{ReadServe},
			isLocalAdmin:  false,
			wantAllow:     true,
		},
		{
			name:          "change-serve-not-admin",
			geese:         []string{"windows"},
			requestAccess: []ProfileAccess{ChangeServe},
			isLocalAdmin:  false,
			wantAllow:     true,
		},
		{
			name:          "change-serve-not-admin",
			geese:         []string{"linux", "darwin", "freebsd"},
			requestAccess: []ProfileAccess{ChangeServe},
			isLocalAdmin:  false,
			wantAllow:     false,
		},
		{
			name:          "serve-path-not-admin",
			geese:         allGOOSes,
			requestAccess: []ProfileAccess{ServePath},
			isLocalAdmin:  false,
			wantAllow:     false,
		},
		{
			name:          "serve-path-admin",
			geese:         allGOOSes,
			requestAccess: []ProfileAccess{ServePath},
			isLocalAdmin:  true,
			wantAllow:     true,
		},
	}
	runProfileAccessTests(t, tests)
}

func runDeviceAccessTests(t *testing.T, tests []accessTest[DeviceAccess]) {
	t.Helper()

	for _, tt := range tests {
		for _, goos := range tt.geese {
			user := NewTestIdentityWithGOOS(goos, "test", tt.isLocalAdmin)
			for _, access := range tt.requestAccess {
				testName := goos + "-" + tt.name + "-" + access.String()
				t.Run(testName, func(t *testing.T) {
					res := user.CheckAccess(access)
					if res.Allowed() != tt.wantAllow {
						t.Errorf("got result = %v, want allow %v", res, tt.wantAllow)
					}
				})
			}
		}
	}
}

func runProfileAccessTests(t *testing.T, tests []accessTest[ProfileAccess]) {
	t.Helper()

	for _, tt := range tests {
		for _, goos := range tt.geese {
			user := NewTestIdentityWithGOOS(goos, "test", tt.isLocalAdmin)
			profile := &ipn.LoginProfile{LocalUserID: user.UserID()}
			prefs := func() (ipn.PrefsView, error) { return ipn.NewPrefs().View(), nil }

			for _, access := range tt.requestAccess {
				testName := goos + "-" + tt.name + "-" + access.String()
				t.Run(testName, func(t *testing.T) {
					res := user.CheckProfileAccess(profile.View(), prefs, access)
					if res.Allowed() != tt.wantAllow {
						t.Errorf("got result = %v, want allow %v", res, tt.wantAllow)
					}
				})
			}
		}
	}
}
