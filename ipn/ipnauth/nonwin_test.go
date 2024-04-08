// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package ipnauth

import (
	"testing"

	"tailscale.com/envknob"
	"tailscale.com/ipn"
)

var (
	unixGOOSes  = []string{"linux", "darwin", "freebsd"}
	otherGOOSes = []string{"js"}
)

func TestDeviceAccessUnix(t *testing.T) {
	tests := []accessTest[DeviceAccess]{
		{
			name:          "allow-read-admin",
			geese:         unixGOOSes,
			requestAccess: []DeviceAccess{ReadDeviceStatus, GenerateBugReport},
			isLocalAdmin:  true,
			wantAllow:     true,
		},
		{
			name:          "allow-read-non-admin",
			geese:         unixGOOSes,
			requestAccess: []DeviceAccess{ReadDeviceStatus, GenerateBugReport},
			isLocalAdmin:  false,
			wantAllow:     true,
		},
		{
			name:          "deny-non-read-non-admin",
			geese:         unixGOOSes,
			requestAccess: []DeviceAccess{^(ReadDeviceStatus | GenerateBugReport)},
			isLocalAdmin:  false,
			wantAllow:     false,
		},
		{
			name:          "allow-all-access-admin",
			geese:         unixGOOSes,
			requestAccess: []DeviceAccess{UnrestrictedDeviceAccess},
			isLocalAdmin:  true,
			wantAllow:     true,
		},
	}
	runDeviceAccessTests(t, tests)
}

func TestDeviceAccessOther(t *testing.T) {
	tests := []accessTest[DeviceAccess]{
		{
			name:          "allow-all-access-admin",
			geese:         otherGOOSes,
			requestAccess: []DeviceAccess{UnrestrictedDeviceAccess},
			isLocalAdmin:  true,
			wantAllow:     true,
		},
		{
			name:          "allow-all-access-non-admin",
			geese:         otherGOOSes,
			requestAccess: []DeviceAccess{UnrestrictedDeviceAccess},
			isLocalAdmin:  false,
			wantAllow:     true,
		},
	}
	runDeviceAccessTests(t, tests)
}

func TestProfileAccessUnix(t *testing.T) {
	tests := []accessTest[ProfileAccess]{
		{
			name:          "allow-read-admin",
			geese:         unixGOOSes,
			requestAccess: []ProfileAccess{ReadProfileInfo, ReadPrefs, ReadServe, ListPeers},
			isLocalAdmin:  true,
			wantAllow:     true,
		},
		{
			name:          "allow-read-non-admin",
			geese:         unixGOOSes,
			requestAccess: []ProfileAccess{ReadProfileInfo, ReadPrefs, ReadServe, ListPeers},
			isLocalAdmin:  false,
			wantAllow:     true,
		},
		{
			name:          "deny-non-read-non-admin",
			geese:         unixGOOSes,
			requestAccess: []ProfileAccess{^(ReadProfileInfo | ReadPrefs | ReadServe | ListPeers)},
			isLocalAdmin:  false,
			wantAllow:     false,
		},
		{
			name:          "allow-use-profile-admin",
			geese:         unixGOOSes,
			requestAccess: []ProfileAccess{Connect, Disconnect, DeleteProfile, ReauthProfile, ChangePrefs, ChangeExitNode},
			isLocalAdmin:  true,
			wantAllow:     true,
		},
		{
			name:          "deny-use-profile-non-admin",
			geese:         unixGOOSes,
			requestAccess: []ProfileAccess{Connect, Disconnect, DeleteProfile, ReauthProfile, ChangePrefs, ChangeExitNode},
			isLocalAdmin:  false,
			wantAllow:     false,
		},
		{
			name:          "allow-all-access-admin",
			geese:         unixGOOSes,
			requestAccess: []ProfileAccess{UnrestrictedProfileAccess},
			isLocalAdmin:  true,
			wantAllow:     true,
		},
	}
	runProfileAccessTests(t, tests)
}

func TestFetchCertsAccessUnix(t *testing.T) {
	for _, goos := range unixGOOSes {
		t.Run(goos, func(t *testing.T) {
			user := NewTestIdentityWithGOOS(goos, "user", false)
			uid := *user.(*unixIdentity).forceForTest.uid
			envknob.Setenv("TS_PERMIT_CERT_UID", uid)
			defer envknob.Setenv("TS_PERMIT_CERT_UID", "")

			profile := ipn.LoginProfile{}
			res := user.CheckProfileAccess(profile.View(), ipn.PrefsGetterFor(ipn.NewPrefs().View()), FetchCerts)
			if !res.Allowed() {
				t.Errorf("got result = %v, want allow", res)
			}
		})
	}
}

func TestProfileAccessOther(t *testing.T) {
	tests := []accessTest[ProfileAccess]{
		{
			name:          "allow-all-access-admin",
			geese:         otherGOOSes,
			requestAccess: []ProfileAccess{UnrestrictedProfileAccess},
			isLocalAdmin:  true,
			wantAllow:     true,
		},
		{
			name:          "allow-all-access-non-admin",
			geese:         otherGOOSes,
			requestAccess: []ProfileAccess{UnrestrictedProfileAccess},
			isLocalAdmin:  false,
			wantAllow:     true,
		},
	}
	runProfileAccessTests(t, tests)
}
